//go:build gssapi && cgo && (linux || darwin || freebsd || openbsd)

// Package main provides a read-only FreeIPA GSSAPI smoke check.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"time"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/auth/gssapi/native"
	"github.com/wyattanderson/arden/rfc4532"
)

type configuration struct {
	address    string
	serverName string
	caFile     string
	stableID   string
	timeout    time.Duration
}

func main() {
	config := configuration{}
	flag.StringVar(&config.address, "address", "", "FreeIPA LDAPS address (host:port)")
	flag.StringVar(&config.serverName, "server-name", "", "verified TLS and Kerberos service hostname")
	flag.StringVar(&config.caFile, "ca-file", "", "optional PEM CA file; system roots are used by default")
	flag.StringVar(&config.stableID, "identity", "freeipa-gssapi-smoke", "nonsecret stable Arden identity")
	flag.DurationVar(&config.timeout, "timeout", 30*time.Second, "overall dial, Bind, and search timeout")
	flag.Parse()

	if err := run(config); err != nil {
		log.Fatal(err)
	}
}

func run(config configuration) error {
	if config.address == "" || config.serverName == "" {
		return errors.New("-address and -server-name are required")
	}
	if config.timeout <= 0 {
		return errors.New("-timeout must be positive")
	}

	roots, err := x509.SystemCertPool()
	if err != nil {
		return fmt.Errorf("load system certificate pool: %w", err)
	}
	if roots == nil {
		roots = x509.NewCertPool()
	}
	if config.caFile != "" {
		pem, err := os.ReadFile(config.caFile)
		if err != nil {
			return fmt.Errorf("read CA file: %w", err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return errors.New("CA file contains no usable certificates")
		}
	}

	authentication, err := native.New(config.stableID)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), config.timeout)
	defer cancel()

	var l = new(slog.LevelVar)
	l.Set(slog.LevelDebug)
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})
	slog.SetDefault(slog.New(h))

	conn, err := (&arden.Dialer{
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
		},
		Authentication: authentication,
		Logger:         slog.Default(),
	}).Dial(ctx, arden.Endpoint{
		ID:         "freeipa-gssapi-smoke",
		Address:    config.address,
		ServerName: config.serverName,
	})
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	authorizationID, err := rfc4532.WhoAmI(ctx, conn)
	if err != nil {
		return err
	}
	if authorizationID == "" {
		return errors.New("Who Am I? reported an anonymous authorization identity after GSSAPI Bind")
	}
	client := arden.NewClient(conn)
	rootDSE, err := client.RootDSE(ctx, "supportedLDAPVersion", "supportedSASLMechanisms")
	if err != nil {
		return err
	}
	if !rootDSE.Contains("supportedLDAPVersion", "3") {
		return errors.New("root DSE does not advertise LDAPv3")
	}
	identity := conn.Identity().StableID
	if err := conn.Close(); err != nil {
		return err
	}
	fmt.Printf(
		"GSSAPI Bind, Who Am I?, and read-only root DSE search succeeded (authorization identity %q, Arden identity %q)\n",
		authorizationID,
		identity,
	)
	return nil
}
