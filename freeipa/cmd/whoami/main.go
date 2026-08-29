//go:build gssapi && cgo && (linux || darwin || freebsd || openbsd)

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/auth/gssapi/native"
	"github.com/wyattanderson/arden/rfc4532"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	config, err := loadConfiguration()
	if err != nil {
		return err
	}

	roots, err := x509.SystemCertPool()
	if err != nil {
		return fmt.Errorf("load system certificate pool: %w", err)
	}
	if roots == nil {
		roots = x509.NewCertPool()
	}
	pem, err := os.ReadFile(config.caFile)
	if err != nil {
		return fmt.Errorf("read FreeIPA CA: %w", err)
	}
	if !roots.AppendCertsFromPEM(pem) {
		return errors.New("FreeIPA CA file contains no usable certificates")
	}

	authentication, err := native.New(config.stableID)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), config.timeout)
	defer cancel()

	conn, err := (&arden.Dialer{
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
		},
		Authentication: authentication,
	}).Dial(ctx, arden.Endpoint{
		ID:         "freeipa-compose",
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
		return errors.New("Who Am I? returned an anonymous authorization identity")
	}
	if err := conn.Close(); err != nil {
		return err
	}

	fmt.Printf("Who Am I? %s\n", authorizationID)
	return nil
}
