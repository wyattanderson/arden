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
	"io"
	"log"
	"log/slog"
	"os"
	"time"
	"unicode/utf8"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/auth/gssapi/native"
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
)

const whoAmIOID = "1.3.6.1.4.1.4203.1.11.3"

type operationExecutor interface {
	Do(context.Context, arden.Operation) (arden.ResponseStream, error)
}

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

	authorizationID, err := whoAmI(ctx, conn)
	if err != nil {
		return err
	}

	search, err := rfc4511.NewSearchOperation(&rfc4511.SearchRequest{
		BaseObject:   rfc4511.LDAPDN{},
		Scope:        rfc4511.ScopeBaseObject,
		DerefAliases: rfc4511.DerefNever,
		SizeLimit:    1,
		Filter: rfc4511.Present{
			Attribute: rfc4511.AttributeDescription("objectClass"),
		},
		Attributes: []rfc4511.AttributeSelector{
			rfc4511.AttributeSelector("supportedLDAPVersion"),
			rfc4511.AttributeSelector("supportedSASLMechanisms"),
		},
	}, nil)
	if err != nil {
		return err
	}
	stream, err := conn.Do(ctx, search)
	if err != nil {
		return err
	}
	defer func() { _ = stream.Close() }()

	entries := 0
	for {
		response, err := stream.Next(ctx)
		if err != nil {
			return err
		}
		switch response.ProtocolID {
		case rfc4511.SearchResultEntryIdentifier():
			var entry rfc4511.SearchResultEntry
			if err := response.UnmarshalProtocol(&entry, ber.DefaultLimits()); err != nil {
				return err
			}
			entries++
		case rfc4511.SearchResultReferenceIdentifier():
			return errors.New("root DSE search returned an unexpected reference")
		case rfc4511.SearchResultDoneIdentifier():
			var done rfc4511.SearchResultDone
			if err := response.UnmarshalProtocol(&done, ber.DefaultLimits()); err != nil {
				return err
			}
			if done.Result.ResultCode != rfc4511.ResultSuccess {
				return fmt.Errorf("root DSE search failed with LDAP result code %d", done.Result.ResultCode)
			}
			if _, err := stream.Next(ctx); !errors.Is(err, io.EOF) {
				if err == nil {
					return errors.New("root DSE search returned data after SearchResultDone")
				}
				return err
			}
			if entries != 1 {
				return fmt.Errorf("root DSE search returned %d entries, want 1", entries)
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
		default:
			return fmt.Errorf("root DSE search returned unexpected protocol identifier %s", response.ProtocolID)
		}
	}
}

func whoAmI(ctx context.Context, executor operationExecutor) (string, error) {
	operation, err := rfc4511.NewExtendedOperation(&rfc4511.ExtendedRequest{
		Name: rfc4511.LDAPOID(whoAmIOID),
	}, nil)
	if err != nil {
		return "", err
	}
	stream, err := executor.Do(ctx, operation)
	if err != nil {
		return "", err
	}
	defer func() { _ = stream.Close() }()

	response, err := stream.Next(ctx)
	if err != nil {
		return "", err
	}
	if response.ProtocolID != rfc4511.ExtendedResponseIdentifier() {
		return "", fmt.Errorf("who am I? returned unexpected protocol identifier %s", response.ProtocolID)
	}

	var extended rfc4511.ExtendedResponse
	if err := response.UnmarshalProtocol(&extended, ber.DefaultLimits()); err != nil {
		return "", err
	}

	if _, err := stream.Next(ctx); !errors.Is(err, io.EOF) {
		if err == nil {
			return "", errors.New("who am I? returned more than one response")
		}
		return "", err
	}
	if extended.Result.ResultCode != rfc4511.ResultSuccess {
		return "", fmt.Errorf("who am I? failed with LDAP result code %d", extended.Result.ResultCode)
	}
	if extended.HasResponseName {
		return "", errors.New("who am I? returned an unexpected response name")
	}
	if !extended.HasResponseValue {
		return "", errors.New("who am I? omitted the authorization identity")
	}
	if len(extended.ResponseValue) == 0 {
		return "", errors.New("who am I? reported an anonymous authorization identity after GSSAPI Bind")
	}
	if !utf8.Valid(extended.ResponseValue) {
		return "", errors.New("who am I? returned a non-UTF-8 authorization identity")
	}
	return string(extended.ResponseValue), nil
}
