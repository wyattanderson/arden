package arden_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/auth"
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
)

type authenticationTestProfile struct {
	Vendor string
}

type authenticationTestInitializer struct{}

func (authenticationTestInitializer) Initialize(context.Context, arden.InitializationSession) (authenticationTestProfile, arden.ConnectionPolicy, error) {
	return authenticationTestProfile{Vendor: "389ds"}, arden.ConnectionPolicy{Cancellation: arden.CancellationRFC3909}, nil
}

func TestAnonymousBootstrapOverExplicitPlaintext(t *testing.T) {
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	serverErr := make(chan error, 1)
	go func() {
		peer, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer func() { _ = peer.Close() }()
		framer, err := ber.NewFramer(peer, ber.DefaultLimits())
		if err != nil {
			serverErr <- err
			return
		}
		message, err := framer.Next()
		if err != nil {
			serverErr <- err
			return
		}
		envelope, err := arden.ParseResponse(message, ber.DefaultLimits())
		if err != nil {
			serverErr <- err
			return
		}
		var request rfc4511.BindRequest
		if err := envelope.UnmarshalProtocol(&request, ber.DefaultLimits()); err != nil {
			serverErr <- err
			return
		}
		credentials, ok := request.Authentication.(rfc4511.SimpleAuthentication)
		if !ok || request.Version != 3 || len(request.Name) != 0 || len(credentials) != 0 {
			serverErr <- errors.New("server received a non-anonymous Bind")
			return
		}
		response, err := authenticationBindMessage(envelope.MessageID, rfc4511.ResultSuccess, nil)
		if err == nil {
			_, err = peer.Write(response)
		}
		if err != nil {
			serverErr <- err
			return
		}
		_, err = framer.Next()
		serverErr <- err
	}()

	endpoint := arden.Endpoint{ID: "plain-anonymous", Address: listener.Addr().String(), Transport: arden.TransportPlaintext}
	result, err := arden.Bootstrap(context.Background(), &arden.Dialer{Authentication: auth.Anonymous{}}, endpoint, authenticationTestInitializer{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Endpoint != endpoint || result.Identity.StableID != "anonymous" || result.Profile.Vendor != "389ds" || result.Policy.Cancellation != arden.CancellationRFC3909 {
		t.Fatalf("anonymous bootstrap result = %#v", result)
	}
	if err := result.Conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

func TestSimpleBindCompletesDuringDirectTLSDial(t *testing.T) {
	certificate, roots := authenticationTestCertificate(t, "ldap.auth.test")
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	serverErr := make(chan error, 1)
	go func() {
		peer, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer func() { _ = peer.Close() }()
		framer, err := ber.NewFramer(peer, ber.DefaultLimits())
		if err != nil {
			serverErr <- err
			return
		}
		message, err := framer.Next()
		if err != nil {
			serverErr <- err
			return
		}
		envelope, err := arden.ParseResponse(message, ber.DefaultLimits())
		if err != nil {
			serverErr <- err
			return
		}
		var request rfc4511.BindRequest
		if err := envelope.UnmarshalProtocol(&request, ber.DefaultLimits()); err != nil {
			serverErr <- err
			return
		}
		credentials, ok := request.Authentication.(rfc4511.SimpleAuthentication)
		if !ok || request.Name != "uid=service,dc=example" || string(credentials) != "credential-secret" {
			serverErr <- errors.New("server received unexpected Simple Bind values")
			return
		}
		response, err := authenticationBindMessage(envelope.MessageID, rfc4511.ResultSuccess, nil)
		if err == nil {
			_, err = peer.Write(response)
		}
		if err != nil {
			serverErr <- err
			return
		}
		// A successfully published connection closes with Unbind.
		_, err = framer.Next()
		serverErr <- err
	}()

	configuration, err := auth.NewSimpleBind(
		"service-account-a",
		"uid=service,dc=example",
		"credential-secret",
	)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &arden.Dialer{
		TLSConfig:      &tls.Config{RootCAs: roots},
		Authentication: configuration,
	}
	conn, err := dialer.Dial(context.Background(), arden.Endpoint{
		ID:         "tls-auth",
		Address:    listener.Addr().String(),
		ServerName: "ldap.auth.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if conn.Identity().StableID != "service-account-a" {
		t.Fatalf("connection identity = %#v", conn.Identity())
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

func TestFailedSimpleBindNeverPublishesConnectionAndRedactsValues(t *testing.T) {
	certificate, roots := authenticationTestCertificate(t, "ldap.auth.test")
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	closed := make(chan error, 1)
	go func() {
		peer, err := listener.Accept()
		if err != nil {
			closed <- err
			return
		}
		defer func() { _ = peer.Close() }()
		framer, err := ber.NewFramer(peer, ber.DefaultLimits())
		if err != nil {
			closed <- err
			return
		}
		message, err := framer.Next()
		if err != nil {
			closed <- err
			return
		}
		envelope, err := arden.ParseResponse(message, ber.DefaultLimits())
		if err != nil {
			closed <- err
			return
		}
		response, err := authenticationBindMessage(
			envelope.MessageID,
			rfc4511.ResultInvalidCredentials,
			[]byte("diagnostic-with-secret-value"),
		)
		if err == nil {
			_, err = peer.Write(response)
		}
		if err != nil {
			closed <- err
			return
		}
		_, err = framer.Next()
		closed <- err
	}()

	configuration, err := auth.NewSimpleBind("service-account-a", "uid=service", "credential-secret-value")
	if err != nil {
		t.Fatal(err)
	}
	dialer := &arden.Dialer{TLSConfig: &tls.Config{RootCAs: roots}, Authentication: configuration}
	conn, err := dialer.Dial(context.Background(), arden.Endpoint{
		ID: "tls-auth", Address: listener.Addr().String(), ServerName: "ldap.auth.test",
	})
	if conn != nil {
		t.Fatal("failed authentication published a connection")
	}
	var setupErr *arden.SetupError
	var bindErr *auth.BindError
	if !errors.As(err, &setupErr) || setupErr.Stage != arden.SetupAuthentication || !errors.As(err, &bindErr) {
		t.Fatalf("failed Bind error = %v", err)
	}
	if bytes.Contains([]byte(err.Error()), []byte("secret-value")) {
		t.Fatalf("failed Bind leaked authentication material: %v", err)
	}
	if peerErr := <-closed; peerErr != nil && !errors.Is(peerErr, io.EOF) && !errors.Is(peerErr, net.ErrClosed) {
		t.Fatalf("failed Bind did not close the peer: %v", peerErr)
	}
}

func TestSimpleBindPlaintextPreflightRunsBeforeDial(t *testing.T) {
	configuration, err := auth.NewSimpleBind("service-account-a", "uid=service", "credential")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := (&arden.Dialer{Authentication: configuration}).Dial(context.Background(), arden.Endpoint{
		ID: "plain", Address: "127.0.0.1:1", Transport: arden.TransportPlaintext,
	})
	if conn != nil {
		t.Fatal("plaintext Simple Bind returned a connection")
	}
	var setupErr *arden.SetupError
	var transportErr *arden.TransportError
	if !errors.As(err, &setupErr) || setupErr.Stage != arden.SetupAuthentication || errors.As(err, &transportErr) {
		t.Fatalf("plaintext preflight error = %v", err)
	}
}

func authenticationBindMessage(id arden.MessageID, code rfc4511.ResultCode, diagnostic []byte) ([]byte, error) {
	protocol, err := (rfc4511.BindResponse{Result: rfc4511.LDAPResult{
		ResultCode: code, DiagnosticMessage: rfc4511.LDAPString(diagnostic),
	}}).AppendBER(nil)
	if err != nil {
		return nil, err
	}
	contents, err := ber.AppendInteger(nil, int64(id))
	if err != nil {
		return nil, err
	}
	contents = append(contents, protocol...)
	return ber.AppendSequence(nil, contents)
}

func authenticationTestCertificate(t *testing.T, serverName string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	roots := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(parsed)
	return certificate, roots
}
