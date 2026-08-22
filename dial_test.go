package arden

import (
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

	"github.com/wyattanderson/arden/ber"
)

func TestEndpointTransportValidation(t *testing.T) {
	if err := (Endpoint{ID: "tls", Address: "localhost:636"}).Validate(); err == nil {
		t.Fatal("default direct-TLS endpoint accepted an empty server name")
	}
	if err := (Endpoint{ID: "plain", Address: "localhost:389", Transport: TransportPlaintext}).Validate(); err != nil {
		t.Fatalf("explicit plaintext endpoint: %v", err)
	}
	if err := (Endpoint{ID: "bad", Address: "localhost:389", Transport: TransportMode(99)}).Validate(); err == nil {
		t.Fatal("invalid transport mode was accepted")
	}
}

func TestDialerDirectTLSVerifiesAndClonesConfiguration(t *testing.T) {
	certificate, roots := testServerCertificate(t, "ldap.test")
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverResult := make(chan error, 1)
	go func() {
		peer, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer peer.Close()
		framer, err := ber.NewFramer(peer, ber.DefaultLimits())
		if err != nil {
			serverResult <- err
			return
		}
		message, err := framer.Next()
		if err != nil {
			serverResult <- err
			return
		}
		request, err := ParseResponse(message, ber.DefaultLimits())
		if err != nil {
			serverResult <- err
			return
		}
		_, err = peer.Write(testLDAPMessage(t, request.MessageID, testModifyDone, nil))
		serverResult <- err
	}()

	callerTLS := &tls.Config{RootCAs: roots, ServerName: "caller-value.invalid"}
	dialer := &Dialer{TLSConfig: callerTLS}
	conn, err := dialer.Dial(context.Background(), Endpoint{
		ID: "tls", Address: listener.Addr().String(), ServerName: "ldap.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.retire(ErrClosed)
	if callerTLS.ServerName != "caller-value.invalid" {
		t.Fatalf("Dial mutated caller TLS config ServerName to %q", callerTLS.ServerName)
	}

	stream, err := conn.Do(context.Background(), newTestOperation(t, testModifyRequest, ResponseSpec{Complete: []ber.Identifier{testModifyDone}}, CancelDrain))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestDialerRejectsHostnameMismatch(t *testing.T) {
	certificate, roots := testServerCertificate(t, "ldap.test")
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		peer, err := listener.Accept()
		if err == nil {
			defer peer.Close()
			_ = peer.(*tls.Conn).Handshake()
		}
	}()

	_, err = (&Dialer{TLSConfig: &tls.Config{RootCAs: roots}}).Dial(context.Background(), Endpoint{
		ID: "tls", Address: listener.Addr().String(), ServerName: "wrong.test",
	})
	var transportErr *TransportError
	if !errors.As(err, &transportErr) || transportErr.Stage != StageTLS {
		t.Fatalf("hostname mismatch error = %v", err)
	}
}

func TestDialerTLSHandshakeUsesContext(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		peer, err := listener.Accept()
		if err == nil {
			accepted <- peer
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = new(Dialer).Dial(ctx, Endpoint{ID: "tls", Address: listener.Addr().String(), ServerName: "ldap.test"})
	var transportErr *TransportError
	if !errors.As(err, &transportErr) || transportErr.Stage != StageTLS || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("handshake timeout error = %v", err)
	}
	select {
	case peer := <-accepted:
		_ = peer.Close()
	case <-time.After(time.Second):
		t.Fatal("server did not accept TLS connection")
	}
}

func TestDialerPlaintextRequiresExplicitSelection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	requestReady := make(chan Response, 1)
	serverErr := make(chan error, 1)
	go func() {
		peer, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer peer.Close()
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
		request, err := ParseResponse(message, ber.DefaultLimits())
		if err == nil {
			requestReady <- request
		}
		serverErr <- err
	}()

	conn, err := new(Dialer).Dial(context.Background(), Endpoint{
		ID: "plain", Address: listener.Addr().String(), Transport: TransportPlaintext,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.retire(ErrClosed)
	stream, err := conn.Do(context.Background(), newTestOperation(t, testModifyRequest, ResponseSpec{NoResponse: true}, CancelNone))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("no-response stream error = %v", err)
	}
	request := <-requestReady
	if request.ProtocolID != testModifyRequest {
		t.Fatalf("plaintext protocol = %s", request.ProtocolID)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestTLSFailureNeverFallsBackToPlaintext(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	firstByte := make(chan byte, 1)
	go func() {
		peer, err := listener.Accept()
		if err != nil {
			return
		}
		defer peer.Close()
		var one [1]byte
		if _, err := peer.Read(one[:]); err == nil {
			firstByte <- one[0]
		}
	}()

	_, err = new(Dialer).Dial(context.Background(), Endpoint{
		ID: "default-tls", Address: listener.Addr().String(), ServerName: "ldap.test",
	})
	var transportErr *TransportError
	if !errors.As(err, &transportErr) || transportErr.Stage != StageTLS {
		t.Fatalf("TLS failure error = %v", err)
	}
	select {
	case got := <-firstByte:
		if got != 0x16 {
			t.Fatalf("first transport byte = 0x%02x, want TLS handshake record", got)
		}
	case <-time.After(time.Second):
		t.Fatal("plaintext peer received no TLS bytes")
	}
}

func testServerCertificate(t *testing.T, serverName string) (tls.Certificate, *x509.CertPool) {
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
