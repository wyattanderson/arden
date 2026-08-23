package arden

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
)

func TestEndpointTransportValidation(t *testing.T) {
	require.Error(t, (Endpoint{ID: "tls", Address: "localhost:636"}).Validate())
	require.NoError(t, (Endpoint{ID: "plain", Address: "localhost:389", Transport: TransportPlaintext}).Validate())
	assert.Error(t, (Endpoint{ID: "bad", Address: "localhost:389", Transport: TransportMode(99)}).Validate())
}

func TestDialerDirectTLSVerifiesAndClonesConfiguration(t *testing.T) {
	certificate, roots := testServerCertificate(t, "ldap.test")
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}})
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()

	serverResult := make(chan error, 1)
	go func() {
		peer, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer func() { _ = peer.Close() }()
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
	require.NoError(t, err)
	defer conn.retire(ErrClosed)
	require.Equal(t, "caller-value.invalid", callerTLS.ServerName)

	stream, err := conn.Do(context.Background(), newTestOperation(t, testModifyRequest, ResponseSpec{Complete: []ber.Identifier{testModifyDone}}, CancelDrain))
	require.NoError(t, err)
	_, err = stream.Next(context.Background())
	require.NoError(t, err)
	assert.NoError(t, <-serverResult)
}

func TestDialerRejectsHostnameMismatch(t *testing.T) {
	certificate, roots := testServerCertificate(t, "ldap.test")
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}})
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()
	go func() {
		peer, err := listener.Accept()
		if err == nil {
			defer func() { _ = peer.Close() }()
			_ = peer.(*tls.Conn).HandshakeContext(context.Background())
		}
	}()

	_, err = (&Dialer{TLSConfig: &tls.Config{RootCAs: roots}}).Dial(context.Background(), Endpoint{
		ID: "tls", Address: listener.Addr().String(), ServerName: "wrong.test",
	})
	var transportErr *TransportError
	require.ErrorAs(t, err, &transportErr)
	assert.Equal(t, StageTLS, transportErr.Stage)
}

func TestDialerTLSHandshakeUsesContext(t *testing.T) {
	listener, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()
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
	require.ErrorAs(t, err, &transportErr)
	assert.Equal(t, StageTLS, transportErr.Stage)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	select {
	case peer := <-accepted:
		_ = peer.Close()
	case <-time.After(time.Second):
		assert.Fail(t, "server did not accept TLS connection")
	}
}

func TestDialerPlaintextRequiresExplicitSelection(t *testing.T) {
	listener, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()
	requestReady := make(chan Response, 1)
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
		request, err := ParseResponse(message, ber.DefaultLimits())
		if err == nil {
			requestReady <- request
		}
		serverErr <- err
	}()

	conn, err := new(Dialer).Dial(context.Background(), Endpoint{
		ID: "plain", Address: listener.Addr().String(), Transport: TransportPlaintext,
	})
	require.NoError(t, err)
	defer conn.retire(ErrClosed)
	stream, err := conn.Do(context.Background(), newTestOperation(t, testModifyRequest, ResponseSpec{NoResponse: true}, CancelNone))
	require.NoError(t, err)
	_, err = stream.Next(context.Background())
	require.ErrorIs(t, err, io.EOF)
	request := <-requestReady
	require.Equal(t, testModifyRequest, request.ProtocolID)
	assert.NoError(t, <-serverErr)
}

func TestTLSFailureNeverFallsBackToPlaintext(t *testing.T) {
	listener, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()
	firstByte := make(chan byte, 1)
	go func() {
		peer, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = peer.Close() }()
		var one [1]byte
		if _, err := peer.Read(one[:]); err == nil {
			firstByte <- one[0]
		}
	}()

	_, err = new(Dialer).Dial(context.Background(), Endpoint{
		ID: "default-tls", Address: listener.Addr().String(), ServerName: "ldap.test",
	})
	var transportErr *TransportError
	require.ErrorAs(t, err, &transportErr)
	require.Equal(t, StageTLS, transportErr.Stage)
	select {
	case got := <-firstByte:
		assert.Equal(t, byte(0x16), got)
	case <-time.After(time.Second):
		assert.Fail(t, "plaintext peer received no TLS bytes")
	}
}

func testServerCertificate(t *testing.T, serverName string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
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
	require.NoError(t, err)
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	roots := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots.AddCert(parsed)
	return certificate, roots
}
