package arden_test

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	require.NoError(t, err)
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
		response := authenticationBindMessage(envelope.MessageID, rfc4511.ResultSuccess, nil)
		_, err = peer.Write(response)
		if err != nil {
			serverErr <- err
			return
		}
		_, err = framer.Next()
		serverErr <- err
	}()

	endpoint := arden.Endpoint{ID: "plain-anonymous", Address: listener.Addr().String(), Transport: arden.TransportPlaintext}
	result, err := arden.Bootstrap(context.Background(), &arden.Dialer{Authentication: auth.Anonymous{}}, endpoint, authenticationTestInitializer{})
	require.NoError(t, err)
	require.Equal(t, endpoint, result.Endpoint)
	require.Equal(t, "anonymous", result.Identity.StableID)
	require.Equal(t, "389ds", result.Profile.Vendor)
	require.Equal(t, arden.CancellationRFC3909, result.Policy.Cancellation)
	require.NoError(t, result.Conn.Close())
	err = <-serverErr
	assert.True(t, err == nil || errors.Is(err, io.EOF))
}

func TestSimpleBindCompletesDuringDirectTLSDial(t *testing.T) {
	certificate, roots := authenticationTestCertificate(t, "ldap.auth.test")
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}})
	require.NoError(t, err)
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
		response := authenticationBindMessage(envelope.MessageID, rfc4511.ResultSuccess, nil)
		_, err = peer.Write(response)
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
	require.NoError(t, err)
	dialer := &arden.Dialer{
		TLSConfig:      &tls.Config{RootCAs: roots},
		Authentication: configuration,
	}
	conn, err := dialer.Dial(context.Background(), arden.Endpoint{
		ID:         "tls-auth",
		Address:    listener.Addr().String(),
		ServerName: "ldap.auth.test",
	})
	require.NoError(t, err)
	require.Equal(t, "service-account-a", conn.Identity().StableID)
	require.NoError(t, conn.Close())
	err = <-serverErr
	assert.True(t, err == nil || errors.Is(err, io.EOF))
}

func TestFailedSimpleBindNeverPublishesConnectionAndRedactsValues(t *testing.T) {
	certificate, roots := authenticationTestCertificate(t, "ldap.auth.test")
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}})
	require.NoError(t, err)
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
		response := authenticationBindMessage(
			envelope.MessageID,
			rfc4511.ResultInvalidCredentials,
			[]byte("diagnostic-with-secret-value"),
		)
		_, err = peer.Write(response)
		if err != nil {
			closed <- err
			return
		}
		_, err = framer.Next()
		closed <- err
	}()

	configuration, err := auth.NewSimpleBind("service-account-a", "uid=service", "credential-secret-value")
	require.NoError(t, err)
	dialer := &arden.Dialer{TLSConfig: &tls.Config{RootCAs: roots}, Authentication: configuration}
	conn, err := dialer.Dial(context.Background(), arden.Endpoint{
		ID: "tls-auth", Address: listener.Addr().String(), ServerName: "ldap.auth.test",
	})
	require.Nil(t, conn)
	var setupErr *arden.SetupError
	var bindErr *auth.BindError
	require.ErrorAs(t, err, &setupErr)
	assert.Equal(t, arden.SetupAuthentication, setupErr.Stage)
	require.ErrorAs(t, err, &bindErr)
	assert.NotContains(t, err.Error(), "secret-value")
	peerErr := <-closed
	assert.True(t, peerErr == nil || errors.Is(peerErr, io.EOF) || errors.Is(peerErr, net.ErrClosed))
}

func TestSimpleBindPlaintextPreflightRunsBeforeDial(t *testing.T) {
	configuration, err := auth.NewSimpleBind("service-account-a", "uid=service", "credential")
	require.NoError(t, err)
	conn, err := (&arden.Dialer{Authentication: configuration}).Dial(context.Background(), arden.Endpoint{
		ID: "plain", Address: "127.0.0.1:1", Transport: arden.TransportPlaintext,
	})
	require.Nil(t, conn)
	var setupErr *arden.SetupError
	var transportErr *arden.TransportError
	require.ErrorAs(t, err, &setupErr)
	assert.Equal(t, arden.SetupAuthentication, setupErr.Stage)
	assert.NotErrorAs(t, err, &transportErr)
}

func authenticationBindMessage(id arden.MessageID, code rfc4511.ResultCode, diagnostic []byte) []byte {
	response := rfc4511.BindResponse{Result: rfc4511.LDAPResult{
		ResultCode: code, DiagnosticMessage: rfc4511.LDAPString(diagnostic),
	}}
	return ber.Sequence().
		Add(ber.Integer(id)).
		Add(response).
		BERPacket().Encode()
}

func authenticationTestCertificate(t *testing.T, serverName string) (tls.Certificate, *x509.CertPool) {
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
