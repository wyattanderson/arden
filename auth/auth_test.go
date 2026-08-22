package auth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
)

type recordingSession struct {
	operations []arden.Operation
	response   arden.Response
	err        error
}

func (s *recordingSession) Do(_ context.Context, operation arden.Operation) (arden.ResponseStream, error) {
	s.operations = append(s.operations, operation)
	if s.err != nil {
		return nil, s.err
	}
	return &singleResponseStream{response: s.response}, nil
}

type singleResponseStream struct {
	response arden.Response
	read     bool
}

func (s *singleResponseStream) Next(context.Context) (arden.Response, error) {
	if s.read {
		return arden.Response{}, io.EOF
	}
	s.read = true
	return s.response, nil
}

func (*singleResponseStream) Close() error { return nil }

func TestAnonymousUsesMinimalOrdinaryBind(t *testing.T) {
	session := &recordingSession{response: bindResponse(t, rfc4511.ResultSuccess, nil)}
	authenticator, err := (Anonymous{}).Begin(context.Background(), arden.Endpoint{
		ID: "plain", Address: "unused", Transport: arden.TransportPlaintext,
	})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := authenticator.Authenticate(context.Background(), session)
	if err != nil {
		t.Fatal(err)
	}
	if identity.StableID != anonymousStableID {
		t.Fatalf("anonymous identity = %q", identity.StableID)
	}
	if len(session.operations) != 1 {
		t.Fatalf("Bind operations = %d, want 1", len(session.operations))
	}
	request, ok := session.operations[0].Protocol.(*rfc4511.BindRequest)
	if !ok {
		t.Fatalf("anonymous protocol = %T", session.operations[0].Protocol)
	}
	credentials, ok := request.Authentication.(rfc4511.SimpleAuthentication)
	if request.Version != 3 || len(request.Name) != 0 || !ok || len(credentials) != 0 {
		t.Fatalf("anonymous Bind = %#v", request)
	}
}

func TestSimpleBindPreservesBinaryValuesAndClearsPerConnectionCopies(t *testing.T) {
	bindDN := []byte{'c', 'n', '=', 0xff}
	credential := []byte{0x00, 0xff, 0x01}
	configuration, err := NewSimpleBind("service-account-a", bindDN, credential)
	if err != nil {
		t.Fatal(err)
	}
	bindDN[0], credential[0] = 'X', 'X'

	authenticatorValue, err := configuration.Begin(context.Background(), arden.Endpoint{
		ID: "tls", Address: "unused", ServerName: "ldap.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	authenticator := authenticatorValue.(*bindAuthenticator)
	session := &recordingSession{response: bindResponse(t, rfc4511.ResultSuccess, nil)}
	identity, err := authenticator.Authenticate(context.Background(), session)
	if err != nil {
		t.Fatal(err)
	}
	if identity.StableID != "service-account-a" {
		t.Fatalf("Simple identity = %q", identity.StableID)
	}
	request := session.operations[0].Protocol.(*rfc4511.BindRequest)
	if !bytes.Equal(request.Name, []byte{'c', 'n', '=', 0xff}) {
		t.Fatalf("Bind DN = %x", request.Name)
	}
	if got := []byte(request.Authentication.(rfc4511.SimpleAuthentication)); !bytes.Equal(got, []byte{0x00, 0xff, 0x01}) {
		t.Fatalf("Bind credentials = %x", got)
	}
	if err := authenticator.Close(); err != nil {
		t.Fatal(err)
	}
	if authenticator.name != nil || authenticator.credentials != nil {
		t.Fatal("per-connection authentication material was retained after Close")
	}
}

func TestSimpleBindRejectsPlaintextBeforeBegin(t *testing.T) {
	configuration, err := NewSimpleBind("service-account-a", []byte("uid=user"), []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	endpoint := arden.Endpoint{ID: "plain", Address: "unused", Transport: arden.TransportPlaintext}
	if err := configuration.ValidateEndpoint(endpoint); err == nil {
		t.Fatal("Simple Bind accepted plaintext")
	}
	if _, err := configuration.Begin(context.Background(), endpoint); err == nil {
		t.Fatal("Simple Bind Begin accepted plaintext")
	}
}

func TestBindFailureReportsOnlyResultCode(t *testing.T) {
	const secret = "server diagnostic containing password-value"
	session := &recordingSession{response: bindResponse(t, rfc4511.ResultInvalidCredentials, []byte(secret))}
	authenticator, err := (Anonymous{}).Begin(context.Background(), arden.Endpoint{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = authenticator.Authenticate(context.Background(), session)
	var bindErr *BindError
	if !errors.As(err, &bindErr) || bindErr.ResultCode != rfc4511.ResultInvalidCredentials {
		t.Fatalf("Bind error = %v", err)
	}
	if bytes.Contains([]byte(err.Error()), []byte(secret)) {
		t.Fatalf("Bind error leaked server diagnostic: %v", err)
	}
}

func TestSimpleBindRejectsAmbiguousEmptyAuthentication(t *testing.T) {
	if _, err := NewSimpleBind("identity", nil, []byte("password")); err == nil {
		t.Fatal("Simple Bind accepted an empty DN")
	}
	if _, err := NewSimpleBind("identity", []byte("uid=user"), nil); err == nil {
		t.Fatal("Simple Bind accepted empty credentials")
	}
}

func bindResponse(t *testing.T, code rfc4511.ResultCode, diagnostic []byte) arden.Response {
	t.Helper()
	protocol, err := (rfc4511.BindResponse{Result: rfc4511.LDAPResult{
		ResultCode: code, DiagnosticMessage: rfc4511.LDAPString(diagnostic),
	}}).AppendBER(nil)
	if err != nil {
		t.Fatal(err)
	}
	contents, err := ber.AppendInteger(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	contents = append(contents, protocol...)
	message, err := ber.AppendSequence(nil, contents)
	if err != nil {
		t.Fatal(err)
	}
	response, err := arden.ParseResponse(message, ber.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return response
}
