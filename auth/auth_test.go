package auth

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
)

type recordingSession struct {
	operations []arden.UntypedOperation
	response   arden.Response
	err        error
}

func (s *recordingSession) Do(_ context.Context, operation arden.AnyOperation) (arden.ResponseStream, error) {
	s.operations = append(s.operations, operation.Untyped())
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
	require.NoError(t, err)
	identity, err := authenticator.Authenticate(context.Background(), session)
	require.NoError(t, err)
	require.Equal(t, anonymousStableID, identity.StableID)
	require.Len(t, session.operations, 1)
	request, ok := session.operations[0].Protocol.(*rfc4511.BindRequest)
	require.True(t, ok)
	credentials, ok := request.Authentication.(rfc4511.SimpleAuthentication)
	assert.Equal(t, int64(3), request.Version)
	assert.Empty(t, request.Name)
	assert.True(t, ok)
	assert.Empty(t, credentials)
}

func TestSimpleBindUsesStringValuesAndClearsPerConnectionCopies(t *testing.T) {
	const bindDN = "cn=user"
	const credential = "password"
	configuration, err := NewSimpleBind("service-account-a", bindDN, credential)
	require.NoError(t, err)

	authenticatorValue, err := configuration.Begin(context.Background(), arden.Endpoint{
		ID: "tls", Address: "unused", ServerName: "ldap.test",
	})
	require.NoError(t, err)
	authenticator := authenticatorValue.(*bindAuthenticator)
	session := &recordingSession{response: bindResponse(t, rfc4511.ResultSuccess, nil)}
	identity, err := authenticator.Authenticate(context.Background(), session)
	require.NoError(t, err)
	require.Equal(t, "service-account-a", identity.StableID)
	request := session.operations[0].Protocol.(*rfc4511.BindRequest)
	require.Equal(t, rfc4511.LDAPDN(bindDN), request.Name)
	require.Equal(t, credential, string(request.Authentication.(rfc4511.SimpleAuthentication)))
	require.NoError(t, authenticator.Close())
	assert.Empty(t, authenticator.name)
	assert.Nil(t, authenticator.credentials)
}

func TestSimpleBindRejectsPlaintextBeforeBegin(t *testing.T) {
	configuration, err := NewSimpleBind("service-account-a", "uid=user", "password")
	require.NoError(t, err)
	endpoint := arden.Endpoint{ID: "plain", Address: "unused", Transport: arden.TransportPlaintext}
	require.Error(t, configuration.ValidateEndpoint(endpoint))
	_, err = configuration.Begin(context.Background(), endpoint)
	assert.Error(t, err)
}

func TestBindFailureReportsOnlyResultCode(t *testing.T) {
	const secret = "server diagnostic containing password-value"
	session := &recordingSession{response: bindResponse(t, rfc4511.ResultInvalidCredentials, []byte(secret))}
	authenticator, err := (Anonymous{}).Begin(context.Background(), arden.Endpoint{})
	require.NoError(t, err)
	_, err = authenticator.Authenticate(context.Background(), session)
	var bindErr *BindError
	require.ErrorAs(t, err, &bindErr)
	assert.Equal(t, rfc4511.ResultInvalidCredentials, bindErr.ResultCode)
	assert.NotContains(t, err.Error(), secret)
}

func TestSimpleBindRejectsAmbiguousEmptyAuthentication(t *testing.T) {
	_, err := NewSimpleBind("identity", "", "password")
	require.Error(t, err)
	_, err = NewSimpleBind("identity", "uid=user", "")
	assert.Error(t, err)
}

func bindResponse(t *testing.T, code rfc4511.ResultCode, diagnostic []byte) arden.Response {
	t.Helper()
	protocol, err := (rfc4511.BindResponse{Result: rfc4511.LDAPResult{
		ResultCode: code, DiagnosticMessage: rfc4511.LDAPString(diagnostic),
	}}).AppendBER(nil)
	require.NoError(t, err)
	contents, err := ber.AppendInteger(nil, 1)
	require.NoError(t, err)
	contents = append(contents, protocol...)
	message, err := ber.AppendSequence(nil, contents)
	require.NoError(t, err)
	response, err := arden.ParseResponse(message, ber.DefaultLimits())
	require.NoError(t, err)
	return response
}
