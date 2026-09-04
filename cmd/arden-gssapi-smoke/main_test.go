//go:build gssapi && cgo && (linux || darwin || freebsd || openbsd)

package main

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
	"github.com/wyattanderson/arden/rfc4532"
)

func TestWhoAmIVerifiesAuthenticatedAuthorizationIdentity(t *testing.T) {
	executor := &scriptedExecutor{response: extendedResponse(t, rfc4511.ExtendedResponse{
		Result:           rfc4511.LDAPResult{ResultCode: rfc4511.ResultSuccess},
		ResponseValue:    []byte("u:alice@EXAMPLE.TEST"),
		HasResponseValue: true,
	})}

	got, err := rfc4532.WhoAmI(context.Background(), executor)
	require.NoError(t, err)
	require.Equal(t, "u:alice@EXAMPLE.TEST", got)
	request, ok := executor.operation.Untyped().Protocol.(*rfc4511.ExtendedRequest)
	require.True(t, ok)
	assert.Equal(t, rfc4532.OID, request.Name)
	assert.False(t, request.HasValue)
	assert.True(t, executor.stream.closed)
}

func TestWhoAmIRejectsResponsesThatDoNotVerifyAuthentication(t *testing.T) {
	const diagnostic = "secret server diagnostic"
	tests := []struct {
		name     string
		response rfc4511.ExtendedResponse
		want     string
	}{
		{
			name:     "missing response value",
			response: rfc4511.ExtendedResponse{Result: rfc4511.LDAPResult{ResultCode: rfc4511.ResultSuccess}},
			want:     "omitted the authorization identity",
		},
		{
			name: "unexpected response name",
			response: rfc4511.ExtendedResponse{
				Result:           rfc4511.LDAPResult{ResultCode: rfc4511.ResultSuccess},
				ResponseName:     rfc4532.OID,
				HasResponseName:  true,
				ResponseValue:    []byte("u:alice"),
				HasResponseValue: true,
			},
			want: "unexpected response name",
		},
		{
			name: "server rejection",
			response: rfc4511.ExtendedResponse{Result: rfc4511.LDAPResult{
				ResultCode:        rfc4511.ResultInsufficientAccessRights,
				DiagnosticMessage: rfc4511.LDAPString(diagnostic),
			}},
			want: "LDAP result code",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executor := &scriptedExecutor{response: extendedResponse(t, test.response)}
			_, err := rfc4532.WhoAmI(context.Background(), executor)
			require.Error(t, err)
			assert.ErrorContains(t, err, test.want)
			assert.NotContains(t, err.Error(), diagnostic)
		})
	}
}

type scriptedExecutor struct {
	response  arden.Response
	operation arden.AnyOperation
	stream    *singleResponseStream
}

func (e *scriptedExecutor) Do(_ context.Context, operation arden.AnyOperation) (arden.ResponseStream, error) {
	e.operation = operation
	e.stream = &singleResponseStream{response: e.response}
	return e.stream, nil
}

type singleResponseStream struct {
	response arden.Response
	read     bool
	closed   bool
}

func (s *singleResponseStream) Next(context.Context) (arden.Response, error) {
	if s.read {
		return arden.Response{}, io.EOF
	}
	s.read = true
	return s.response, nil
}

func (s *singleResponseStream) Close() error {
	s.closed = true
	return nil
}

func extendedResponse(t *testing.T, response rfc4511.ExtendedResponse) arden.Response {
	t.Helper()
	message := ber.Sequence().
		Add(ber.Integer(1)).
		Add(response).
		BERPacket().Encode()
	decoded, err := arden.ParseResponse(message, ber.DefaultLimits())
	require.NoError(t, err)
	return decoded
}
