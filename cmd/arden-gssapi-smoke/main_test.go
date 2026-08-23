//go:build gssapi && cgo && (linux || darwin || freebsd || openbsd)

package main

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
)

func TestWhoAmIVerifiesAuthenticatedAuthorizationIdentity(t *testing.T) {
	executor := &scriptedExecutor{response: extendedResponse(t, rfc4511.ExtendedResponse{
		Result:           rfc4511.LDAPResult{ResultCode: rfc4511.ResultSuccess},
		ResponseValue:    []byte("u:alice@EXAMPLE.TEST"),
		HasResponseValue: true,
	})}

	got, err := whoAmI(context.Background(), executor)
	if err != nil {
		t.Fatal(err)
	}
	if got != "u:alice@EXAMPLE.TEST" {
		t.Fatalf("authorization identity = %q", got)
	}
	request, ok := executor.operation.Protocol.(*rfc4511.ExtendedRequest)
	if !ok || string(request.Name) != whoAmIOID || request.HasValue {
		t.Fatalf("Who Am I? request = %#v", executor.operation.Protocol)
	}
	if !executor.stream.closed {
		t.Fatal("Who Am I? response stream was not closed")
	}
}

func TestWhoAmIRejectsResponsesThatDoNotVerifyAuthentication(t *testing.T) {
	const diagnostic = "secret server diagnostic"
	tests := []struct {
		name     string
		response rfc4511.ExtendedResponse
		want     string
	}{
		{
			name: "anonymous",
			response: rfc4511.ExtendedResponse{
				Result: rfc4511.LDAPResult{ResultCode: rfc4511.ResultSuccess}, HasResponseValue: true,
			},
			want: "anonymous authorization identity",
		},
		{
			name:     "missing response value",
			response: rfc4511.ExtendedResponse{Result: rfc4511.LDAPResult{ResultCode: rfc4511.ResultSuccess}},
			want:     "omitted the authorization identity",
		},
		{
			name: "unexpected response name",
			response: rfc4511.ExtendedResponse{
				Result:           rfc4511.LDAPResult{ResultCode: rfc4511.ResultSuccess},
				ResponseName:     rfc4511.LDAPOID(whoAmIOID),
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
				DiagnosticMessage: []byte(diagnostic),
			}},
			want: "LDAP result code",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executor := &scriptedExecutor{response: extendedResponse(t, test.response)}
			_, err := whoAmI(context.Background(), executor)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
			if strings.Contains(err.Error(), diagnostic) {
				t.Fatalf("error leaked server diagnostic: %v", err)
			}
		})
	}
}

type scriptedExecutor struct {
	response  arden.Response
	operation arden.Operation
	stream    *singleResponseStream
}

func (e *scriptedExecutor) Do(_ context.Context, operation arden.Operation) (arden.ResponseStream, error) {
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
	protocol, err := response.AppendBER(nil)
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
	decoded, err := arden.ParseResponse(message, ber.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
