package rfc4532

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/protocol"
	"github.com/wyattanderson/arden/rfc4511"
)

func TestWhoAmI(t *testing.T) {
	encoded, err := (rfc4511.ExtendedResponse{
		Result:        rfc4511.LDAPResult{ResultCode: rfc4511.ResultSuccess},
		ResponseValue: []byte("dn:uid=alice,dc=example"), HasResponseValue: true,
	}).AppendBER(nil)
	require.NoError(t, err)
	executor := &executor{response: protocol.Response{
		ProtocolID: rfc4511.ExtendedResponseIdentifier(), Protocol: encoded,
	}}

	identity, err := WhoAmI(context.Background(), executor)
	require.NoError(t, err)
	assert.Equal(t, "dn:uid=alice,dc=example", identity)
	untyped := executor.operation.Untyped()
	require.NotNil(t, untyped.Protocol)
	request := untyped.Protocol.(*rfc4511.ExtendedRequest)
	assert.Equal(t, OID, request.Name)
}

type executor struct {
	operation protocol.AnyOperation
	response  protocol.Response
}

func (e *executor) Do(_ context.Context, operation protocol.AnyOperation) (protocol.ResponseStream, error) {
	e.operation = operation
	return &stream{response: e.response}, nil
}

type stream struct {
	response protocol.Response
	done     bool
}

func (s *stream) Next(context.Context) (protocol.Response, error) {
	if s.done {
		return protocol.Response{}, io.EOF
	}
	s.done = true
	return s.response, nil
}

func (*stream) Close() error { return nil }
