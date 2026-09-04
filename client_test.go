package arden

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
)

func TestEntryTextAndRawAccess(t *testing.T) {
	entry := NewEntry("uid=alice,dc=example")
	entry.Set("cn", "Alice", "Alice Example")
	entry.SetBytes("jpegPhoto", []byte{0x00, 0xff})

	assert.Equal(t, "Alice", entry.Value("CN"))
	assert.Equal(t, []string{"Alice", "Alice Example"}, entry.Values("cn"))
	assert.Equal(t, []byte{0x00, 0xff}, entry.RawValue("jpegphoto"))
	assert.True(t, entry.Contains("cn", "Alice Example"))

	raw := entry.RawValue("jpegPhoto")
	raw[0] = 0x7f
	assert.Equal(t, []byte{0x7f, 0xff}, entry.RawValue("jpegPhoto"))
}

func TestEntryByteStorageIsSharedButTextValuesAreSnapshots(t *testing.T) {
	value := []byte("Alice")
	input := [][]byte{value, []byte("Bob")}
	entry := NewEntry("cn=Alice")
	entry.SetBytes("cn", input...)
	text := entry.Value("cn")
	texts := entry.Values("cn")
	input[0] = []byte("replacement")
	value[0] = 'a'
	assert.Equal(t, "alice", entry.Value("CN"))
	assert.Equal(t, "Alice", text)
	assert.Equal(t, []string{"Alice", "Bob"}, texts)

	raw := entry.RawValues("CN")
	raw[1][0] = 'b'
	raw[0] = nil
	assert.Equal(t, []string{"alice", "bob"}, entry.Values("cn"))
	assert.Nil(t, entry.RawValue("missing"))
	entry.SetBytes("cn")
	assert.Nil(t, entry.RawValue("cn"))
}

var benchmarkEntryValue string

func BenchmarkEntryValue(b *testing.B) {
	entry := NewEntry("cn=Alice")
	entry.Set("cn", "Alice Example", "Another Name", "Third Name")
	for b.Loop() {
		benchmarkEntryValue = entry.Value("cn")
	}
}

func TestClientAddReturnsTypedLDAPResultError(t *testing.T) {
	executor := &scriptedExecutor{pages: [][]Response{{protocolResponse(t, rfc4511.AddResponseIdentifier(), rfc4511.AddResponse{
		Result: rfc4511.LDAPResult{ResultCode: rfc4511.ResultEntryAlreadyExists, DiagnosticMessage: "exists"},
	})}}}
	entry := NewEntry("uid=alice,dc=example")
	entry.Set("objectClass", "person")

	err := NewClient(executor).Add(context.Background(), entry)
	var resultErr *ResultError
	require.ErrorAs(t, err, &resultErr)
	assert.Equal(t, rfc4511.ResultEntryAlreadyExists, resultErr.ResultCode())
	require.Len(t, executor.operations, 1)
	request := executor.operations[0].Protocol.(*rfc4511.AddRequest)
	assert.Equal(t, entry.DN, request.Entry)
}

func TestClientExecuteSingleReturnsTypedPointerAndControls(t *testing.T) {
	control := rfc4511.Control{Type: "1.2.3"}
	executor := &scriptedExecutor{pages: [][]Response{
		{protocolResponseWithControls(
			t,
			rfc4511.AddResponseIdentifier(),
			rfc4511.AddResponse{Result: rfc4511.LDAPResult{ResultCode: rfc4511.ResultSuccess}},
			control,
		)},
	}}
	operation, err := rfc4511.NewAddOperation(&rfc4511.AddRequest{Entry: "uid=alice,dc=example"}, nil)
	require.NoError(t, err)

	response, controls, err := NewClient(executor).ExecuteSingle(context.Background(), operation)
	require.NoError(t, err)
	require.NotNil(t, response)
	assert.Equal(t, rfc4511.ResultSuccess, response.Result.ResultCode)
	assert.Equal(t, []rfc4511.Control{control}, controls)
}

func TestClientExecuteSingleErrorReturnValues(t *testing.T) {
	operation, err := rfc4511.NewAddOperation(&rfc4511.AddRequest{Entry: "uid=alice,dc=example"}, nil)
	require.NoError(t, err)

	t.Run("LDAP result", func(t *testing.T) {
		executor := &scriptedExecutor{pages: [][]Response{{protocolResponse(t, rfc4511.AddResponseIdentifier(), rfc4511.AddResponse{
			Result: rfc4511.LDAPResult{ResultCode: rfc4511.ResultBusy},
		})}}}
		response, controls, err := NewClient(executor).ExecuteSingle(context.Background(), operation)
		require.NotNil(t, response)
		assert.Equal(t, rfc4511.ResultBusy, response.Result.ResultCode)
		assert.Empty(t, controls)
		var resultErr *ResultError
		require.ErrorAs(t, err, &resultErr)
		assert.Equal(t, rfc4511.ResultBusy, resultErr.ResultCode())
	})

	t.Run("decode", func(t *testing.T) {
		executor := &scriptedExecutor{pages: [][]Response{
			{{
				ProtocolID: rfc4511.AddResponseIdentifier(),
				Protocol:   []byte{0x01, 0x01, 0xff},
			}},
		}}
		response, controls, err := NewClient(executor).ExecuteSingle(context.Background(), operation)
		assert.Nil(t, response)
		assert.Nil(t, controls)
		assert.Error(t, err)
	})
}

func TestClientExecuteSingleAcceptResultCodesReplacesSuccessDefault(t *testing.T) {
	executor := &scriptedExecutor{pages: [][]Response{{protocolResponse(t, rfc4511.AddResponseIdentifier(), rfc4511.AddResponse{
		Result: rfc4511.LDAPResult{ResultCode: rfc4511.ResultEntryAlreadyExists},
	})}}}
	operation, err := rfc4511.NewAddOperation(&rfc4511.AddRequest{Entry: "uid=alice,dc=example"}, nil)
	require.NoError(t, err)

	response, _, err := NewClient(executor).ExecuteSingle(
		context.Background(),
		operation,
		AcceptResultCodes(rfc4511.ResultEntryAlreadyExists),
	)
	require.NoError(t, err)
	require.NotNil(t, response)
	assert.Equal(t, rfc4511.ResultEntryAlreadyExists, response.Result.ResultCode)
}

func TestClientExecuteStreamDecodesResponsesAndControls(t *testing.T) {
	control := rfc4511.Control{Type: "1.2.3"}
	executor := &scriptedExecutor{pages: [][]Response{{
		protocolResponseWithControls(t, rfc4511.SearchResultEntryIdentifier(), rfc4511.SearchResultEntry{
			ObjectName: "uid=alice,dc=example",
		}, control),
		protocolResponse(t, rfc4511.SearchResultDoneIdentifier(), rfc4511.SearchResultDone{
			Result: rfc4511.LDAPResult{ResultCode: rfc4511.ResultSuccess},
		}),
	}}}
	request := SearchRequest{BaseDN: "dc=example", Scope: ScopeSubtree, Filter: Has("uid")}.protocolRequest()
	operation, err := rfc4511.NewSearchOperation(&request, nil)
	require.NoError(t, err)

	stream, err := NewClient(executor).ExecuteStream(context.Background(), operation)
	require.NoError(t, err)
	defer func() { require.NoError(t, stream.Close()) }()

	response, controls, err := stream.Next(context.Background())
	require.NoError(t, err)
	entry, ok := response.Value().(rfc4511.SearchResultEntry)
	require.True(t, ok)
	assert.Equal(t, rfc4511.LDAPDN("uid=alice,dc=example"), entry.ObjectName)
	assert.Equal(t, []rfc4511.Control{control}, controls)

	response, controls, err = stream.Next(context.Background())
	require.NoError(t, err)
	done, ok := response.Value().(rfc4511.SearchResultDone)
	require.True(t, ok)
	assert.Equal(t, rfc4511.ResultSuccess, done.Result.ResultCode)
	assert.Empty(t, controls)

	response, controls, err = stream.Next(context.Background())
	require.ErrorIs(t, err, io.EOF)
	assert.Nil(t, response)
	assert.Nil(t, controls)
	require.NoError(t, stream.Close())
	assert.True(t, executor.streams[0].closed)
}

func TestClientSearchFollowsPagedResultsCookies(t *testing.T) {
	firstControl := newPagedResultsControl(2, []byte("next"))
	secondControl := newPagedResultsControl(2, nil)
	executor := &scriptedExecutor{pages: [][]Response{
		{
			protocolResponse(t, rfc4511.SearchResultEntryIdentifier(), rfc4511.SearchResultEntry{
				ObjectName: "uid=one,dc=example",
				Attributes: []rfc4511.PartialAttribute{{Type: "uid", Values: []rfc4511.AttributeValue{rfc4511.AttributeValue("one")}}},
			}),
			protocolResponseWithControls(t, rfc4511.SearchResultDoneIdentifier(), rfc4511.SearchResultDone{Result: rfc4511.LDAPResult{ResultCode: rfc4511.ResultSuccess}}, firstControl),
		},
		{
			protocolResponse(t, rfc4511.SearchResultEntryIdentifier(), rfc4511.SearchResultEntry{
				ObjectName: "uid=two,dc=example",
				Attributes: []rfc4511.PartialAttribute{{Type: "uid", Values: []rfc4511.AttributeValue{rfc4511.AttributeValue("two")}}},
			}),
			protocolResponseWithControls(t, rfc4511.SearchResultDoneIdentifier(), rfc4511.SearchResultDone{Result: rfc4511.LDAPResult{ResultCode: rfc4511.ResultSuccess}}, secondControl),
		},
	}}

	rows, err := NewClient(executor).Search(context.Background(), SearchRequest{
		BaseDN: "dc=example", Scope: ScopeSubtree, Filter: Has("uid"),
		Attributes: []string{"uid"}, PageSize: 2,
	})
	require.NoError(t, err)
	defer func() { require.NoError(t, rows.Close()) }()

	var values []string
	for rows.Next() {
		values = append(values, rows.Entry().Value("uid"))
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, []string{"one", "two"}, values)
	require.Len(t, executor.operations, 2)
	require.Len(t, executor.streams, 2)
	assert.True(t, executor.streams[0].closed, "first page stream was not closed before paging")
	assert.True(t, executor.streams[1].closed, "final page stream was not closed")

	firstCookie := requestPageCookie(t, executor.operations[0])
	secondCookie := requestPageCookie(t, executor.operations[1])
	assert.Empty(t, firstCookie)
	assert.Equal(t, []byte("next"), secondCookie)
}

func TestClientGetRequiresOneEntry(t *testing.T) {
	executor := &scriptedExecutor{pages: [][]Response{{
		protocolResponse(t, rfc4511.SearchResultDoneIdentifier(), rfc4511.SearchResultDone{Result: rfc4511.LDAPResult{ResultCode: rfc4511.ResultSuccess}}),
	}}}
	_, err := NewClient(executor).Get(context.Background(), "uid=missing,dc=example", "uid")
	require.ErrorIs(t, err, ErrNotFound)
}

type scriptedExecutor struct {
	pages      [][]Response
	operations []UntypedOperation
	streams    []*scriptedResponseStream
}

func (e *scriptedExecutor) Do(_ context.Context, operation AnyOperation) (ResponseStream, error) {
	e.operations = append(e.operations, operation.Untyped())
	index := len(e.operations) - 1
	if index >= len(e.pages) {
		return nil, errors.New("unexpected operation")
	}
	if index > 0 && !e.streams[index-1].closed {
		return nil, errors.New("previous response stream is still open")
	}
	stream := &scriptedResponseStream{responses: e.pages[index]}
	e.streams = append(e.streams, stream)
	return stream, nil
}

type scriptedResponseStream struct {
	responses []Response
	index     int
	closed    bool
}

func (s *scriptedResponseStream) Next(context.Context) (Response, error) {
	if s.index == len(s.responses) {
		return Response{}, io.EOF
	}
	response := s.responses[s.index]
	s.index++
	return response, nil
}

func (s *scriptedResponseStream) Close() error {
	s.closed = true
	return nil
}

func protocolResponse(t *testing.T, identifier ber.Identifier, value ber.Packeter) Response {
	t.Helper()
	protocol := value.BERPacket().Encode()
	return Response{ProtocolID: identifier, Protocol: protocol, Bytes: protocol}
}

func protocolResponseWithControls(t *testing.T, identifier ber.Identifier, value ber.Packeter, controls ...rfc4511.Control) Response {
	t.Helper()
	response := protocolResponse(t, identifier, value)
	for _, control := range controls {
		raw := control.BERPacket().Encode()
		response.Controls = append(response.Controls, ber.Element{Identifier: ber.SequenceIdentifier, Raw: raw})
	}
	return response
}

func requestPageCookie(t *testing.T, operation UntypedOperation) []byte {
	t.Helper()
	for _, packet := range operation.Controls {
		control, ok := packet.(rfc4511.Control)
		if !ok || control.Type != pagedResultsOID {
			continue
		}
		cookie, err := pagedResultsCookie([]rfc4511.Control{control}, ber.DefaultLimits())
		require.NoError(t, err)
		return cookie
	}
	require.Fail(t, "paged-results control missing")
	return nil
}
