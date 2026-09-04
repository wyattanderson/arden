package arden

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
)

var (
	testSearchRequest = ber.Identifier{Class: ber.ClassApplication, Constructed: true, Number: 3}
	testSearchEntry   = ber.Identifier{Class: ber.ClassApplication, Constructed: true, Number: 4}
	testSearchDone    = ber.Identifier{Class: ber.ClassApplication, Constructed: true, Number: 5}
	testModifyRequest = ber.Identifier{Class: ber.ClassApplication, Constructed: true, Number: 6}
	testModifyDone    = ber.Identifier{Class: ber.ClassApplication, Constructed: true, Number: 7}
)

type testProtocol struct {
	id      ber.Identifier
	encoded []byte
}

type testResponse struct{}

func (*testResponse) UnmarshalBER(*ber.Reader) error { return nil }

func (p testProtocol) ProtocolIdentifier() ber.Identifier { return p.id }
func (p testProtocol) BERPacket() ber.Packet              { return ber.Encoded(p.encoded) }

func newTestOperation(t *testing.T, request ber.Identifier, pattern ResponseSpec, mode CancellationMode) Operation[testResponse] {
	t.Helper()
	encoded := ber.WithContents(request, nil).Encode()
	responses, err := NewResponsePattern[testResponse](pattern)
	require.NoError(t, err)
	return Operation[testResponse]{
		Protocol:     testProtocol{id: request, encoded: encoded},
		Responses:    responses,
		Cancellation: mode,
	}
}

func newPipeConnection(t *testing.T, options ConnectionOptions, maxID MessageID) (*Conn, net.Conn) {
	t.Helper()
	normalized, err := options.normalized()
	require.NoError(t, err)
	client, server := net.Pipe()
	conn, err := newConn(client, Endpoint{ID: "test", Address: "pipe", Transport: TransportPlaintext}, normalized, maxID)
	require.NoError(t, err)
	t.Cleanup(func() {
		conn.retire(ErrClosed)
		_ = server.Close()
	})
	return conn, server
}

func newTestFramer(t *testing.T, conn net.Conn) *ber.Framer {
	t.Helper()
	framer, err := ber.NewFramer(conn, ber.DefaultLimits())
	require.NoError(t, err)
	return framer
}

func readTestMessage(t *testing.T, framer *ber.Framer) Response {
	t.Helper()
	message, err := framer.Next()
	if err != nil {
		assert.NoError(t, err)
		return Response{}
	}
	response, err := ParseResponse(message, ber.DefaultLimits())
	if err != nil {
		assert.NoError(t, err)
		return Response{}
	}
	return response
}

func testLDAPMessage(t *testing.T, id MessageID, protocolID ber.Identifier, value []byte) []byte {
	t.Helper()
	return encodeInternalRequest(id, ber.WithContents(protocolID, value))
}

func writeTestMessage(t *testing.T, conn net.Conn, message []byte) {
	t.Helper()
	if _, err := conn.Write(message); err != nil {
		assert.NoError(t, err)
	}
}

func TestConnectionRoutesInterleavedOperations(t *testing.T) {
	conn, peer := newPipeConnection(t, ConnectionOptions{}, MaxMessageID)
	framer := newTestFramer(t, peer)
	serverErr := make(chan error, 1)
	go func() {
		first := readTestMessage(t, framer)
		second := readTestMessage(t, framer)
		writeTestMessage(t, peer, testLDAPMessage(t, first.MessageID, testSearchEntry, []byte("entry")))
		writeTestMessage(t, peer, testLDAPMessage(t, second.MessageID, testModifyDone, []byte("modify")))
		writeTestMessage(t, peer, testLDAPMessage(t, first.MessageID, testSearchDone, []byte("done")))
		serverErr <- nil
	}()

	search, err := conn.Do(context.Background(), newTestOperation(t, testSearchRequest, ResponseSpec{
		Continue: []ber.Identifier{testSearchEntry}, Complete: []ber.Identifier{testSearchDone},
	}, CancelDrain))
	require.NoError(t, err)
	modify, err := conn.Do(context.Background(), newTestOperation(t, testModifyRequest, ResponseSpec{
		Complete: []ber.Identifier{testModifyDone},
	}, CancelDrain))
	require.NoError(t, err)

	searchEntry, err := search.Next(context.Background())
	require.NoError(t, err)
	require.Equal(t, testSearchEntry, searchEntry.ProtocolID)
	modifyDone, err := modify.Next(context.Background())
	require.NoError(t, err)
	require.Equal(t, testModifyDone, modifyDone.ProtocolID)
	searchDone, err := search.Next(context.Background())
	require.NoError(t, err)
	require.Equal(t, testSearchDone, searchDone.ProtocolID)
	_, err = search.Next(context.Background())
	require.ErrorIs(t, err, io.EOF)
	require.NoError(t, <-serverErr)
}

func TestConnectionSerializesConcurrentShortWrites(t *testing.T) {
	const operations = 32
	conn, peer := newPipeConnection(t, ConnectionOptions{}, MaxMessageID)
	framer := newTestFramer(t, peer)
	ids := make(chan MessageID, operations)
	go func() {
		for range operations {
			ids <- readTestMessage(t, framer).MessageID
		}
	}()

	op := newTestOperation(t, testModifyRequest, ResponseSpec{NoResponse: true}, CancelNone)
	var wg sync.WaitGroup
	errs := make(chan error, operations)
	for range operations {
		wg.Go(func() {
			stream, err := conn.Do(context.Background(), op)
			if err == nil {
				_, err = stream.Next(context.Background())
				if errors.Is(err, io.EOF) {
					err = nil
				}
			}
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	seen := make(map[MessageID]bool)
	for range operations {
		id := <-ids
		require.NotZero(t, id)
		require.NotContains(t, seen, id)
		seen[id] = true
	}
}

func TestMessageIDWrapSkipsOnlyLiveIDs(t *testing.T) {
	conn, peer := newPipeConnection(t, ConnectionOptions{}, 2)
	framer := newTestFramer(t, peer)
	ids := make(chan MessageID, 3)
	go func() {
		for range 3 {
			ids <- readTestMessage(t, framer).MessageID
		}
	}()
	op := newTestOperation(t, testModifyRequest, ResponseSpec{NoResponse: true}, CancelNone)
	for range 3 {
		stream, err := conn.Do(context.Background(), op)
		require.NoError(t, err)
		_, err = stream.Next(context.Background())
		require.ErrorIs(t, err, io.EOF)
	}
	assert.Equal(t, []MessageID{1, 2, 1}, []MessageID{<-ids, <-ids, <-ids})
}

func TestCanceledDrainReleasesIDOnlyAfterTerminalResponse(t *testing.T) {
	conn, peer := newPipeConnection(t, ConnectionOptions{}, 1)
	framer := newTestFramer(t, peer)
	op := newTestOperation(t, testSearchRequest, ResponseSpec{
		Continue: []ber.Identifier{testSearchEntry}, Complete: []ber.Identifier{testSearchDone},
	}, CancelDrain)

	opCtx, cancel := context.WithCancel(context.Background())
	firstRequestReady := make(chan Response, 1)
	go func() { firstRequestReady <- readTestMessage(t, framer) }()
	first, err := conn.Do(opCtx, op)
	require.NoError(t, err)
	firstRequest := <-firstRequestReady
	cancel()
	_, err = first.Next(context.Background())
	require.ErrorIs(t, err, context.Canceled)

	secondResult := make(chan ResponseStream, 1)
	secondErr := make(chan error, 1)
	go func() {
		stream, err := conn.Do(context.Background(), op)
		secondResult <- stream
		secondErr <- err
	}()
	select {
	case err := <-secondErr:
		assert.Fail(t, "second operation completed before drain", "%v", err)
	case <-time.After(25 * time.Millisecond):
	}

	writeTestMessage(t, peer, testLDAPMessage(t, firstRequest.MessageID, testSearchEntry, nil))
	writeTestMessage(t, peer, testLDAPMessage(t, firstRequest.MessageID, testSearchDone, nil))
	secondRequest := readTestMessage(t, framer)
	require.Equal(t, firstRequest.MessageID, secondRequest.MessageID)
	writeTestMessage(t, peer, testLDAPMessage(t, secondRequest.MessageID, testSearchDone, nil))
	second := <-secondResult
	require.NoError(t, <-secondErr)
	response, err := second.Next(context.Background())
	require.NoError(t, err)
	assert.Equal(t, testSearchDone, response.ProtocolID)
}

func TestTerminalResponseWinsCancellationRace(t *testing.T) {
	conn, peer := newPipeConnection(t, ConnectionOptions{}, MaxMessageID)
	framer := newTestFramer(t, peer)
	requestReady := make(chan Response, 1)
	go func() { requestReady <- readTestMessage(t, framer) }()
	ctx, cancel := context.WithCancel(context.Background())
	stream, err := conn.Do(ctx, newTestOperation(t, testModifyRequest, ResponseSpec{Complete: []ber.Identifier{testModifyDone}}, CancelDrain))
	require.NoError(t, err)
	request := <-requestReady
	writeTestMessage(t, peer, testLDAPMessage(t, request.MessageID, testModifyDone, nil))
	concrete := stream.(*responseStream)
	select {
	case <-concrete.pending.ready:
	case <-time.After(time.Second):
		require.Fail(t, "terminal response was not routed")
	}
	cancel()
	response, err := stream.Next(context.Background())
	require.NoError(t, err)
	assert.Equal(t, testModifyDone, response.ProtocolID)
}

func TestAbandonCancellationTombstonesTarget(t *testing.T) {
	conn, peer := newPipeConnection(t, ConnectionOptions{}, 3)
	framer := newTestFramer(t, peer)
	op := newTestOperation(t, testSearchRequest, ResponseSpec{
		Continue: []ber.Identifier{testSearchEntry}, Complete: []ber.Identifier{testSearchDone},
	}, CancelAbandon)
	opCtx, cancel := context.WithCancel(context.Background())
	targetReady := make(chan Response, 1)
	go func() { targetReady <- readTestMessage(t, framer) }()
	stream, err := conn.Do(opCtx, op)
	require.NoError(t, err)
	target := <-targetReady
	cancel()
	_, err = stream.Next(context.Background())
	require.ErrorIs(t, err, context.Canceled)

	abandon := readTestMessage(t, framer)
	require.Equal(t, rfc4511.AbandonRequestIdentifier(), abandon.ProtocolID)
	r, err := ber.NewReader(abandon.Protocol, ber.DefaultLimits())
	require.NoError(t, err)
	abandonedID, err := r.IntegerWithIdentifier(rfc4511.AbandonRequestIdentifier())
	require.NoError(t, err)
	require.Equal(t, target.MessageID, MessageID(abandonedID))

	writeTestMessage(t, peer, testLDAPMessage(t, target.MessageID, testSearchEntry, nil))
	writeTestMessage(t, peer, testLDAPMessage(t, target.MessageID, testSearchDone, nil))
	select {
	case <-conn.Done():
		assert.Fail(t, "tombstoned responses retired connection", "%v", conn.Err())
	case <-time.After(25 * time.Millisecond):
	}
	conn.mu.Lock()
	_, tombstoned := conn.tombstones[target.MessageID]
	conn.mu.Unlock()
	assert.True(t, tombstoned)
}

func TestSlowConsumerCannotBlockUnrelatedOperation(t *testing.T) {
	options := DefaultConnectionOptions()
	options.MaxQueuedResponses = 1
	conn, peer := newPipeConnection(t, options, MaxMessageID)
	framer := newTestFramer(t, peer)
	searchOp := newTestOperation(t, testSearchRequest, ResponseSpec{
		Continue: []ber.Identifier{testSearchEntry}, Complete: []ber.Identifier{testSearchDone},
	}, CancelDrain)
	modifyOp := newTestOperation(t, testModifyRequest, ResponseSpec{Complete: []ber.Identifier{testModifyDone}}, CancelDrain)

	requests := make(chan Response, 2)
	go func() {
		requests <- readTestMessage(t, framer)
		requests <- readTestMessage(t, framer)
	}()
	search, err := conn.Do(context.Background(), searchOp)
	require.NoError(t, err)
	searchRequest := <-requests
	modify, err := conn.Do(context.Background(), modifyOp)
	require.NoError(t, err)
	modifyRequest := <-requests

	writeTestMessage(t, peer, testLDAPMessage(t, searchRequest.MessageID, testSearchEntry, []byte("one")))
	writeTestMessage(t, peer, testLDAPMessage(t, searchRequest.MessageID, testSearchEntry, []byte("two")))
	writeTestMessage(t, peer, testLDAPMessage(t, modifyRequest.MessageID, testModifyDone, nil))
	writeTestMessage(t, peer, testLDAPMessage(t, searchRequest.MessageID, testSearchDone, nil))

	response, err := modify.Next(context.Background())
	require.NoError(t, err)
	require.Equal(t, testModifyDone, response.ProtocolID)
	_, err = search.Next(context.Background())
	require.ErrorIs(t, err, ErrResourceLimit)
}

func TestUnexpectedMessageIDRetiresConnection(t *testing.T) {
	conn, peer := newPipeConnection(t, ConnectionOptions{}, MaxMessageID)
	writeTestMessage(t, peer, testLDAPMessage(t, 99, testSearchDone, nil))
	select {
	case <-conn.Done():
	case <-time.After(time.Second):
		require.Fail(t, "connection did not retire")
	}
	var protocolErr *ProtocolError
	require.ErrorAs(t, conn.Err(), &protocolErr)
	assert.Equal(t, ProtocolUnexpectedMessageID, protocolErr.Kind)
}

func TestUnexpectedApplicationTagRetiresConnection(t *testing.T) {
	conn, peer := newPipeConnection(t, ConnectionOptions{}, MaxMessageID)
	framer := newTestFramer(t, peer)
	requestReady := make(chan Response, 1)
	go func() { requestReady <- readTestMessage(t, framer) }()
	stream, err := conn.Do(context.Background(), newTestOperation(t, testModifyRequest, ResponseSpec{Complete: []ber.Identifier{testModifyDone}}, CancelDrain))
	require.NoError(t, err)
	request := <-requestReady
	writeTestMessage(t, peer, testLDAPMessage(t, request.MessageID, testSearchEntry, nil))
	_, err = stream.Next(context.Background())
	var protocolErr *ProtocolError
	require.ErrorAs(t, err, &protocolErr)
	assert.Equal(t, ProtocolUnexpectedIdentifier, protocolErr.Kind)
}

func TestPeerClosureMarksWrittenOperationAmbiguous(t *testing.T) {
	conn, peer := newPipeConnection(t, ConnectionOptions{}, MaxMessageID)
	framer := newTestFramer(t, peer)
	requestReady := make(chan Response, 1)
	go func() { requestReady <- readTestMessage(t, framer) }()
	stream, err := conn.Do(context.Background(), newTestOperation(t, testModifyRequest, ResponseSpec{Complete: []ber.Identifier{testModifyDone}}, CancelDrain))
	require.NoError(t, err)
	<-requestReady
	_ = peer.Close()
	_, err = stream.Next(context.Background())
	var transportErr *TransportError
	require.ErrorAs(t, err, &transportErr)
	assert.Equal(t, StagePeerClose, transportErr.Stage)
	require.ErrorIs(t, err, ErrAmbiguousOutcome)
}

func TestMalformedFrameAndEnvelopeRetireConnection(t *testing.T) {
	for _, test := range []struct {
		name string
		wire []byte
		kind ProtocolErrorKind
	}{
		{name: "frame", wire: []byte{0x30, 0x80}, kind: ProtocolFraming},
		{name: "envelope", wire: []byte{0x30, 0x00}, kind: ProtocolEnvelope},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn, peer := newPipeConnection(t, ConnectionOptions{}, MaxMessageID)
			writeTestMessage(t, peer, test.wire)
			select {
			case <-conn.Done():
			case <-time.After(time.Second):
				require.Fail(t, "connection did not retire")
			}
			var protocolErr *ProtocolError
			require.ErrorAs(t, conn.Err(), &protocolErr)
			assert.Equal(t, test.kind, protocolErr.Kind)
		})
	}
}

func TestUnsolicitedResponseAndNoticeOfDisconnection(t *testing.T) {
	t.Run("ordinary", func(t *testing.T) {
		conn, peer := newPipeConnection(t, ConnectionOptions{}, MaxMessageID)
		contents := ber.Enumerated(0).Encode()
		contents = ber.OctetString([]byte(nil)).AppendTo(contents)
		contents = ber.OctetString([]byte(nil)).AppendTo(contents)
		writeTestMessage(t, peer, testLDAPMessage(t, 0, rfc4511.ExtendedResponseIdentifier(), contents))
		response, err := conn.NextUnsolicited(context.Background())
		require.NoError(t, err)
		assert.Zero(t, response.MessageID)
	})

	t.Run("notice", func(t *testing.T) {
		conn, peer := newPipeConnection(t, ConnectionOptions{}, MaxMessageID)
		contents := ber.Enumerated(52).Encode()
		contents = ber.OctetString([]byte(nil)).AppendTo(contents)
		contents = ber.OctetString("server shutdown").AppendTo(contents)
		contents = ber.Primitive(ber.Identifier{Class: ber.ClassContextSpecific, Number: 10}, []byte(noticeOfDisconnectionOID)).AppendTo(contents)
		writeTestMessage(t, peer, testLDAPMessage(t, 0, rfc4511.ExtendedResponseIdentifier(), contents))
		_, err := conn.NextUnsolicited(context.Background())
		var notice *NoticeError
		require.ErrorAs(t, err, &notice)
		assert.Equal(t, int64(52), notice.ResultCode)
		assert.Equal(t, []byte("server shutdown"), notice.Diagnostic)
		require.ErrorIs(t, err, ErrNoticeOfDisconnection)
	})
}

func TestCloseSendsUnbindAndIsIdempotent(t *testing.T) {
	conn, peer := newPipeConnection(t, ConnectionOptions{}, MaxMessageID)
	framer := newTestFramer(t, peer)
	closed := make(chan error, 1)
	go func() { closed <- conn.Close() }()
	request := readTestMessage(t, framer)
	require.Equal(t, rfc4511.UnbindRequestIdentifier(), request.ProtocolID)
	require.NoError(t, <-closed)
	require.ErrorIs(t, conn.Err(), ErrClosed)
	assert.NoError(t, conn.Close())
}

func TestWriteFailureOutcomeAtEveryOffset(t *testing.T) {
	op := newTestOperation(t, testModifyRequest, ResponseSpec{NoResponse: true}, CancelNone)
	encoded, err := encodeLDAPRequest(1, op.Untyped(), ber.DefaultLimits())
	require.NoError(t, err)
	for failAt := range len(encoded) {
		t.Run("offset", func(t *testing.T) {
			transport := newScriptedConn(failAt, 3)
			options, err := (ConnectionOptions{}).normalized()
			require.NoError(t, err)
			conn, err := newConn(transport, Endpoint{ID: "write", Address: "scripted", Transport: TransportPlaintext}, options, MaxMessageID)
			require.NoError(t, err)
			_, err = conn.Do(context.Background(), op)
			if failAt == 0 {
				require.ErrorIs(t, err, ErrDefinitelyUnsent)
				require.NotErrorIs(t, err, ErrAmbiguousOutcome)
			} else {
				require.ErrorIs(t, err, ErrAmbiguousOutcome)
			}
		})
	}
}

func TestSuccessfulShortWritesProduceOneCompleteEnvelope(t *testing.T) {
	transport := newScriptedConn(-1, 2)
	options, err := (ConnectionOptions{}).normalized()
	require.NoError(t, err)
	conn, err := newConn(transport, Endpoint{ID: "write", Address: "scripted", Transport: TransportPlaintext}, options, MaxMessageID)
	require.NoError(t, err)
	defer conn.retire(ErrClosed)
	op := newTestOperation(t, testModifyRequest, ResponseSpec{NoResponse: true}, CancelNone)
	stream, err := conn.Do(context.Background(), op)
	require.NoError(t, err)
	_, err = stream.Next(context.Background())
	require.ErrorIs(t, err, io.EOF)
	transport.mu.Lock()
	written := bytes.Clone(transport.written.Bytes())
	transport.mu.Unlock()
	_, err = ParseResponse(written, ber.DefaultLimits())
	assert.NoError(t, err)
}

func TestCancellationBeforeAndDuringWrite(t *testing.T) {
	t.Run("before write", func(t *testing.T) {
		conn, _ := newPipeConnection(t, ConnectionOptions{}, MaxMessageID)
		<-conn.writeToken
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := conn.Do(ctx, newTestOperation(t, testModifyRequest, ResponseSpec{NoResponse: true}, CancelNone))
		conn.releaseWriter()
		require.ErrorIs(t, err, context.Canceled)
		require.ErrorIs(t, err, ErrDefinitelyUnsent)
		conn.mu.Lock()
		pending := len(conn.pending)
		conn.mu.Unlock()
		assert.Zero(t, pending)
	})

	t.Run("during write", func(t *testing.T) {
		transport := newBlockingWriteConn()
		options, err := (ConnectionOptions{}).normalized()
		require.NoError(t, err)
		conn, err := newConn(transport, Endpoint{ID: "write", Address: "blocking", Transport: TransportPlaintext}, options, MaxMessageID)
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		op := newTestOperation(t, testModifyRequest, ResponseSpec{NoResponse: true}, CancelNone)
		go func() {
			_, err := conn.Do(ctx, op)
			result <- err
		}()
		<-transport.writeStarted
		cancel()
		select {
		case err := <-result:
			require.ErrorIs(t, err, context.Canceled)
			require.ErrorIs(t, err, ErrAmbiguousOutcome)
		case <-time.After(time.Second):
			require.Fail(t, "in-progress write did not unblock on cancellation")
		}
	})
}

type scriptedConn struct {
	mu       sync.Mutex
	written  bytes.Buffer
	failAt   int
	maxChunk int
	closed   chan struct{}
	once     sync.Once
}

func newScriptedConn(failAt, maxChunk int) *scriptedConn {
	return &scriptedConn{failAt: failAt, maxChunk: maxChunk, closed: make(chan struct{})}
}

func (c *scriptedConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *scriptedConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failAt >= 0 && c.written.Len() >= c.failAt {
		return 0, errors.New("scripted write failure")
	}
	n := min(len(p), c.maxChunk)
	if c.failAt >= 0 {
		n = min(n, c.failAt-c.written.Len())
	}
	_, _ = c.written.Write(p[:n])
	if c.failAt >= 0 && c.written.Len() == c.failAt {
		return n, errors.New("scripted write failure")
	}
	return n, nil
}

func (c *scriptedConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}
func (*scriptedConn) LocalAddr() net.Addr              { return testAddr("local") }
func (*scriptedConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (*scriptedConn) SetDeadline(time.Time) error      { return nil }
func (*scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (*scriptedConn) SetWriteDeadline(time.Time) error { return nil }

type testAddr string

func (a testAddr) Network() string { return "test" }
func (a testAddr) String() string  { return string(a) }

type blockingWriteConn struct {
	closed       chan struct{}
	writeStarted chan struct{}
	closeOnce    sync.Once
	writeOnce    sync.Once
}

func newBlockingWriteConn() *blockingWriteConn {
	return &blockingWriteConn{closed: make(chan struct{}), writeStarted: make(chan struct{})}
}

func (c *blockingWriteConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}
func (c *blockingWriteConn) Write([]byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writeStarted) })
	<-c.closed
	return 0, net.ErrClosed
}
func (c *blockingWriteConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
func (*blockingWriteConn) LocalAddr() net.Addr              { return testAddr("local") }
func (*blockingWriteConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (*blockingWriteConn) SetDeadline(time.Time) error      { return nil }
func (*blockingWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (*blockingWriteConn) SetWriteDeadline(time.Time) error { return nil }
