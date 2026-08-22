package arden

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/wyattanderson/arden/ber"
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

func (p testProtocol) ProtocolIdentifier() ber.Identifier { return p.id }
func (p testProtocol) AppendBER(dst []byte) ([]byte, error) {
	return append(dst, p.encoded...), nil
}

func newTestOperation(t *testing.T, request ber.Identifier, pattern ResponseSpec, mode CancellationMode) Operation {
	t.Helper()
	encoded, err := ber.AppendElement(nil, request, nil)
	if err != nil {
		t.Fatal(err)
	}
	responses, err := NewResponsePattern(pattern)
	if err != nil {
		t.Fatal(err)
	}
	return Operation{
		Protocol:     testProtocol{id: request, encoded: encoded},
		Responses:    responses,
		Cancellation: mode,
	}
}

func newPipeConnection(t *testing.T, options ConnectionOptions, maxID MessageID) (*Conn, net.Conn) {
	t.Helper()
	normalized, err := options.normalized()
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	conn, err := newConn(client, Endpoint{ID: "test", Address: "pipe", Transport: TransportPlaintext}, normalized, maxID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn.retire(ErrClosed)
		_ = server.Close()
	})
	return conn, server
}

func newTestFramer(t *testing.T, conn net.Conn) *ber.Framer {
	t.Helper()
	framer, err := ber.NewFramer(conn, ber.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return framer
}

func readTestMessage(t *testing.T, framer *ber.Framer) Response {
	t.Helper()
	message, err := framer.Next()
	if err != nil {
		t.Errorf("read LDAP message: %v", err)
		return Response{}
	}
	response, err := ParseResponse(message, ber.DefaultLimits())
	if err != nil {
		t.Errorf("parse LDAP message: %v", err)
		return Response{}
	}
	return response
}

func testLDAPMessage(t *testing.T, id MessageID, protocolID ber.Identifier, value []byte) []byte {
	t.Helper()
	protocol, err := ber.AppendElement(nil, protocolID, value)
	if err != nil {
		t.Errorf("encode protocol: %v", err)
		return nil
	}
	message, err := encodeInternalRequest(id, protocol)
	if err != nil {
		t.Errorf("encode LDAP message: %v", err)
		return nil
	}
	return message
}

func writeTestMessage(t *testing.T, conn net.Conn, message []byte) {
	t.Helper()
	if _, err := conn.Write(message); err != nil {
		t.Errorf("write LDAP message: %v", err)
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
	if err != nil {
		t.Fatal(err)
	}
	modify, err := conn.Do(context.Background(), newTestOperation(t, testModifyRequest, ResponseSpec{
		Complete: []ber.Identifier{testModifyDone},
	}, CancelDrain))
	if err != nil {
		t.Fatal(err)
	}

	searchEntry, err := search.Next(context.Background())
	if err != nil || searchEntry.ProtocolID != testSearchEntry {
		t.Fatalf("search entry = %#v, %v", searchEntry.Header(), err)
	}
	modifyDone, err := modify.Next(context.Background())
	if err != nil || modifyDone.ProtocolID != testModifyDone {
		t.Fatalf("modify result = %#v, %v", modifyDone.Header(), err)
	}
	searchDone, err := search.Next(context.Background())
	if err != nil || searchDone.ProtocolID != testSearchDone {
		t.Fatalf("search done = %#v, %v", searchDone.Header(), err)
	}
	if _, err := search.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("search terminal error = %v, want EOF", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
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
		wg.Add(1)
		go func() {
			defer wg.Done()
			stream, err := conn.Do(context.Background(), op)
			if err == nil {
				_, err = stream.Next(context.Background())
				if errors.Is(err, io.EOF) {
					err = nil
				}
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	seen := make(map[MessageID]bool)
	for range operations {
		id := <-ids
		if id == 0 || seen[id] {
			t.Fatalf("invalid or duplicate concurrent message ID %d", id)
		}
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
		if err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Next(context.Background()); !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
	}
	if got := []MessageID{<-ids, <-ids, <-ids}; !slices.Equal(got, []MessageID{1, 2, 1}) {
		t.Fatalf("message IDs = %v, want [1 2 1]", got)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	firstRequest := <-firstRequestReady
	cancel()
	if _, err := first.Next(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled stream error = %v", err)
	}

	secondResult := make(chan ResponseStream, 1)
	secondErr := make(chan error, 1)
	go func() {
		stream, err := conn.Do(context.Background(), op)
		secondResult <- stream
		secondErr <- err
	}()
	select {
	case err := <-secondErr:
		t.Fatalf("second operation completed before drain with %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	writeTestMessage(t, peer, testLDAPMessage(t, firstRequest.MessageID, testSearchEntry, nil))
	writeTestMessage(t, peer, testLDAPMessage(t, firstRequest.MessageID, testSearchDone, nil))
	secondRequest := readTestMessage(t, framer)
	if secondRequest.MessageID != firstRequest.MessageID {
		t.Fatalf("reused message ID = %d, want %d", secondRequest.MessageID, firstRequest.MessageID)
	}
	writeTestMessage(t, peer, testLDAPMessage(t, secondRequest.MessageID, testSearchDone, nil))
	second := <-secondResult
	if err := <-secondErr; err != nil {
		t.Fatal(err)
	}
	response, err := second.Next(context.Background())
	if err != nil || response.ProtocolID != testSearchDone {
		t.Fatalf("second response = %#v, %v", response.Header(), err)
	}
}

func TestTerminalResponseWinsCancellationRace(t *testing.T) {
	conn, peer := newPipeConnection(t, ConnectionOptions{}, MaxMessageID)
	framer := newTestFramer(t, peer)
	requestReady := make(chan Response, 1)
	go func() { requestReady <- readTestMessage(t, framer) }()
	ctx, cancel := context.WithCancel(context.Background())
	stream, err := conn.Do(ctx, newTestOperation(t, testModifyRequest, ResponseSpec{Complete: []ber.Identifier{testModifyDone}}, CancelDrain))
	if err != nil {
		t.Fatal(err)
	}
	request := <-requestReady
	writeTestMessage(t, peer, testLDAPMessage(t, request.MessageID, testModifyDone, nil))
	concrete := stream.(*responseStream)
	select {
	case <-concrete.pending.ready:
	case <-time.After(time.Second):
		t.Fatal("terminal response was not routed")
	}
	cancel()
	response, err := stream.Next(context.Background())
	if err != nil || response.ProtocolID != testModifyDone {
		t.Fatalf("terminal/cancellation race = %#v, %v", response.Header(), err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	target := <-targetReady
	cancel()
	if _, err := stream.Next(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled stream error = %v", err)
	}

	abandon := readTestMessage(t, framer)
	if abandon.ProtocolID != abandonRequestIdentifier {
		t.Fatalf("cancellation protocol = %s, want Abandon", abandon.ProtocolID)
	}
	r, err := ber.NewReader(abandon.Protocol, ber.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	abandonedID, err := r.IntegerWithIdentifier(abandonRequestIdentifier)
	if err != nil || MessageID(abandonedID) != target.MessageID {
		t.Fatalf("Abandon target = %d, %v; want %d", abandonedID, err, target.MessageID)
	}

	writeTestMessage(t, peer, testLDAPMessage(t, target.MessageID, testSearchEntry, nil))
	writeTestMessage(t, peer, testLDAPMessage(t, target.MessageID, testSearchDone, nil))
	select {
	case <-conn.Done():
		t.Fatalf("tombstoned responses retired connection: %v", conn.Err())
	case <-time.After(25 * time.Millisecond):
	}
	conn.mu.Lock()
	_, tombstoned := conn.tombstones[target.MessageID]
	conn.mu.Unlock()
	if !tombstoned {
		t.Fatal("Abandon target was reused after a terminal response")
	}
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
	if err != nil {
		t.Fatal(err)
	}
	searchRequest := <-requests
	modify, err := conn.Do(context.Background(), modifyOp)
	if err != nil {
		t.Fatal(err)
	}
	modifyRequest := <-requests

	writeTestMessage(t, peer, testLDAPMessage(t, searchRequest.MessageID, testSearchEntry, []byte("one")))
	writeTestMessage(t, peer, testLDAPMessage(t, searchRequest.MessageID, testSearchEntry, []byte("two")))
	writeTestMessage(t, peer, testLDAPMessage(t, modifyRequest.MessageID, testModifyDone, nil))
	writeTestMessage(t, peer, testLDAPMessage(t, searchRequest.MessageID, testSearchDone, nil))

	response, err := modify.Next(context.Background())
	if err != nil || response.ProtocolID != testModifyDone {
		t.Fatalf("unrelated operation = %#v, %v", response.Header(), err)
	}
	if _, err := search.Next(context.Background()); !errors.Is(err, ErrResourceLimit) {
		t.Fatalf("slow consumer error = %v, want resource limit", err)
	}
}

func TestUnexpectedMessageIDRetiresConnection(t *testing.T) {
	conn, peer := newPipeConnection(t, ConnectionOptions{}, MaxMessageID)
	writeTestMessage(t, peer, testLDAPMessage(t, 99, testSearchDone, nil))
	select {
	case <-conn.Done():
	case <-time.After(time.Second):
		t.Fatal("connection did not retire")
	}
	var protocolErr *ProtocolError
	if !errors.As(conn.Err(), &protocolErr) || protocolErr.Kind != ProtocolUnexpectedMessageID {
		t.Fatalf("connection error = %v", conn.Err())
	}
}

func TestUnexpectedApplicationTagRetiresConnection(t *testing.T) {
	conn, peer := newPipeConnection(t, ConnectionOptions{}, MaxMessageID)
	framer := newTestFramer(t, peer)
	requestReady := make(chan Response, 1)
	go func() { requestReady <- readTestMessage(t, framer) }()
	stream, err := conn.Do(context.Background(), newTestOperation(t, testModifyRequest, ResponseSpec{Complete: []ber.Identifier{testModifyDone}}, CancelDrain))
	if err != nil {
		t.Fatal(err)
	}
	request := <-requestReady
	writeTestMessage(t, peer, testLDAPMessage(t, request.MessageID, testSearchEntry, nil))
	_, err = stream.Next(context.Background())
	var protocolErr *ProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.Kind != ProtocolUnexpectedIdentifier {
		t.Fatalf("stream error = %v", err)
	}
}

func TestPeerClosureMarksWrittenOperationAmbiguous(t *testing.T) {
	conn, peer := newPipeConnection(t, ConnectionOptions{}, MaxMessageID)
	framer := newTestFramer(t, peer)
	requestReady := make(chan Response, 1)
	go func() { requestReady <- readTestMessage(t, framer) }()
	stream, err := conn.Do(context.Background(), newTestOperation(t, testModifyRequest, ResponseSpec{Complete: []ber.Identifier{testModifyDone}}, CancelDrain))
	if err != nil {
		t.Fatal(err)
	}
	<-requestReady
	_ = peer.Close()
	_, err = stream.Next(context.Background())
	var transportErr *TransportError
	if !errors.As(err, &transportErr) || transportErr.Stage != StagePeerClose || !errors.Is(err, ErrAmbiguousOutcome) {
		t.Fatalf("peer closure error = %v", err)
	}
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
				t.Fatal("connection did not retire")
			}
			var protocolErr *ProtocolError
			if !errors.As(conn.Err(), &protocolErr) || protocolErr.Kind != test.kind {
				t.Fatalf("connection error = %v", conn.Err())
			}
		})
	}
}

func TestUnsolicitedResponseAndNoticeOfDisconnection(t *testing.T) {
	t.Run("ordinary", func(t *testing.T) {
		conn, peer := newPipeConnection(t, ConnectionOptions{}, MaxMessageID)
		contents, _ := ber.AppendEnumerated(nil, 0)
		contents, _ = ber.AppendOctetString(contents, nil)
		contents, _ = ber.AppendOctetString(contents, nil)
		writeTestMessage(t, peer, testLDAPMessage(t, 0, extendedResponseIdentifier, contents))
		response, err := conn.NextUnsolicited(context.Background())
		if err != nil || response.MessageID != 0 {
			t.Fatalf("unsolicited response = %#v, %v", response.Header(), err)
		}
	})

	t.Run("notice", func(t *testing.T) {
		conn, peer := newPipeConnection(t, ConnectionOptions{}, MaxMessageID)
		contents, _ := ber.AppendEnumerated(nil, 52)
		contents, _ = ber.AppendOctetString(contents, nil)
		contents, _ = ber.AppendOctetString(contents, []byte("server shutdown"))
		contents, _ = ber.AppendPrimitive(contents, responseNameIdentifier, noticeOfDisconnectionOID)
		writeTestMessage(t, peer, testLDAPMessage(t, 0, extendedResponseIdentifier, contents))
		_, err := conn.NextUnsolicited(context.Background())
		var notice *NoticeError
		if !errors.As(err, &notice) || notice.ResultCode != 52 || !bytes.Equal(notice.Diagnostic, []byte("server shutdown")) {
			t.Fatalf("notice error = %#v", err)
		}
		if !errors.Is(err, ErrNoticeOfDisconnection) {
			t.Fatalf("notice identity = %v", err)
		}
	})
}

func TestCloseSendsUnbindAndIsIdempotent(t *testing.T) {
	conn, peer := newPipeConnection(t, ConnectionOptions{}, MaxMessageID)
	framer := newTestFramer(t, peer)
	closed := make(chan error, 1)
	go func() { closed <- conn.Close() }()
	request := readTestMessage(t, framer)
	if request.ProtocolID != unbindRequestIdentifier {
		t.Fatalf("close protocol = %s, want Unbind", request.ProtocolID)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if !errors.Is(conn.Err(), ErrClosed) {
		t.Fatalf("close error = %v", conn.Err())
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("second close = %v", err)
	}
}

func TestWriteFailureOutcomeAtEveryOffset(t *testing.T) {
	op := newTestOperation(t, testModifyRequest, ResponseSpec{NoResponse: true}, CancelNone)
	encoded, err := encodeLDAPRequest(1, op, ber.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for failAt := range len(encoded) {
		t.Run("offset", func(t *testing.T) {
			transport := newScriptedConn(failAt, 3)
			options, err := (ConnectionOptions{}).normalized()
			if err != nil {
				t.Fatal(err)
			}
			conn, err := newConn(transport, Endpoint{ID: "write", Address: "scripted", Transport: TransportPlaintext}, options, MaxMessageID)
			if err != nil {
				t.Fatal(err)
			}
			_, err = conn.Do(context.Background(), op)
			if failAt == 0 {
				if !errors.Is(err, ErrDefinitelyUnsent) || errors.Is(err, ErrAmbiguousOutcome) {
					t.Fatalf("offset zero error = %v", err)
				}
			} else if !errors.Is(err, ErrAmbiguousOutcome) {
				t.Fatalf("offset %d error = %v, want ambiguous", failAt, err)
			}
		})
	}
}

func TestSuccessfulShortWritesProduceOneCompleteEnvelope(t *testing.T) {
	transport := newScriptedConn(-1, 2)
	options, err := (ConnectionOptions{}).normalized()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := newConn(transport, Endpoint{ID: "write", Address: "scripted", Transport: TransportPlaintext}, options, MaxMessageID)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.retire(ErrClosed)
	op := newTestOperation(t, testModifyRequest, ResponseSpec{NoResponse: true}, CancelNone)
	stream, err := conn.Do(context.Background(), op)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	transport.mu.Lock()
	written := bytes.Clone(transport.written.Bytes())
	transport.mu.Unlock()
	if _, err := ParseResponse(written, ber.DefaultLimits()); err != nil {
		t.Fatalf("short writes produced malformed envelope: %x: %v", written, err)
	}
}

func TestCancellationBeforeAndDuringWrite(t *testing.T) {
	t.Run("before write", func(t *testing.T) {
		conn, _ := newPipeConnection(t, ConnectionOptions{}, MaxMessageID)
		<-conn.writeToken
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := conn.Do(ctx, newTestOperation(t, testModifyRequest, ResponseSpec{NoResponse: true}, CancelNone))
		conn.releaseWriter()
		if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrDefinitelyUnsent) {
			t.Fatalf("pre-write cancellation = %v", err)
		}
		conn.mu.Lock()
		pending := len(conn.pending)
		conn.mu.Unlock()
		if pending != 0 {
			t.Fatalf("pre-write cancellation left %d pending operations", pending)
		}
	})

	t.Run("during write", func(t *testing.T) {
		transport := newBlockingWriteConn()
		options, err := (ConnectionOptions{}).normalized()
		if err != nil {
			t.Fatal(err)
		}
		conn, err := newConn(transport, Endpoint{ID: "write", Address: "blocking", Transport: TransportPlaintext}, options, MaxMessageID)
		if err != nil {
			t.Fatal(err)
		}
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
			if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrAmbiguousOutcome) {
				t.Fatalf("in-write cancellation = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("in-progress write did not unblock on cancellation")
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
