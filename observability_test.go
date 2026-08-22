package arden

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wyattanderson/arden/ber"
)

type recordedTrace struct {
	mu      sync.Mutex
	start   TraceStart
	events  []TraceEvent
	end     TraceEnd
	ended   chan struct{}
	blockAt TraceEventKind
	blocked chan struct{}
	release chan struct{}
	panicAt TraceEventKind
}

func (t *recordedTrace) Start(ctx context.Context, start TraceStart) (context.Context, Trace) {
	t.mu.Lock()
	t.start = start
	t.mu.Unlock()
	return ctx, t
}

func (t *recordedTrace) Event(event TraceEvent) {
	if event.Kind == t.panicAt {
		panic("trace event panic")
	}
	if event.Kind == t.blockAt {
		close(t.blocked)
		<-t.release
	}
	t.mu.Lock()
	t.events = append(t.events, event)
	t.mu.Unlock()
}

func (t *recordedTrace) End(end TraceEnd) {
	t.mu.Lock()
	t.end = end
	t.mu.Unlock()
	close(t.ended)
}

type capturedRecord struct {
	message string
	attrs   map[string]string
}

type captureHandler struct {
	mu      *sync.Mutex
	records *[]capturedRecord
	attrs   []slog.Attr
}

func newCaptureLogger() (*slog.Logger, func() []capturedRecord) {
	var mu sync.Mutex
	var records []capturedRecord
	handler := &captureHandler{mu: &mu, records: &records}
	return slog.New(handler), func() []capturedRecord {
		mu.Lock()
		defer mu.Unlock()
		return append([]capturedRecord(nil), records...)
	}
}

func (*captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, record slog.Record) error {
	attrs := make(map[string]string)
	for _, attr := range h.attrs {
		attrs[attr.Key] = attr.Value.String()
	}
	record.Attrs(func(attr slog.Attr) bool {
		attrs[attr.Key] = attr.Value.String()
		return true
	})
	h.mu.Lock()
	*h.records = append(*h.records, capturedRecord{message: record.Message, attrs: attrs})
	h.mu.Unlock()
	return nil
}

func (h *captureHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := *h
	clone.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	return &clone
}

func (h *captureHandler) WithGroup(string) slog.Handler { return h }

func newObservedPipeConnection(t *testing.T, logger *slog.Logger, tracer Tracer, traceMessageIDs bool) (*Conn, net.Conn) {
	t.Helper()
	options, err := (ConnectionOptions{}).normalized()
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	conn, err := newObservedConnWithState(client, Endpoint{
		ID: "trace-endpoint", Address: "ldap.trace.test:389", Transport: TransportPlaintext,
	}, options, MaxMessageID, stateReady, logger, tracer, traceMessageIDs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn.retire(ErrClosed)
		_ = server.Close()
	})
	return conn, server
}

func TestTraceOrderingCountsAndSlowHookIsolation(t *testing.T) {
	trace := &recordedTrace{
		ended:   make(chan struct{}),
		blockAt: TraceFirstResponse,
		blocked: make(chan struct{}),
		release: make(chan struct{}),
	}
	conn, peer := newObservedPipeConnection(t, nil, trace, false)
	framer := newTestFramer(t, peer)
	go func() {
		request := readTestMessage(t, framer)
		writeTestMessage(t, peer, testLDAPMessage(t, request.MessageID, testModifyDone, []byte("directory-secret")))
	}()

	operation := newTestOperation(t, testModifyRequest, ResponseSpec{Complete: []ber.Identifier{testModifyDone}}, CancelDrain)
	operation.Metadata.Label = "ldap.modify"
	stream, err := conn.Do(context.Background(), operation)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-trace.blocked:
	case <-time.After(time.Second):
		t.Fatal("first-response hook did not run")
	}
	responseReady := make(chan error, 1)
	go func() {
		_, err := stream.Next(context.Background())
		responseReady <- err
	}()
	select {
	case err := <-responseReady:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("slow trace hook blocked socket response delivery")
	}
	close(trace.release)
	select {
	case <-trace.ended:
	case <-time.After(time.Second):
		t.Fatal("trace did not end")
	}

	trace.mu.Lock()
	defer trace.mu.Unlock()
	if trace.start.Endpoint != "trace-endpoint" || trace.start.EndpointAddress != "ldap.trace.test:389" || trace.start.Connection == 0 {
		t.Fatalf("trace start identity = %#v", trace.start)
	}
	if trace.start.ApplicationTag != testModifyRequest || trace.start.RequestID != testModifyRequest || trace.start.MessageID != 0 {
		t.Fatalf("trace start request metadata = %#v", trace.start)
	}
	wantKinds := []TraceEventKind{TraceQueued, TraceWritten, TraceFirstResponse}
	if len(trace.events) != len(wantKinds) {
		t.Fatalf("trace events = %#v", trace.events)
	}
	for i, want := range wantKinds {
		if trace.events[i].Kind != want {
			t.Fatalf("trace event %d = %v, want %v", i, trace.events[i].Kind, want)
		}
	}
	if trace.end.RequestBytes == 0 || trace.end.ResponseBytes != uint64(len(responseBytes(t, 1, []byte("directory-secret")))) || trace.end.Responses != 1 || trace.end.ErrorClass != "none" {
		t.Fatalf("trace end = %#v", trace.end)
	}
}

func TestTracePanicDoesNotRetireConnection(t *testing.T) {
	trace := &recordedTrace{ended: make(chan struct{}), panicAt: TraceWritten}
	conn, peer := newObservedPipeConnection(t, nil, trace, false)
	framer := newTestFramer(t, peer)
	go func() {
		request := readTestMessage(t, framer)
		writeTestMessage(t, peer, testLDAPMessage(t, request.MessageID, testModifyDone, nil))
	}()
	stream, err := conn.Do(context.Background(), newTestOperation(t, testModifyRequest, ResponseSpec{Complete: []ber.Identifier{testModifyDone}}, CancelDrain))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-trace.ended:
	case <-time.After(time.Second):
		t.Fatal("trace did not survive event panic")
	}
	select {
	case <-conn.Done():
		t.Fatalf("trace panic retired connection: %v", conn.Err())
	default:
	}
}

func TestDebugLoggingUsesOnlySafeFieldsAndMessageIDIsOptIn(t *testing.T) {
	logger, records := newCaptureLogger()
	trace := &recordedTrace{ended: make(chan struct{})}
	conn, peer := newObservedPipeConnection(t, logger, trace, false)
	framer := newTestFramer(t, peer)
	secret := []byte("credential-and-directory-secret")
	go func() {
		request := readTestMessage(t, framer)
		writeTestMessage(t, peer, testLDAPMessage(t, request.MessageID, testModifyDone, secret))
	}()
	operation := newTestOperation(t, testModifyRequest, ResponseSpec{Complete: []ber.Identifier{testModifyDone}}, CancelDrain)
	operation.Metadata.Label = "safe.operation"
	stream, err := conn.Do(context.Background(), operation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-trace.ended
	eventuallyRecords(t, records, func(records []capturedRecord) bool {
		for _, record := range records {
			if record.message == "ldap operation completed" {
				return true
			}
		}
		return false
	})
	for _, record := range records() {
		if _, exists := record.attrs["message_id"]; exists {
			t.Fatalf("message ID logged without opt-in: %#v", record)
		}
		if strings.Contains(record.message, string(secret)) {
			t.Fatalf("secret appeared in log message: %#v", record)
		}
		for key, value := range record.attrs {
			if strings.Contains(value, string(secret)) {
				t.Fatalf("secret appeared in log field %q", key)
			}
		}
	}
	completed := records()[len(records())-1]
	if completed.attrs["endpoint_id"] != "trace-endpoint" || completed.attrs["endpoint_address"] != "ldap.trace.test:389" || completed.attrs["operation"] != "safe.operation" {
		t.Fatalf("safe endpoint/operation fields = %#v", completed.attrs)
	}

	optInTrace := &recordedTrace{ended: make(chan struct{})}
	optIn, optInPeer := newObservedPipeConnection(t, nil, optInTrace, true)
	optInFramer := newTestFramer(t, optInPeer)
	go func() {
		request := readTestMessage(t, optInFramer)
		writeTestMessage(t, optInPeer, testLDAPMessage(t, request.MessageID, testModifyDone, nil))
	}()
	optInStream, err := optIn.Do(context.Background(), newTestOperation(t, testModifyRequest, ResponseSpec{Complete: []ber.Identifier{testModifyDone}}, CancelDrain))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := optInStream.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-optInTrace.ended
	optInTrace.mu.Lock()
	defer optInTrace.mu.Unlock()
	if optInTrace.start.MessageID == 0 {
		t.Fatal("message ID missing after explicit opt-in")
	}
}

func responseBytes(t *testing.T, messageID MessageID, value []byte) []byte {
	t.Helper()
	return testLDAPMessage(t, messageID, testModifyDone, value)
}

func eventuallyRecords(t *testing.T, records func() []capturedRecord, condition func([]capturedRecord) bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !condition(records()) {
		if time.Now().After(deadline) {
			t.Fatal("log record condition was not satisfied")
		}
		time.Sleep(time.Millisecond)
	}
}
