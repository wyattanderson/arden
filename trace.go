package arden

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/wyattanderson/arden/ber"
)

// Tracer starts an operation trace. Connection implementations invoke hooks
// outside the socket reader and isolate the transport from hook panics.
type Tracer interface {
	Start(context.Context, TraceStart) (context.Context, Trace)
}

// Trace receives safe lifecycle metadata only. It must not receive BER payloads
// or directory data.
type Trace interface {
	Event(TraceEvent)
	End(TraceEnd)
}

// TraceStart contains safe metadata captured when an operation begins.
type TraceStart struct {
	Endpoint        EndpointID
	EndpointAddress string
	Connection      uint64
	Label           string
	ApplicationTag  ber.Identifier
	// RequestID is retained for compatibility. It contains the request's BER
	// application identifier, not an LDAP message ID.
	RequestID ber.Identifier
	// MessageID is zero unless Dialer.TraceMessageIDs is explicitly enabled.
	MessageID MessageID
}

// TraceEventKind identifies an intermediate operation lifecycle event.
type TraceEventKind uint8

// Operation lifecycle events reported to a Trace.
const (
	TraceQueued TraceEventKind = iota + 1
	TraceWritten
	TraceFirstResponse
	TraceCanceled
	TraceConnectionRetired
)

// TraceEvent contains safe metadata for an intermediate lifecycle event.
type TraceEvent struct {
	Kind      TraceEventKind
	At        time.Time
	Bytes     uint64
	Responses uint64
}

// TraceEnd contains safe metadata captured when an operation finishes.
type TraceEnd struct {
	At            time.Time
	RequestBytes  uint64
	ResponseBytes uint64
	Responses     uint64
	ErrorClass    string
}

type traceDispatchKind uint8

const (
	traceDispatchEvent traceDispatchKind = iota + 1
	traceDispatchEnd
)

type traceDispatch struct {
	kind  traceDispatchKind
	event TraceEvent
	end   TraceEnd
}

// operationObserver serializes hook calls away from the socket reader. An
// operation has at most a small, fixed number of lifecycle events, so the
// buffer cannot be exhausted by response volume.
type operationObserver struct {
	trace  Trace
	logger *slog.Logger
	start  TraceStart
	began  time.Time
	ctx    context.Context
	queue  chan traceDispatch
	once   sync.Once
}

func startOperationObserver(ctx context.Context, tracer Tracer, logger *slog.Logger, start TraceStart, began time.Time) (context.Context, *operationObserver) {
	traceCtx := ctx
	var trace Trace
	if tracer != nil {
		func() {
			defer func() { _ = recover() }()
			returned, started := tracer.Start(ctx, start)
			if returned != nil {
				traceCtx = returned
			}
			trace = started
		}()
	}
	if trace == nil && logger == nil {
		return traceCtx, &operationObserver{}
	}
	observer := &operationObserver{
		trace:  trace,
		logger: logger,
		start:  start,
		began:  began,
		ctx:    traceCtx,
		queue:  make(chan traceDispatch, 8),
	}
	go observer.run()
	return traceCtx, observer
}

func (o *operationObserver) run() {
	for dispatch := range o.queue {
		switch dispatch.kind {
		case traceDispatchEvent:
			o.callEvent(dispatch.event)
			o.logEvent(dispatch.event)
		case traceDispatchEnd:
			o.callEnd(dispatch.end)
			o.logEnd(dispatch.end)
			return
		}
	}
}

func (o *operationObserver) event(event TraceEvent) {
	if o.queue == nil {
		return
	}
	o.queue <- traceDispatch{kind: traceDispatchEvent, event: event}
}

func (o *operationObserver) end(end TraceEnd) {
	if o.queue == nil {
		return
	}
	o.once.Do(func() { o.queue <- traceDispatch{kind: traceDispatchEnd, end: end} })
}

func (o *operationObserver) callEvent(event TraceEvent) {
	if o.trace == nil {
		return
	}
	defer func() { _ = recover() }()
	o.trace.Event(event)
}

func (o *operationObserver) callEnd(end TraceEnd) {
	if o.trace == nil {
		return
	}
	defer func() { _ = recover() }()
	o.trace.End(end)
}

func (o *operationObserver) logEvent(event TraceEvent) {
	message := "ldap operation event"
	attrs := o.logAttrs()
	byteField := slog.Uint64("response_bytes", event.Bytes)
	if event.Kind == TraceWritten {
		byteField = slog.Uint64("request_bytes", event.Bytes)
	}
	attrs = append(attrs,
		slog.String("event", event.Kind.String()),
		slog.Duration("elapsed", event.At.Sub(o.began)),
		byteField,
		slog.Uint64("responses", event.Responses),
	)
	safeDebug(o.ctx, o.logger, message, attrs...)
}

func (o *operationObserver) logEnd(end TraceEnd) {
	attrs := o.logAttrs()
	attrs = append(attrs,
		slog.Duration("duration", end.At.Sub(o.began)),
		slog.Uint64("request_bytes", end.RequestBytes),
		slog.Uint64("response_bytes", end.ResponseBytes),
		slog.Uint64("responses", end.Responses),
		slog.String("error_class", end.ErrorClass),
	)
	safeDebug(o.ctx, o.logger, "ldap operation completed", attrs...)
}

func (o *operationObserver) logAttrs() []slog.Attr {
	attrs := []slog.Attr{
		slog.String("endpoint_id", string(o.start.Endpoint)),
		slog.String("endpoint_address", o.start.EndpointAddress),
		slog.Uint64("connection_id", o.start.Connection),
		slog.String("operation", o.start.Label),
		slog.String("application_tag", o.start.ApplicationTag.String()),
	}
	if o.start.MessageID != 0 {
		attrs = append(attrs, slog.Int64("message_id", int64(o.start.MessageID)))
	}
	return attrs
}

// String returns the stable logging name for a trace event.
func (k TraceEventKind) String() string {
	switch k {
	case TraceQueued:
		return "queued"
	case TraceWritten:
		return "written"
	case TraceFirstResponse:
		return "first_response"
	case TraceCanceled:
		return "canceled"
	case TraceConnectionRetired:
		return "connection_retired"
	default:
		return "unknown"
	}
}

func safeDebug(ctx context.Context, logger *slog.Logger, message string, attrs ...slog.Attr) {
	if logger == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	defer func() { _ = recover() }()
	if logger.Enabled(ctx, slog.LevelDebug) {
		logger.LogAttrs(ctx, slog.LevelDebug, message, attrs...)
	}
}

func errorClass(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, ErrClosed):
		return "closed"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, ErrNoticeOfDisconnection):
		return "notice_of_disconnection"
	case errors.Is(err, ErrProtocol):
		return "protocol"
	case errors.Is(err, ErrResourceLimit):
		return "resource_limit"
	case errors.Is(err, ErrSetup):
		return "setup"
	case errors.Is(err, ErrEndpointUnavailable):
		return "endpoint_unavailable"
	case errors.Is(err, ErrTransport):
		return "transport"
	default:
		return "other"
	}
}
