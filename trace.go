package arden

import (
	"context"
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
	Endpoint   EndpointID
	Connection uint64
	Label      string
	RequestID  ber.Identifier
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
