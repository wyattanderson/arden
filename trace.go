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

type TraceStart struct {
	Endpoint   EndpointID
	Connection uint64
	Label      string
	RequestID  ber.Identifier
}

type TraceEventKind uint8

const (
	TraceQueued TraceEventKind = iota + 1
	TraceWritten
	TraceFirstResponse
	TraceCanceled
	TraceConnectionRetired
)

type TraceEvent struct {
	Kind      TraceEventKind
	At        time.Time
	Bytes     uint64
	Responses uint64
}

type TraceEnd struct {
	At            time.Time
	RequestBytes  uint64
	ResponseBytes uint64
	Responses     uint64
	ErrorClass    string
}
