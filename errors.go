package arden

import (
	"errors"
	"fmt"

	"github.com/wyattanderson/arden/ber"
)

var (
	ErrClosed                = errors.New("arden: closed")
	ErrTransport             = errors.New("arden: transport failure")
	ErrProtocol              = errors.New("arden: protocol failure")
	ErrResourceLimit         = errors.New("arden: resource limit exceeded")
	ErrAmbiguousOutcome      = errors.New("arden: request outcome is ambiguous")
	ErrDefinitelyUnsent      = errors.New("arden: request was definitely not sent")
	ErrEndpointUnavailable   = errors.New("arden: endpoint unavailable")
	ErrSetup                 = errors.New("arden: connection setup failed")
	ErrNoticeOfDisconnection = errors.New("arden: notice of disconnection")
)

// TransportStage identifies the stage at which I/O failed.
type TransportStage uint8

const (
	StageDial TransportStage = iota + 1
	StageTLS
	StageRead
	StageWrite
	StagePeerClose
)

func (s TransportStage) String() string {
	switch s {
	case StageDial:
		return "dial"
	case StageTLS:
		return "tls"
	case StageRead:
		return "read"
	case StageWrite:
		return "write"
	case StagePeerClose:
		return "peer-close"
	default:
		return fmt.Sprintf("stage(%d)", uint8(s))
	}
}

// RequestOutcome records only what the transport can prove about a request.
type RequestOutcome uint8

const (
	OutcomeNotApplicable RequestOutcome = iota
	OutcomeDefinitelyUnsent
	OutcomeAmbiguous
)

// TransportError preserves the underlying context or network error. Outcome is
// explicit because connection-level failures are not always tied to a request.
type TransportError struct {
	Stage   TransportStage
	Outcome RequestOutcome
	Err     error
}

func (e *TransportError) Error() string {
	if e == nil {
		return "arden: <nil transport error>"
	}
	return fmt.Sprintf("arden: %s: %v", e.Stage, e.Err)
}

func (e *TransportError) Unwrap() error { return e.Err }
func (e *TransportError) Is(target error) bool {
	return target == ErrTransport ||
		(target == ErrDefinitelyUnsent && e.Outcome == OutcomeDefinitelyUnsent) ||
		(target == ErrAmbiguousOutcome && e.Outcome == OutcomeAmbiguous)
}

// ProtocolErrorKind distinguishes framing, envelope, and routing violations.
type ProtocolErrorKind uint8

const (
	ProtocolFraming ProtocolErrorKind = iota + 1
	ProtocolEnvelope
	ProtocolUnexpectedMessageID
	ProtocolUnexpectedIdentifier
)

// ProtocolError retires the entire connection.
type ProtocolError struct {
	Kind      ProtocolErrorKind
	MessageID MessageID
	Got       ber.Identifier
	Err       error
}

func (e *ProtocolError) Error() string {
	if e == nil {
		return "arden: <nil protocol error>"
	}
	if e.Err != nil {
		return fmt.Sprintf("arden: protocol failure (%d): %v", e.Kind, e.Err)
	}
	return fmt.Sprintf("arden: protocol failure (%d): message %d, identifier %s", e.Kind, e.MessageID, e.Got)
}

func (e *ProtocolError) Unwrap() error        { return e.Err }
func (e *ProtocolError) Is(target error) bool { return target == ErrProtocol }

// LimitError names a public configured limit without exposing payload data.
type LimitError struct {
	Limit string
	Value uint64
	Max   uint64
}

func (e *LimitError) Error() string {
	if e == nil {
		return "arden: <nil limit error>"
	}
	return fmt.Sprintf("arden: resource limit %q exceeded: %d > %d", e.Limit, e.Value, e.Max)
}

func (e *LimitError) Is(target error) bool { return target == ErrResourceLimit }

// RouteError never authorizes implicit rerouting to another endpoint.
type RouteError struct {
	Endpoint EndpointID
	Err      error
}

func (e *RouteError) Error() string {
	if e == nil {
		return "arden: <nil route error>"
	}
	return fmt.Sprintf("arden: endpoint %q unavailable: %v", e.Endpoint, e.Err)
}

func (e *RouteError) Unwrap() error        { return e.Err }
func (e *RouteError) Is(target error) bool { return target == ErrEndpointUnavailable }

// SetupStage identifies a failure before a connection becomes application-ready.
type SetupStage uint8

const (
	SetupAuthentication SetupStage = iota + 1
	SetupInitialization
	SetupProfileMismatch
)

// SetupError contains no credentials, tokens, or endpoint profile values.
type SetupError struct {
	Endpoint EndpointID
	Stage    SetupStage
	Err      error
}

func (e *SetupError) Error() string {
	if e == nil {
		return "arden: <nil setup error>"
	}
	return fmt.Sprintf("arden: endpoint %q setup stage %d failed: %v", e.Endpoint, e.Stage, e.Err)
}

func (e *SetupError) Unwrap() error        { return e.Err }
func (e *SetupError) Is(target error) bool { return target == ErrSetup }

// NoticeError represents the RFC 4511 Notice of Disconnection. Diagnostic is
// owned but intentionally excluded from Error so server-provided data is not
// logged accidentally.
type NoticeError struct {
	ResultCode int64
	Diagnostic []byte
}

func (e *NoticeError) Error() string {
	if e == nil {
		return "arden: <nil notice of disconnection>"
	}
	return fmt.Sprintf("arden: notice of disconnection (result code %d)", e.ResultCode)
}

func (e *NoticeError) Is(target error) bool { return target == ErrNoticeOfDisconnection }
