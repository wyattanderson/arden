package arden

import (
	"errors"
	"fmt"

	"github.com/wyattanderson/arden/ber"
)

// Sentinel errors classify public connection and protocol failures.
var (
	ErrClosed                = errors.New("arden: closed")
	ErrTransport             = errors.New("arden: transport failure")
	ErrProtocol              = errors.New("arden: protocol failure")
	ErrResourceLimit         = errors.New("arden: resource limit exceeded")
	ErrAmbiguousOutcome      = errors.New("arden: request outcome is ambiguous")
	ErrDefinitelyUnsent      = errors.New("arden: request was definitely not sent")
	ErrEndpointUnavailable   = errors.New("arden: endpoint unavailable")
	ErrSetup                 = errors.New("arden: connection setup failed")
	ErrProfileMismatch       = errors.New("arden: endpoint profile mismatch")
	ErrConnectionNotReady    = errors.New("arden: connection is not ready")
	ErrInitializationClosed  = errors.New("arden: initialization session is closed")
	ErrAssociationChange     = errors.New("arden: association-changing operation is restricted to initialization")
	ErrNoticeOfDisconnection = errors.New("arden: notice of disconnection")
)

// TransportStage identifies the stage at which I/O failed.
type TransportStage uint8

// Transport failure stages.
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

// Request outcomes that can be established after transport failure.
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
	return fmt.Sprintf("arden: %s: %v", e.Stage, e.Err)
}

func (e *TransportError) Unwrap() error { return e.Err }

// Is reports whether the transport error belongs to a public error class.
func (e *TransportError) Is(target error) bool {
	return target == ErrTransport ||
		(target == ErrDefinitelyUnsent && e.Outcome == OutcomeDefinitelyUnsent) ||
		(target == ErrAmbiguousOutcome && e.Outcome == OutcomeAmbiguous)
}

// ProtocolErrorKind distinguishes framing, envelope, and routing violations.
type ProtocolErrorKind uint8

// Protocol failure kinds.
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
	if e.Err != nil {
		return fmt.Sprintf("arden: protocol failure (%d): %v", e.Kind, e.Err)
	}
	return fmt.Sprintf("arden: protocol failure (%d): message %d, identifier %s", e.Kind, e.MessageID, e.Got)
}

func (e *ProtocolError) Unwrap() error { return e.Err }

// Is reports whether the error is a protocol failure.
func (e *ProtocolError) Is(target error) bool { return target == ErrProtocol }

// LimitError names a public configured limit without exposing payload data.
type LimitError struct {
	Limit string
	Value uint64
	Max   uint64
}

func (e *LimitError) Error() string {
	return fmt.Sprintf("arden: resource limit %q exceeded: %d > %d", e.Limit, e.Value, e.Max)
}

// Is reports whether the error is a resource-limit failure.
func (e *LimitError) Is(target error) bool { return target == ErrResourceLimit }

// RouteError never authorizes implicit rerouting to another endpoint.
type RouteError struct {
	Endpoint EndpointID
	Err      error
}

func (e *RouteError) Error() string {
	return fmt.Sprintf("arden: endpoint %q unavailable: %v", e.Endpoint, e.Err)
}

func (e *RouteError) Unwrap() error { return e.Err }

// Is reports whether the error is an endpoint-availability failure.
func (e *RouteError) Is(target error) bool { return target == ErrEndpointUnavailable }

// SetupStage identifies a failure before a connection becomes application-ready.
type SetupStage uint8

// Connection setup stages.
const (
	SetupAuthentication SetupStage = iota + 1
	SetupInitialization
	SetupProfileMismatch
)

func (s SetupStage) String() string {
	switch s {
	case SetupAuthentication:
		return "authentication"
	case SetupInitialization:
		return "initialization"
	case SetupProfileMismatch:
		return "profile-validation"
	default:
		return fmt.Sprintf("setup-stage(%d)", uint8(s))
	}
}

// SetupError contains no credentials, tokens, or endpoint profile values.
type SetupError struct {
	Endpoint EndpointID
	Stage    SetupStage
	Err      error
}

func (e *SetupError) Error() string {
	// The underlying mechanism or initializer is not trusted to redact
	// credentials, SASL tokens, directory values, or discovered profile data.
	// Keep errors.Is/errors.As access through Unwrap, but make ordinary logging
	// of the setup error safe by excluding the underlying text.
	return fmt.Sprintf("arden: endpoint %q %s failed", e.Endpoint, e.Stage)
}

func (e *SetupError) Unwrap() error { return e.Err }

// Is reports whether the error is a connection-setup failure.
func (e *SetupError) Is(target error) bool { return target == ErrSetup }

// ProfileMismatchError lets a validating initializer report that a frozen
// endpoint profile no longer matches without exposing either profile in logs.
// Dial setup maps it to SetupProfileMismatch.
type ProfileMismatchError struct {
	Err error
}

func (e *ProfileMismatchError) Error() string {
	return ErrProfileMismatch.Error()
}

func (e *ProfileMismatchError) Unwrap() error {
	return e.Err
}

// Is reports whether target is the profile-mismatch sentinel error.
func (e *ProfileMismatchError) Is(target error) bool {
	return target == ErrProfileMismatch
}

// NoticeError represents the RFC 4511 Notice of Disconnection. Diagnostic is
// owned but intentionally excluded from Error so server-provided data is not
// logged accidentally.
type NoticeError struct {
	ResultCode int64
	Diagnostic []byte
}

func (e *NoticeError) Error() string {
	return fmt.Sprintf("arden: notice of disconnection (result code %d)", e.ResultCode)
}

// Is reports whether the error is an RFC 4511 Notice of Disconnection.
func (e *NoticeError) Is(target error) bool { return target == ErrNoticeOfDisconnection }
