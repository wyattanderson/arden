package gssapi

import (
	"errors"
	"fmt"

	gogssapi "github.com/golang-auth/go-gssapi/v3"

	"github.com/wyattanderson/arden/rfc4511"
)

// GSSOperation identifies the provider operation that failed. These values
// contain no names, principals, credentials, or tokens.
type GSSOperation string

// GSS provider operations reported by Error.
const (
	OperationNewProvider     GSSOperation = "new-provider"
	OperationImportName      GSSOperation = "import-name"
	OperationInitContext     GSSOperation = "init-context"
	OperationContinue        GSSOperation = "continue-context"
	OperationReleaseName     GSSOperation = "release-name"
	OperationUnwrap          GSSOperation = "unwrap"
	OperationWrap            GSSOperation = "wrap"
	OperationDeleteContext   GSSOperation = "delete-context"
	OperationReleaseProvider GSSOperation = "release-provider"
)

// Error is a safely printable GSS provider failure. Err remains available to
// errors.Is and errors.As, but its text is excluded from Error because native
// mechanism messages can contain principal names and credential-cache paths.
//
// Major is the RFC 2744 major status when go-gssapi exposes enough structured
// status information to reconstruct it. MajorKnown is false for provider
// errors that do not retain those components. The upstream API does not expose
// raw mechanism-specific minor status values.
type Error struct {
	Operation  GSSOperation
	Major      uint32
	MajorKnown bool
	Err        error
}

func (e *Error) Error() string {
	if e.MajorKnown {
		return fmt.Sprintf("arden/auth/gssapi: GSS %s failed (major 0x%08x)", e.Operation, e.Major)
	}
	return fmt.Sprintf("arden/auth/gssapi: GSS %s failed", e.Operation)
}

// Unwrap exposes the typed provider cause without including it in ordinary
// formatted output.
func (e *Error) Unwrap() error {
	return e.Err
}

func gssError(operation GSSOperation, err error) error {
	if err == nil {
		return nil
	}
	major, known := majorStatus(err)
	return &Error{Operation: operation, Major: major, MajorKnown: known, Err: err}
}

func majorStatus(err error) (uint32, bool) {
	if fatal, ok := errors.AsType[gogssapi.FatalStatus](err); ok {
		return uint32(fatal.FatalErrorCode)<<16 | uint32(fatal.InformationCode), true
	}
	var fatalPointer *gogssapi.FatalStatus
	if errors.As(err, &fatalPointer) && fatalPointer != nil {
		return uint32(fatalPointer.FatalErrorCode)<<16 | uint32(fatalPointer.InformationCode), true
	}
	if info, ok := errors.AsType[gogssapi.InfoStatus](err); ok {
		return uint32(info.InformationCode), true
	}
	var infoPointer *gogssapi.InfoStatus
	if errors.As(err, &infoPointer) && infoPointer != nil {
		return uint32(infoPointer.InformationCode), true
	}
	return 0, false
}

// ErrNegotiation identifies a malformed, unsupported, or inconsistent RFC
// 4752 exchange.
var ErrNegotiation = errors.New("arden/auth/gssapi: negotiation failed")

// NegotiationStep identifies the portion of RFC 4752 that failed.
type NegotiationStep uint8

// RFC 4752 negotiation steps.
const (
	StepContext NegotiationStep = iota + 1
	StepSecurityLayer
	StepFinalBind
)

func (s NegotiationStep) String() string {
	switch s {
	case StepContext:
		return "context-establishment"
	case StepSecurityLayer:
		return "security-layer-selection"
	case StepFinalBind:
		return "final-bind"
	default:
		return fmt.Sprintf("step(%d)", uint8(s))
	}
}

// NegotiationFailure classifies a safe RFC 4752 failure without retaining a
// GSS or SASL token.
type NegotiationFailure uint8

// Negotiation failure classes.
const (
	FailureNilHandle NegotiationFailure = iota + 1
	FailureTooManyRounds
	FailureInconsistentContextState
	FailureUnexpectedLDAPResult
	FailureMissingServerCredentials
	FailureMissingContextProtection
	FailureWrongMechanism
	FailureInvalidSecurityOffer
	FailureEncryptedSecurityOffer
	FailureNoAuthenticationOnlyLayer
	FailureInvalidServerBuffer
	FailureEncryptedLayerSelection
	FailureUnexpectedFinalCredentials
)

func (f NegotiationFailure) String() string {
	switch f {
	case FailureNilHandle:
		return "provider returned a nil handle"
	case FailureTooManyRounds:
		return "context round limit exceeded"
	case FailureInconsistentContextState:
		return "provider returned inconsistent context state"
	case FailureUnexpectedLDAPResult:
		return "server returned an unexpected LDAP result"
	case FailureMissingServerCredentials:
		return "server omitted required SASL credentials"
	case FailureMissingContextProtection:
		return "context lacks mutual authentication or integrity"
	case FailureWrongMechanism:
		return "context did not negotiate Kerberos V5"
	case FailureInvalidSecurityOffer:
		return "server security-layer offer is invalid"
	case FailureEncryptedSecurityOffer:
		return "server encrypted the security-layer offer"
	case FailureNoAuthenticationOnlyLayer:
		return "server did not offer authentication-only operation"
	case FailureInvalidServerBuffer:
		return "server advertised a buffer for authentication-only operation"
	case FailureEncryptedLayerSelection:
		return "provider encrypted the security-layer selection"
	case FailureUnexpectedFinalCredentials:
		return "server returned unexpected final SASL credentials"
	default:
		return fmt.Sprintf("failure(%d)", uint8(f))
	}
}

// NegotiationError contains only nonsecret protocol metadata. ResultCode and
// OfferedLayers are populated when relevant; no token or server diagnostic is
// retained.
type NegotiationError struct {
	Step          NegotiationStep
	Failure       NegotiationFailure
	ResultCode    rfc4511.ResultCode
	OfferedLayers byte
}

func (e *NegotiationError) Error() string {
	return fmt.Sprintf("arden/auth/gssapi: %s: %s", e.Step, e.Failure)
}

// Is reports whether target is ErrNegotiation.
func (e *NegotiationError) Is(target error) bool { return target == ErrNegotiation }
