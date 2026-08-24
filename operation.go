package arden

import (
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/protocol"
)

// MessageID is an LDAP message identifier.
type MessageID = protocol.MessageID

// ProtocolOperation encodes one LDAP protocolOp value.
type ProtocolOperation = protocol.ProtocolOperation

// Classification is the framing disposition of a response identifier.
type Classification = protocol.Classification

// ResponseSpec describes a response pattern before validation.
type ResponseSpec = protocol.ResponseSpec

// FramingPattern is the type-erased immutable response framing contract.
type FramingPattern = protocol.FramingPattern

// NoResponse is the response type of operations which receive no message.
type NoResponse = protocol.NoResponse

// ResponsePattern is an immutable typed response contract.
type ResponsePattern[T any] = protocol.ResponsePattern[T]

// CancellationMode declares how a connection may stop an operation.
type CancellationMode = protocol.CancellationMode

// OperationMetadata is safe routing and observability metadata.
type OperationMetadata = protocol.OperationMetadata

// UntypedOperation is the erased runtime view of an operation.
type UntypedOperation = protocol.UntypedOperation

// AnyOperation is the type-erasure seam accepted by executors.
type AnyOperation = protocol.AnyOperation

// Operation is a fully declared request whose response type is T.
type Operation[T any] = protocol.Operation[T]

// Response owns one decoded LDAP message envelope.
type Response = protocol.Response

// ResponseHeader is the routing header of a response.
type ResponseHeader = protocol.ResponseHeader

// ResponseStream is the consumer side of an operation.
type ResponseStream = protocol.ResponseStream

// ResponseLifecycle exposes protocol completion without consuming responses.
type ResponseLifecycle = protocol.ResponseLifecycle

// Executor submits protocol operations.
type Executor = protocol.Executor

// MaxMessageID and the remaining constants mirror package protocol.
const (
	MaxMessageID = protocol.MaxMessageID

	ClassificationInvalid  = protocol.ClassificationInvalid
	ClassificationContinue = protocol.ClassificationContinue
	ClassificationComplete = protocol.ClassificationComplete

	CancelDrain    = protocol.CancelDrain
	CancelAbandon  = protocol.CancelAbandon
	CancelExtended = protocol.CancelExtended
	CancelClose    = protocol.CancelClose
	CancelNone     = protocol.CancelNone
)

// NewResponsePattern validates and freezes a typed response contract.
func NewResponsePattern[T any, P interface {
	*T
	ber.Unmarshaler
}](spec ResponseSpec) (ResponsePattern[T], error) {
	return protocol.NewResponsePattern[T, P](spec)
}

// NewNoResponsePattern returns the standard typed no-response contract.
func NewNoResponsePattern() ResponsePattern[NoResponse] {
	return protocol.NewNoResponsePattern()
}
