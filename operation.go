package arden

import "github.com/wyattanderson/arden/protocol"

// MessageID is an LDAP message identifier.
type MessageID = protocol.MessageID

// ProtocolOperation encodes one LDAP protocolOp value.
type ProtocolOperation = protocol.ProtocolOperation

// Classification is the framing disposition of a response identifier.
type Classification = protocol.Classification

// ResponseSpec describes a response pattern before validation.
type ResponseSpec = protocol.ResponseSpec

// ResponsePattern is an immutable response contract.
type ResponsePattern = protocol.ResponsePattern

// CancellationMode declares how a connection may stop an operation.
type CancellationMode = protocol.CancellationMode

// OperationMetadata is safe routing and observability metadata.
type OperationMetadata = protocol.OperationMetadata

// Operation is a fully declared request.
type Operation = protocol.Operation

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

// NewResponsePattern validates and freezes a response contract.
var NewResponsePattern = protocol.NewResponsePattern
