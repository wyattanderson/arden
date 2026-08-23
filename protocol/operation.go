// Package protocol defines transport-neutral LDAP operation and response
// contracts shared by Arden's connection runtime, RFC codecs, and extensions.
package protocol

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/wyattanderson/arden/ber"
)

// MessageID is an LDAP message identifier. Zero is reserved for unsolicited
// notifications; requests use values in [1, MaxMessageID].
type MessageID int32

// MaxMessageID is the largest message identifier permitted by RFC 4511.
const MaxMessageID MessageID = 1<<31 - 1

// ProtocolOperation encodes only a protocolOp value, not its LDAPMessage envelope.
//
//revive:disable-next-line:exported
type ProtocolOperation interface {
	ber.Marshaler
	ProtocolIdentifier() ber.Identifier
}

// Classification is the framing-only disposition of a response identifier.
type Classification uint8

// Response classifications produced by ResponsePattern.Classify.
const (
	ClassificationInvalid Classification = iota
	ClassificationContinue
	ClassificationComplete
)

// ResponseSpec is copied by NewResponsePattern.
type ResponseSpec struct {
	Continue   []ber.Identifier
	Complete   []ber.Identifier
	NoResponse bool
}

// ResponsePattern is an immutable response contract. Its zero value is invalid.
type ResponsePattern struct {
	continueIDs []ber.Identifier
	completeIDs []ber.Identifier
	noResponse  bool
	valid       bool
}

// NewResponsePattern validates and freezes a response contract.
func NewResponsePattern(spec ResponseSpec) (ResponsePattern, error) {
	if spec.NoResponse {
		if len(spec.Continue) != 0 || len(spec.Complete) != 0 {
			return ResponsePattern{}, errors.New("arden: a no-response pattern cannot contain response identifiers")
		}
		return ResponsePattern{noResponse: true, valid: true}, nil
	}
	if len(spec.Complete) == 0 {
		return ResponsePattern{}, errors.New("arden: a response pattern needs at least one terminal identifier")
	}

	seen := make(map[ber.Identifier]struct{}, len(spec.Continue)+len(spec.Complete))
	validate := func(kind string, ids []ber.Identifier) error {
		for _, id := range ids {
			if !id.Valid() || id.Class != ber.ClassApplication {
				return fmt.Errorf("arden: %s identifier %s is not an application identifier", kind, id)
			}
			if _, exists := seen[id]; exists {
				return fmt.Errorf("arden: duplicate response identifier %s", id)
			}
			seen[id] = struct{}{}
		}
		return nil
	}
	if err := validate("continuing", spec.Continue); err != nil {
		return ResponsePattern{}, err
	}
	if err := validate("terminal", spec.Complete); err != nil {
		return ResponsePattern{}, err
	}

	return ResponsePattern{
		continueIDs: slices.Clone(spec.Continue),
		completeIDs: slices.Clone(spec.Complete),
		valid:       true,
	}, nil
}

// Classify uses only the protocol-operation identifier.
func (p ResponsePattern) Classify(id ber.Identifier) Classification {
	if !p.valid || p.noResponse {
		return ClassificationInvalid
	}
	if slices.Contains(p.continueIDs, id) {
		return ClassificationContinue
	}
	if slices.Contains(p.completeIDs, id) {
		return ClassificationComplete
	}
	return ClassificationInvalid
}

// Valid reports whether the response pattern was successfully constructed.
func (p ResponsePattern) Valid() bool { return p.valid }

// NoResponse reports whether the valid pattern expects no response messages.
func (p ResponsePattern) NoResponse() bool { return p.valid && p.noResponse }

// CancellationMode tells the connection how it may stop an operation.
type CancellationMode uint8

const (
	// CancelDrain discards responses through a terminal tag.
	CancelDrain CancellationMode = iota + 1
	// CancelAbandon sends Abandon and tombstones the target message ID.
	CancelAbandon
	// CancelExtended reserves the seam for an RFC 3909 Cancel operation.
	CancelExtended
	// CancelClose retires the connection when safe draining is not possible.
	CancelClose
	// CancelNone permits no protocol-side cancellation action.
	CancelNone
)

// OperationMetadata is safe routing and observability metadata.
type OperationMetadata struct {
	Label string
}

// Operation is a fully declared request.
type Operation struct {
	Protocol     ProtocolOperation
	Controls     []ber.Marshaler
	Responses    ResponsePattern
	Cancellation CancellationMode
	Metadata     OperationMetadata
}

// Validate checks transport-independent request invariants.
func (op Operation) Validate() error {
	if op.Protocol == nil {
		return errors.New("arden: operation has no protocol value")
	}
	id := op.Protocol.ProtocolIdentifier()
	if !id.Valid() || id.Class != ber.ClassApplication {
		return fmt.Errorf("arden: request identifier %s is not an application identifier", id)
	}
	if !op.Responses.Valid() {
		return errors.New("arden: operation has an invalid response pattern")
	}
	if op.Cancellation < CancelDrain || op.Cancellation > CancelNone {
		return errors.New("arden: operation has an invalid cancellation mode")
	}
	for i, control := range op.Controls {
		if control == nil {
			return fmt.Errorf("arden: control %d is nil", i)
		}
	}
	return nil
}

// Response owns Bytes; all other byte views refer only to that owned slice.
type Response struct {
	MessageID  MessageID
	ProtocolID ber.Identifier
	Bytes      []byte
	Protocol   []byte
	Controls   []ber.Element
	Extensions []ber.Element
}

// ResponseHeader is the routing information in an LDAP response envelope.
type ResponseHeader struct {
	MessageID  MessageID
	ProtocolID ber.Identifier
}

// Header returns the response's routing information.
func (r Response) Header() ResponseHeader {
	return ResponseHeader{MessageID: r.MessageID, ProtocolID: r.ProtocolID}
}

// UnmarshalProtocol decodes a complete protocolOp and rejects trailing bytes.
func (r Response) UnmarshalProtocol(dst ber.Unmarshaler, limits ber.Limits) error {
	if dst == nil {
		return errors.New("arden: nil protocol unmarshaler")
	}
	if len(r.Protocol) == 0 {
		return errors.New("arden: response has no protocol value")
	}
	reader, err := ber.NewReader(r.Protocol, limits)
	if err != nil {
		return err
	}
	if err := dst.UnmarshalBER(reader); err != nil {
		return err
	}
	return reader.RequireEmpty()
}

// ResponseStream is the consumer side of one operation.
type ResponseStream interface {
	Next(context.Context) (Response, error)
	Close() error
}

// ResponseLifecycle exposes protocol completion without consuming responses.
type ResponseLifecycle interface {
	ResponseStream
	Done() <-chan struct{}
}

// Executor starts transport-neutral protocol operations.
type Executor interface {
	Do(context.Context, Operation) (ResponseStream, error)
}
