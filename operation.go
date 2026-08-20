package arden

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

const MaxMessageID MessageID = 1<<31 - 1

// ProtocolOperation is implemented by hand-authored RFC 4511 and extension
// operations alike. AppendBER encodes only the protocolOp value, not the
// LDAPMessage envelope.
type ProtocolOperation interface {
	ber.Marshaler
	ProtocolIdentifier() ber.Identifier
}

// Classification is the framing-only disposition of a response identifier.
type Classification uint8

const (
	ClassificationInvalid Classification = iota
	ClassificationContinue
	ClassificationComplete
)

// ResponseSpec is copied by NewResponsePattern. The caller may reuse or mutate
// its slices after construction.
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

// Classify uses only the protocol-operation identifier. It never examines a
// result code, controls, or payload bytes.
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

func (p ResponsePattern) Valid() bool      { return p.valid }
func (p ResponsePattern) NoResponse() bool { return p.valid && p.noResponse }

// CancellationMode tells the connection how it may stop an operation. It is
// policy, not an instruction to treat context cancellation as a socket
// deadline.
type CancellationMode uint8

const (
	// CancelDrain stops delivery and discards responses through a terminal tag.
	CancelDrain CancellationMode = iota + 1
	// CancelAbandon sends an RFC 4511 Abandon and tombstones the target message
	// ID for the rest of the connection unless a terminal response wins the race.
	CancelAbandon
	// CancelExtended reserves the seam for an RFC 3909 Cancel operation selected
	// by a frozen endpoint policy.
	CancelExtended
	// CancelClose retires the connection when safe draining is not possible.
	CancelClose
	// CancelNone records cancellation but permits no protocol-side action.
	CancelNone
)

// OperationMetadata is safe routing and observability metadata. Label must not
// contain request payloads, DNs, filters, attributes, or credentials.
type OperationMetadata struct {
	Label string
}

// Operation is a fully declared binary request. Controls are encoded in order
// after the protocol operation and are not consulted by response routing.
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

// Response owns Bytes. Protocol and the raw Control elements are views into
// Bytes; none of them alias the socket reader. The caller may retain or modify
// the response after Next returns.
type Response struct {
	MessageID  MessageID
	ProtocolID ber.Identifier
	Bytes      []byte
	Protocol   []byte
	Controls   []ber.Element
}

// UnmarshalProtocol decodes the complete protocolOp value using a caller-
// selected public codec. It runs in the consumer goroutine, never the socket
// reader, and rejects trailing bytes after the decoded value.
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

// ResponseStream is the consumer side of one operation. Next returns owned
// messages and never runs decoding or caller callbacks in the socket reader.
type ResponseStream interface {
	Next(context.Context) (Response, error)
	Close() error
}
