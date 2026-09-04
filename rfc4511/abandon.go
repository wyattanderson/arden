package rfc4511

import (
	"errors"
	"slices"

	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/protocol"
)

var (
	abandonRequestIdentifier = applicationPrimitive(16)
	abandonResponsePattern   = protocol.NewNoResponsePattern()
)

// AbandonRequestIdentifier returns the application identifier for AbandonRequest.
func AbandonRequestIdentifier() ber.Identifier { return abandonRequestIdentifier }

// AbandonRequest asks the server to abandon Target. The request itself still
// receives its own LDAPMessage message ID from the connection runtime, but it
// has no LDAP response. RFC 4511 section 4.11.
type AbandonRequest struct{ Target protocol.MessageID }

//revive:disable-next-line:exported
func (*AbandonRequest) ProtocolIdentifier() ber.Identifier { return abandonRequestIdentifier }

// BERPacket returns the abandon-request packet.
func (v *AbandonRequest) BERPacket() ber.Packet {
	return ber.IntegerWithIdentifier(abandonRequestIdentifier, v.Target)
}

//revive:disable-next-line:exported
func (v *AbandonRequest) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r)
	decoded := AbandonRequest{Target: d.IntegerAs[protocol.MessageID](abandonRequestIdentifier)}
	if err := d.Err(); err != nil {
		return err
	}
	if decoded.Target <= 0 || decoded.Target > protocol.MaxMessageID {
		return errors.New("arden: AbandonRequest target is outside [1, MaxMessageID]")
	}
	*v = decoded
	return nil
}

// AbandonResponsePattern returns the no-response pattern for AbandonRequest.
func AbandonResponsePattern() protocol.ResponsePattern[protocol.NoResponse] {
	return abandonResponsePattern
}

// NewAbandonOperation creates a complete Abandon request declaration.
func NewAbandonOperation(request *AbandonRequest, controls []ber.Packeter) (protocol.Operation[protocol.NoResponse], error) {
	if request == nil {
		return protocol.Operation[protocol.NoResponse]{}, errors.New("arden: nil AbandonRequest")
	}
	op := protocol.Operation[protocol.NoResponse]{Protocol: request, Controls: slices.Clone(controls), Responses: AbandonResponsePattern(), Cancellation: protocol.CancelNone, Metadata: protocol.OperationMetadata{Label: "ldap.abandon"}}
	if err := op.Validate(); err != nil {
		return protocol.Operation[protocol.NoResponse]{}, err
	}
	return op, nil
}
