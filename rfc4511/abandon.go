package rfc4511

import (
	"errors"
	"slices"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ber"
)

var (
	abandonRequestIdentifier = applicationPrimitive(16)
	abandonResponsePattern   = mustResponsePattern(arden.ResponseSpec{NoResponse: true})
)

// AbandonRequestIdentifier returns the application identifier for AbandonRequest.
func AbandonRequestIdentifier() ber.Identifier { return abandonRequestIdentifier }

// AbandonRequest asks the server to abandon Target. The request itself still
// receives its own LDAPMessage message ID from the connection runtime, but it
// has no LDAP response. RFC 4511 section 4.11.
type AbandonRequest struct{ Target arden.MessageID }

//revive:disable-next-line:exported
func (*AbandonRequest) ProtocolIdentifier() ber.Identifier { return abandonRequestIdentifier }

//revive:disable-next-line:exported
func (v *AbandonRequest) AppendBER(dst []byte) ([]byte, error) {
	if v == nil {
		return dst, errors.New("rfc4511: nil AbandonRequest")
	}
	if v.Target <= 0 || v.Target > arden.MaxMessageID {
		return dst, errors.New("rfc4511: AbandonRequest target is outside [1, MaxMessageID]")
	}
	return ber.AppendIntegerWithIdentifier(dst, abandonRequestIdentifier, int64(v.Target))
}

//revive:disable-next-line:exported
func (v *AbandonRequest) UnmarshalBER(r *ber.Reader) error {
	if v == nil {
		return nilReceiver("AbandonRequest")
	}
	target, err := r.IntegerWithIdentifier(abandonRequestIdentifier)
	if err != nil {
		return err
	}
	if target <= 0 || target > int64(arden.MaxMessageID) {
		return errors.New("rfc4511: AbandonRequest target is outside [1, MaxMessageID]")
	}
	*v = AbandonRequest{Target: arden.MessageID(target)}
	return nil
}

// AbandonResponsePattern returns the no-response pattern for AbandonRequest.
func AbandonResponsePattern() arden.ResponsePattern { return abandonResponsePattern }

// NewAbandonOperation creates a complete Abandon request declaration.
func NewAbandonOperation(request *AbandonRequest, controls []ber.Marshaler) (arden.Operation, error) {
	if request == nil {
		return arden.Operation{}, errors.New("rfc4511: nil AbandonRequest")
	}
	op := arden.Operation{Protocol: request, Controls: slices.Clone(controls), Responses: AbandonResponsePattern(), Cancellation: arden.CancelNone, Metadata: arden.OperationMetadata{Label: "ldap.abandon"}}
	if err := op.Validate(); err != nil {
		return arden.Operation{}, err
	}
	return op, nil
}
