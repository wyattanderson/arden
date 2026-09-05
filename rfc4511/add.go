package rfc4511

import (
	"errors"
	"slices"

	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/protocol"
)

var addResponsePattern = mustResponsePattern[AddResponse](protocol.ResponseSpec{
	Complete: []ber.Identifier{addResponseIdentifier},
})

var (
	addRequestIdentifier = ber.Identifier{
		Class:       ber.ClassApplication,
		Constructed: true,
		Number:      8,
	}
	addResponseIdentifier = ber.Identifier{
		Class:       ber.ClassApplication,
		Constructed: true,
		Number:      9,
	}
)

// AddRequestIdentifier returns the application identifier for AddRequest.
// RFC 4511 section 4.7.
func AddRequestIdentifier() ber.Identifier { return addRequestIdentifier }

// AddResponseIdentifier returns the application identifier for AddResponse.
// RFC 4511 section 4.7.
func AddResponseIdentifier() ber.Identifier { return addResponseIdentifier }

// AddRequest is the RFC 4511 AddRequest protocol operation.
//
// RFC 4511 section 4.7.
type AddRequest struct {
	Entry      LDAPDN
	Attributes []Attribute
	Extensions []UnknownField
}

// ProtocolIdentifier identifies AddRequest as application/constructed/8.
//
//revive:disable-next-line:exported
func (*AddRequest) ProtocolIdentifier() ber.Identifier { return addRequestIdentifier }

// BERPacket returns the add-request packet.
func (v *AddRequest) BERPacket() ber.Packet {
	return ber.Constructed(addRequestIdentifier).
		Add(ber.OctetString(v.Entry)).
		Add(ber.Sequence().Add(v.Attributes...)).
		Add(v.Extensions...).
		BERPacket()
}

// UnmarshalBER decodes one AddRequest protocolOp. Retained value bytes are
// copied, and v is unchanged if decoding fails.
//
//revive:disable-next-line:exported
func (v *AddRequest) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r).Constructed(addRequestIdentifier)
	decoded := AddRequest{
		Entry:      d.Read[LDAPDN](),
		Attributes: d.Sequence().All[Attribute](),
		Extensions: d.Extensions[UnknownField](),
	}
	if err := d.End(); err != nil {
		return err
	}
	// RFC 4511 section 4.7 requires at least one value per added attribute.
	for _, attribute := range decoded.Attributes {
		if len(attribute.Values) == 0 {
			return errors.New("arden: AddRequest attribute requires at least one value")
		}
	}
	*v = decoded
	return nil
}

// AddResponse is the terminal LDAPResult for an AddRequest.
//
// RFC 4511 section 4.7.
type AddResponse struct {
	Result LDAPResult
}

// LDAPResult returns the operation result carried by v.
func (v AddResponse) LDAPResult() LDAPResult { return v.Result }

// BERPacket returns the add-response packet.
func (v AddResponse) BERPacket() ber.Packet {
	return resultResponsePacket(addResponseIdentifier, v.Result)
}

//revive:disable-next-line:exported
func (v *AddResponse) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r)
	decoded := AddResponse{Result: d.ReadAs[LDAPResult](addResponseIdentifier)}
	if err := d.Err(); err != nil {
		return err
	}
	*v = decoded
	return nil
}

// AddResponsePattern returns the immutable standard terminal response pattern
// for AddRequest. It is safe to reuse concurrently.
func AddResponsePattern() protocol.ResponsePattern[AddResponse] { return addResponsePattern }

// NewAddOperation creates the complete request declaration for an Add. It
// clones the control slice but not the caller-owned request or control values;
// the connection validates and encodes them before concurrent use.
func NewAddOperation(request *AddRequest, controls []ber.Packeter) (protocol.Operation[AddResponse], error) {
	if request == nil {
		return protocol.Operation[AddResponse]{}, errors.New("arden: nil AddRequest")
	}
	op := protocol.Operation[AddResponse]{
		Protocol:     request,
		Controls:     slices.Clone(controls),
		Responses:    AddResponsePattern(),
		Cancellation: protocol.CancelDrain,
		Metadata:     protocol.OperationMetadata{Label: "ldap.add"},
	}
	if err := op.Validate(); err != nil {
		return protocol.Operation[AddResponse]{}, err
	}
	return op, nil
}

func mustResponsePattern[T any, P interface {
	*T
	ber.Unmarshaler
}](spec protocol.ResponseSpec) protocol.ResponsePattern[T] {
	pattern, err := protocol.NewResponsePattern[T, P](spec)
	if err != nil {
		panic(err)
	}
	return pattern
}
