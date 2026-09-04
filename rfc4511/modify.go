package rfc4511

import (
	"errors"
	"slices"

	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/protocol"
)

var (
	modifyRequestIdentifier  = applicationConstructed(6)
	modifyResponseIdentifier = applicationConstructed(7)
	modifyResponsePattern    = mustResponsePattern[ModifyResponse](protocol.ResponseSpec{Complete: []ber.Identifier{modifyResponseIdentifier}})
)

// ModifyRequestIdentifier returns the application identifier for ModifyRequest.
func ModifyRequestIdentifier() ber.Identifier { return modifyRequestIdentifier }

// ModifyResponseIdentifier returns the application identifier for ModifyResponse.
func ModifyResponseIdentifier() ber.Identifier { return modifyResponseIdentifier }

// ModifyOperation is the extensible Change operation ENUMERATED.
type ModifyOperation int64

// Modify operations accepted in a Change record.
const (
	ModifyAdd     ModifyOperation = 0
	ModifyDelete  ModifyOperation = 1
	ModifyReplace ModifyOperation = 2
)

// Replace constructs a text-valued replace change.
func Replace(attribute string, values ...string) Change {
	return changeText(ModifyReplace, attribute, values)
}

// AddValues constructs a text-valued add change.
func AddValues(attribute string, values ...string) Change {
	return changeText(ModifyAdd, attribute, values)
}

// DeleteValues constructs a text-valued delete change. With no values it
// removes the entire attribute.
func DeleteValues(attribute string, values ...string) Change {
	return changeText(ModifyDelete, attribute, values)
}

// ReplaceBytes constructs a binary-valued replace change.
func ReplaceBytes(attribute string, values ...[]byte) Change {
	return changeBytes(ModifyReplace, attribute, values)
}

// AddBytes constructs a binary-valued add change.
func AddBytes(attribute string, values ...[]byte) Change {
	return changeBytes(ModifyAdd, attribute, values)
}

// DeleteBytes constructs a binary-valued delete change.
func DeleteBytes(attribute string, values ...[]byte) Change {
	return changeBytes(ModifyDelete, attribute, values)
}

func changeText(operation ModifyOperation, attribute string, values []string) Change {
	raw := make([]AttributeValue, len(values))
	for i, value := range values {
		raw[i] = AttributeValue(value)
	}
	return Change{Operation: operation, Modification: PartialAttribute{
		Type: AttributeDescription(attribute), Values: raw,
	}}
}

func changeBytes(operation ModifyOperation, attribute string, values [][]byte) Change {
	return Change{Operation: operation, Modification: PartialAttribute{
		Type: AttributeDescription(attribute), Values: cloneAttributeValues(values),
	}}
}

// Change is one ModifyRequest change record.
type Change struct {
	Operation    ModifyOperation
	Modification PartialAttribute
	Extensions   []UnknownField
}

// BERPacket returns the modify change packet.
func (v Change) BERPacket() ber.Packet {
	return ber.Sequence().
		Add(ber.Enumerated(v.Operation)).
		Add(v.Modification).
		Add(v.Extensions...).
		BERPacket()
}

//revive:disable-next-line:exported
func (v *Change) UnmarshalBER(r *ber.Reader) error {
	contents, err := r.Sequence()
	if err != nil {
		return err
	}
	operation, err := contents.Enumerated()
	if err != nil {
		return err
	}
	var modification PartialAttribute
	if err := modification.UnmarshalBER(contents); err != nil {
		return err
	}
	extensions, err := decodeUnknownFields(contents)
	if err != nil {
		return err
	}
	*v = Change{Operation: ModifyOperation(operation), Modification: modification, Extensions: extensions}
	return nil
}

// ModifyRequest is the RFC 4511 ModifyRequest protocol operation.
type ModifyRequest struct {
	Object     LDAPDN
	Changes    []Change
	Extensions []UnknownField
}

//revive:disable-next-line:exported
func (*ModifyRequest) ProtocolIdentifier() ber.Identifier { return modifyRequestIdentifier }

// BERPacket returns the modify-request packet.
func (v *ModifyRequest) BERPacket() ber.Packet {
	return ber.Constructed(modifyRequestIdentifier).
		Add(ber.OctetString(v.Object)).
		Add(ber.Sequence().Add(v.Changes...)).
		Add(v.Extensions...).
		BERPacket()
}

//revive:disable-next-line:exported
func (v *ModifyRequest) UnmarshalBER(r *ber.Reader) error {
	contents, err := r.Constructed(modifyRequestIdentifier)
	if err != nil {
		return err
	}
	object, err := contents.OctetString()
	if err != nil {
		return err
	}
	changesReader, err := contents.Sequence()
	if err != nil {
		return err
	}
	var changes []Change
	for !changesReader.Empty() {
		var change Change
		if err := change.UnmarshalBER(changesReader); err != nil {
			return err
		}
		changes = append(changes, change)
	}
	extensions, err := decodeUnknownFields(contents)
	if err != nil {
		return err
	}
	*v = ModifyRequest{Object: LDAPDN(string(object)), Changes: changes, Extensions: extensions}
	return nil
}

// ModifyResponse is the terminal LDAPResult for ModifyRequest.
type ModifyResponse struct{ Result LDAPResult }

// LDAPResult returns the operation result carried by v.
func (v ModifyResponse) LDAPResult() LDAPResult { return v.Result }

// BERPacket returns the modify-response packet.
func (v ModifyResponse) BERPacket() ber.Packet {
	return resultResponsePacket(modifyResponseIdentifier, v.Result)
}

//revive:disable-next-line:exported
func (v *ModifyResponse) UnmarshalBER(r *ber.Reader) error {
	result, err := decodeResultResponse(r, modifyResponseIdentifier)
	if err != nil {
		return err
	}
	*v = ModifyResponse{Result: result}
	return nil
}

// ModifyResponsePattern returns the terminal response pattern for ModifyRequest.
func ModifyResponsePattern() protocol.ResponsePattern[ModifyResponse] { return modifyResponsePattern }

// NewModifyOperation creates a complete Modify request declaration.
func NewModifyOperation(request *ModifyRequest, controls []ber.Packeter) (protocol.Operation[ModifyResponse], error) {
	if request == nil {
		return protocol.Operation[ModifyResponse]{}, errors.New("arden: nil ModifyRequest")
	}
	op := protocol.Operation[ModifyResponse]{Protocol: request, Controls: slices.Clone(controls), Responses: ModifyResponsePattern(), Cancellation: protocol.CancelDrain, Metadata: protocol.OperationMetadata{Label: "ldap.modify"}}
	if err := op.Validate(); err != nil {
		return protocol.Operation[ModifyResponse]{}, err
	}
	return op, nil
}
