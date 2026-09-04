package rfc4511

import (
	"errors"
	"slices"

	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/protocol"
)

var (
	deleteRequestIdentifier  = applicationPrimitive(10)
	deleteResponseIdentifier = applicationConstructed(11)
	deleteResponsePattern    = mustResponsePattern[DeleteResponse](protocol.ResponseSpec{Complete: []ber.Identifier{deleteResponseIdentifier}})
)

// DeleteRequestIdentifier returns the application identifier for DeleteRequest.
func DeleteRequestIdentifier() ber.Identifier { return deleteRequestIdentifier }

// DeleteResponseIdentifier returns the application identifier for DeleteResponse.
func DeleteResponseIdentifier() ber.Identifier { return deleteResponseIdentifier }

// DeleteRequest is the primitive RFC 4511 DelRequest protocol operation.
type DeleteRequest struct{ Entry LDAPDN }

//revive:disable-next-line:exported
func (*DeleteRequest) ProtocolIdentifier() ber.Identifier { return deleteRequestIdentifier }

// BERPacket returns the delete-request packet.
func (v *DeleteRequest) BERPacket() ber.Packet {
	return ber.Primitive(deleteRequestIdentifier, []byte(v.Entry))
}

//revive:disable-next-line:exported
func (v *DeleteRequest) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r)
	decoded := DeleteRequest{Entry: d.ReadAs[LDAPDN](deleteRequestIdentifier)}
	if err := d.Err(); err != nil {
		return err
	}
	*v = decoded
	return nil
}

// DeleteResponse is the terminal LDAPResult for DeleteRequest.
type DeleteResponse struct{ Result LDAPResult }

// LDAPResult returns the operation result carried by v.
func (v DeleteResponse) LDAPResult() LDAPResult { return v.Result }

// BERPacket returns the delete-response packet.
func (v DeleteResponse) BERPacket() ber.Packet {
	return resultResponsePacket(deleteResponseIdentifier, v.Result)
}

//revive:disable-next-line:exported
func (v *DeleteResponse) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r)
	decoded := DeleteResponse{Result: d.ReadAs[LDAPResult](deleteResponseIdentifier)}
	if err := d.Err(); err != nil {
		return err
	}
	*v = decoded
	return nil
}

// DeleteResponsePattern returns the terminal response pattern for DeleteRequest.
func DeleteResponsePattern() protocol.ResponsePattern[DeleteResponse] { return deleteResponsePattern }

// NewDeleteOperation creates a complete Delete request declaration.
func NewDeleteOperation(request *DeleteRequest, controls []ber.Packeter) (protocol.Operation[DeleteResponse], error) {
	if request == nil {
		return protocol.Operation[DeleteResponse]{}, errors.New("arden: nil DeleteRequest")
	}
	op := protocol.Operation[DeleteResponse]{Protocol: request, Controls: slices.Clone(controls), Responses: DeleteResponsePattern(), Cancellation: protocol.CancelDrain, Metadata: protocol.OperationMetadata{Label: "ldap.delete"}}
	if err := op.Validate(); err != nil {
		return protocol.Operation[DeleteResponse]{}, err
	}
	return op, nil
}
