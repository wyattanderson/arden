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

//revive:disable-next-line:exported
func (v *DeleteRequest) AppendBER(dst []byte) ([]byte, error) {
	if v == nil {
		return dst, errors.New("arden: nil DeleteRequest")
	}
	return ber.AppendPrimitive(dst, deleteRequestIdentifier, []byte(v.Entry))
}

//revive:disable-next-line:exported
func (v *DeleteRequest) UnmarshalBER(r *ber.Reader) error {
	if v == nil {
		return nilReceiver("DeleteRequest")
	}
	entry, err := r.Primitive(deleteRequestIdentifier)
	if err != nil {
		return err
	}
	*v = DeleteRequest{Entry: LDAPDN(string(entry))}
	return nil
}

// DeleteResponse is the terminal LDAPResult for DeleteRequest.
type DeleteResponse struct{ Result LDAPResult }

// LDAPResult returns the operation result carried by v.
func (v DeleteResponse) LDAPResult() LDAPResult { return v.Result }

//revive:disable-next-line:exported
func (v DeleteResponse) AppendBER(dst []byte) ([]byte, error) {
	return appendResultResponse(dst, deleteResponseIdentifier, v.Result)
}

//revive:disable-next-line:exported
func (v *DeleteResponse) UnmarshalBER(r *ber.Reader) error {
	if v == nil {
		return nilReceiver("DeleteResponse")
	}
	result, err := decodeResultResponse(r, deleteResponseIdentifier)
	if err != nil {
		return err
	}
	*v = DeleteResponse{Result: result}
	return nil
}

// DeleteResponsePattern returns the terminal response pattern for DeleteRequest.
func DeleteResponsePattern() protocol.ResponsePattern[DeleteResponse] { return deleteResponsePattern }

// NewDeleteOperation creates a complete Delete request declaration.
func NewDeleteOperation(request *DeleteRequest, controls []ber.Marshaler) (protocol.Operation[DeleteResponse], error) {
	if request == nil {
		return protocol.Operation[DeleteResponse]{}, errors.New("arden: nil DeleteRequest")
	}
	op := protocol.Operation[DeleteResponse]{Protocol: request, Controls: slices.Clone(controls), Responses: DeleteResponsePattern(), Cancellation: protocol.CancelDrain, Metadata: protocol.OperationMetadata{Label: "ldap.delete"}}
	if err := op.Validate(); err != nil {
		return protocol.Operation[DeleteResponse]{}, err
	}
	return op, nil
}
