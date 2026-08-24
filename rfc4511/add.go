package rfc4511

import (
	"errors"
	"fmt"
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

// AppendBER appends exactly one AddRequest protocolOp, without an LDAPMessage
// envelope, message ID, or controls.
//
//revive:disable-next-line:exported
func (v *AddRequest) AppendBER(dst []byte) ([]byte, error) {
	start := len(dst)
	if v == nil {
		return dst, errors.New("arden: nil AddRequest")
	}
	contents, err := ber.AppendOctetString(nil, []byte(v.Entry))
	if err != nil {
		return dst[:start], err
	}
	attributeList := make([]byte, 0)
	for i := range v.Attributes {
		attributeList, err = v.Attributes[i].AppendBER(attributeList)
		if err != nil {
			return dst[:start], fmt.Errorf("arden: AddRequest attribute %d: %w", i, err)
		}
	}
	contents, err = ber.AppendSequence(contents, attributeList)
	if err != nil {
		return dst[:start], err
	}
	contents, err = appendUnknownFields(contents, v.Extensions)
	if err != nil {
		return dst[:start], err
	}
	encoded, err := ber.AppendConstructed(dst, addRequestIdentifier, contents)
	if err != nil {
		return dst[:start], err
	}
	return encoded, nil
}

// UnmarshalBER decodes one AddRequest protocolOp. Retained value bytes are
// copied, and v is unchanged if decoding fails.
//
//revive:disable-next-line:exported
func (v *AddRequest) UnmarshalBER(r *ber.Reader) error {
	if v == nil {
		return errors.New("arden: nil AddRequest receiver")
	}
	contents, err := r.Constructed(addRequestIdentifier)
	if err != nil {
		return err
	}
	entry, err := contents.OctetString()
	if err != nil {
		return err
	}
	attributeList, err := contents.Sequence()
	if err != nil {
		return err
	}
	var attributes []Attribute
	for !attributeList.Empty() {
		var attribute Attribute
		if err := attribute.UnmarshalBER(attributeList); err != nil {
			return err
		}
		attributes = append(attributes, attribute)
	}
	extensions, err := decodeUnknownFields(contents)
	if err != nil {
		return err
	}
	*v = AddRequest{
		Entry:      LDAPDN(string(entry)),
		Attributes: attributes,
		Extensions: extensions,
	}
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

//revive:disable-next-line:exported
func (v AddResponse) AppendBER(dst []byte) ([]byte, error) {
	start := len(dst)
	contents, err := v.Result.appendContents(nil)
	if err != nil {
		return dst[:start], err
	}
	encoded, err := ber.AppendConstructed(dst, addResponseIdentifier, contents)
	if err != nil {
		return dst[:start], err
	}
	return encoded, nil
}

//revive:disable-next-line:exported
func (v *AddResponse) UnmarshalBER(r *ber.Reader) error {
	if v == nil {
		return errors.New("arden: nil AddResponse receiver")
	}
	contents, err := r.Constructed(addResponseIdentifier)
	if err != nil {
		return err
	}
	result, err := decodeLDAPResultContents(contents)
	if err != nil {
		return err
	}
	*v = AddResponse{Result: result}
	return nil
}

// AddResponsePattern returns the immutable standard terminal response pattern
// for AddRequest. It is safe to reuse concurrently.
func AddResponsePattern() protocol.ResponsePattern[AddResponse] { return addResponsePattern }

// NewAddOperation creates the complete request declaration for an Add. It
// clones the control slice but not the caller-owned request or control values;
// the connection validates and encodes them before concurrent use.
func NewAddOperation(request *AddRequest, controls []ber.Marshaler) (protocol.Operation[AddResponse], error) {
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
