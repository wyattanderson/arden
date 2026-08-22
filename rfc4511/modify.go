package rfc4511

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ber"
)

var (
	modifyRequestIdentifier  = applicationConstructed(6)
	modifyResponseIdentifier = applicationConstructed(7)
	modifyResponsePattern    = mustResponsePattern(arden.ResponseSpec{Complete: []ber.Identifier{modifyResponseIdentifier}})
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

// Change is one ModifyRequest change record.
type Change struct {
	Operation    ModifyOperation
	Modification PartialAttribute
	Extensions   []UnknownField
}

//revive:disable-next-line:exported
func (v Change) AppendBER(dst []byte) ([]byte, error) {
	start := len(dst)
	contents, err := ber.AppendEnumerated(nil, int64(v.Operation))
	if err != nil {
		return dst[:start], err
	}
	if contents, err = v.Modification.AppendBER(contents); err != nil {
		return dst[:start], err
	}
	if contents, err = appendUnknownFields(contents, v.Extensions); err != nil {
		return dst[:start], err
	}
	encoded, err := ber.AppendSequence(dst, contents)
	if err != nil {
		return dst[:start], err
	}
	return encoded, nil
}

//revive:disable-next-line:exported
func (v *Change) UnmarshalBER(r *ber.Reader) error {
	if v == nil {
		return nilReceiver("Change")
	}
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

//revive:disable-next-line:exported
func (v *ModifyRequest) AppendBER(dst []byte) ([]byte, error) {
	start := len(dst)
	if v == nil {
		return dst, errors.New("rfc4511: nil ModifyRequest")
	}
	contents, err := ber.AppendOctetString(nil, v.Object)
	if err != nil {
		return dst[:start], err
	}
	changes := make([]byte, 0)
	for i := range v.Changes {
		changes, err = v.Changes[i].AppendBER(changes)
		if err != nil {
			return dst[:start], fmt.Errorf("rfc4511: ModifyRequest change %d: %w", i, err)
		}
	}
	if contents, err = ber.AppendSequence(contents, changes); err != nil {
		return dst[:start], err
	}
	if contents, err = appendUnknownFields(contents, v.Extensions); err != nil {
		return dst[:start], err
	}
	encoded, err := ber.AppendConstructed(dst, modifyRequestIdentifier, contents)
	if err != nil {
		return dst[:start], err
	}
	return encoded, nil
}

//revive:disable-next-line:exported
func (v *ModifyRequest) UnmarshalBER(r *ber.Reader) error {
	if v == nil {
		return nilReceiver("ModifyRequest")
	}
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
	*v = ModifyRequest{Object: LDAPDN(bytes.Clone(object)), Changes: changes, Extensions: extensions}
	return nil
}

// ModifyResponse is the terminal LDAPResult for ModifyRequest.
type ModifyResponse struct{ Result LDAPResult }

//revive:disable-next-line:exported
func (v ModifyResponse) AppendBER(dst []byte) ([]byte, error) {
	return appendResultResponse(dst, modifyResponseIdentifier, v.Result)
}

//revive:disable-next-line:exported
func (v *ModifyResponse) UnmarshalBER(r *ber.Reader) error {
	if v == nil {
		return nilReceiver("ModifyResponse")
	}
	result, err := decodeResultResponse(r, modifyResponseIdentifier)
	if err != nil {
		return err
	}
	*v = ModifyResponse{Result: result}
	return nil
}

// ModifyResponsePattern returns the terminal response pattern for ModifyRequest.
func ModifyResponsePattern() arden.ResponsePattern { return modifyResponsePattern }

// NewModifyOperation creates a complete Modify request declaration.
func NewModifyOperation(request *ModifyRequest, controls []ber.Marshaler) (arden.Operation, error) {
	if request == nil {
		return arden.Operation{}, errors.New("rfc4511: nil ModifyRequest")
	}
	op := arden.Operation{Protocol: request, Controls: slices.Clone(controls), Responses: ModifyResponsePattern(), Cancellation: arden.CancelDrain, Metadata: arden.OperationMetadata{Label: "ldap.modify"}}
	if err := op.Validate(); err != nil {
		return arden.Operation{}, err
	}
	return op, nil
}
