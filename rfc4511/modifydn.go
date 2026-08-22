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
	modifyDNRequestIdentifier     = applicationConstructed(12)
	modifyDNResponseIdentifier    = applicationConstructed(13)
	modifyDNNewSuperiorIdentifier = contextPrimitive(0)
	modifyDNResponsePattern       = mustResponsePattern(arden.ResponseSpec{Complete: []ber.Identifier{modifyDNResponseIdentifier}})
)

// ModifyDNRequestIdentifier returns the application identifier for ModifyDNRequest.
func ModifyDNRequestIdentifier() ber.Identifier { return modifyDNRequestIdentifier }

// ModifyDNResponseIdentifier returns the application identifier for ModifyDNResponse.
func ModifyDNResponseIdentifier() ber.Identifier { return modifyDNResponseIdentifier }

// ModifyDNRequest is the RFC 4511 ModifyDNRequest protocol operation.
type ModifyDNRequest struct {
	Entry        LDAPDN
	NewRDN       RelativeLDAPDN
	DeleteOldRDN bool
	NewSuperior  *LDAPDN
	Extensions   []UnknownField
}

//revive:disable-next-line:exported
func (*ModifyDNRequest) ProtocolIdentifier() ber.Identifier { return modifyDNRequestIdentifier }

//revive:disable-next-line:exported
func (v *ModifyDNRequest) AppendBER(dst []byte) ([]byte, error) {
	start := len(dst)
	if v == nil {
		return dst, errors.New("rfc4511: nil ModifyDNRequest")
	}
	contents, err := ber.AppendOctetString(nil, v.Entry)
	if err != nil {
		return dst[:start], err
	}
	if contents, err = ber.AppendOctetString(contents, v.NewRDN); err != nil {
		return dst[:start], err
	}
	if contents, err = ber.AppendBoolean(contents, v.DeleteOldRDN); err != nil {
		return dst[:start], err
	}
	if v.NewSuperior != nil {
		contents, err = appendImplicitOctets(contents, modifyDNNewSuperiorIdentifier, *v.NewSuperior)
		if err != nil {
			return dst[:start], err
		}
	}
	if contents, err = appendUnknownFields(contents, v.Extensions); err != nil {
		return dst[:start], err
	}
	encoded, err := ber.AppendConstructed(dst, modifyDNRequestIdentifier, contents)
	if err != nil {
		return dst[:start], err
	}
	return encoded, nil
}

//revive:disable-next-line:exported
func (v *ModifyDNRequest) UnmarshalBER(r *ber.Reader) error {
	if v == nil {
		return nilReceiver("ModifyDNRequest")
	}
	contents, err := r.Constructed(modifyDNRequestIdentifier)
	if err != nil {
		return err
	}
	entry, err := contents.OctetString()
	if err != nil {
		return err
	}
	newRDN, err := contents.OctetString()
	if err != nil {
		return err
	}
	deleteOldRDN, err := contents.Boolean()
	if err != nil {
		return err
	}
	decoded := ModifyDNRequest{Entry: LDAPDN(bytes.Clone(entry)), NewRDN: RelativeLDAPDN(bytes.Clone(newRDN)), DeleteOldRDN: deleteOldRDN}
	if !contents.Empty() {
		id, err := contents.PeekIdentifier()
		if err != nil {
			return err
		}
		if id == modifyDNNewSuperiorIdentifier {
			value, err := readImplicitOctets(contents, modifyDNNewSuperiorIdentifier)
			if err != nil {
				return err
			}
			newSuperior := LDAPDN(value)
			decoded.NewSuperior = &newSuperior
		}
	}
	if !contents.Empty() {
		id, err := contents.PeekIdentifier()
		if err != nil {
			return err
		}
		if id == modifyDNNewSuperiorIdentifier {
			return fmt.Errorf("rfc4511: duplicate ModifyDN newSuperior field %s", id)
		}
		decoded.Extensions, err = decodeUnknownFields(contents)
		if err != nil {
			return err
		}
	}
	*v = decoded
	return nil
}

// ModifyDNResponse is the terminal LDAPResult for ModifyDNRequest.
type ModifyDNResponse struct{ Result LDAPResult }

//revive:disable-next-line:exported
func (v ModifyDNResponse) AppendBER(dst []byte) ([]byte, error) {
	return appendResultResponse(dst, modifyDNResponseIdentifier, v.Result)
}

//revive:disable-next-line:exported
func (v *ModifyDNResponse) UnmarshalBER(r *ber.Reader) error {
	if v == nil {
		return nilReceiver("ModifyDNResponse")
	}
	result, err := decodeResultResponse(r, modifyDNResponseIdentifier)
	if err != nil {
		return err
	}
	*v = ModifyDNResponse{Result: result}
	return nil
}

// ModifyDNResponsePattern returns the terminal response pattern for ModifyDNRequest.
func ModifyDNResponsePattern() arden.ResponsePattern { return modifyDNResponsePattern }

// NewModifyDNOperation creates a complete Modify DN request declaration.
func NewModifyDNOperation(request *ModifyDNRequest, controls []ber.Marshaler) (arden.Operation, error) {
	if request == nil {
		return arden.Operation{}, errors.New("rfc4511: nil ModifyDNRequest")
	}
	op := arden.Operation{Protocol: request, Controls: slices.Clone(controls), Responses: ModifyDNResponsePattern(), Cancellation: arden.CancelDrain, Metadata: arden.OperationMetadata{Label: "ldap.modify-dn"}}
	if err := op.Validate(); err != nil {
		return arden.Operation{}, err
	}
	return op, nil
}
