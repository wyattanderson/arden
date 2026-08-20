package rfc4511

import (
	"bytes"
	"errors"
	"slices"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ber"
)

var (
	compareRequestIdentifier  = applicationConstructed(14)
	compareResponseIdentifier = applicationConstructed(15)
	compareResponsePattern    = mustResponsePattern(arden.ResponseSpec{Complete: []ber.Identifier{compareResponseIdentifier}})
)

func CompareRequestIdentifier() ber.Identifier  { return compareRequestIdentifier }
func CompareResponseIdentifier() ber.Identifier { return compareResponseIdentifier }

// CompareRequest is the RFC 4511 CompareRequest protocol operation.
type CompareRequest struct {
	Entry      LDAPDN
	Assertion  AttributeValueAssertion
	Extensions []UnknownField
}

func (*CompareRequest) ProtocolIdentifier() ber.Identifier { return compareRequestIdentifier }
func (v *CompareRequest) AppendBER(dst []byte) ([]byte, error) {
	start := len(dst)
	if v == nil {
		return dst, errors.New("rfc4511: nil CompareRequest")
	}
	contents, err := ber.AppendOctetString(nil, v.Entry)
	if err != nil {
		return dst[:start], err
	}
	if contents, err = v.Assertion.AppendBER(contents); err != nil {
		return dst[:start], err
	}
	if contents, err = appendUnknownFields(contents, v.Extensions); err != nil {
		return dst[:start], err
	}
	encoded, err := ber.AppendConstructed(dst, compareRequestIdentifier, contents)
	if err != nil {
		return dst[:start], err
	}
	return encoded, nil
}
func (v *CompareRequest) UnmarshalBER(r *ber.Reader) error {
	if v == nil {
		return nilReceiver("CompareRequest")
	}
	contents, err := r.Constructed(compareRequestIdentifier)
	if err != nil {
		return err
	}
	entry, err := contents.OctetString()
	if err != nil {
		return err
	}
	var assertion AttributeValueAssertion
	if err := assertion.UnmarshalBER(contents); err != nil {
		return err
	}
	extensions, err := decodeUnknownFields(contents)
	if err != nil {
		return err
	}
	*v = CompareRequest{Entry: LDAPDN(bytes.Clone(entry)), Assertion: assertion, Extensions: extensions}
	return nil
}

// CompareResponse is the terminal LDAPResult for CompareRequest. Its
// ResultCode may be ResultCompareTrue or ResultCompareFalse as well as errors.
type CompareResponse struct{ Result LDAPResult }

func (v CompareResponse) AppendBER(dst []byte) ([]byte, error) {
	return appendResultResponse(dst, compareResponseIdentifier, v.Result)
}
func (v *CompareResponse) UnmarshalBER(r *ber.Reader) error {
	if v == nil {
		return nilReceiver("CompareResponse")
	}
	result, err := decodeResultResponse(r, compareResponseIdentifier)
	if err != nil {
		return err
	}
	*v = CompareResponse{Result: result}
	return nil
}

func CompareResponsePattern() arden.ResponsePattern { return compareResponsePattern }
func NewCompareOperation(request *CompareRequest, controls []ber.Marshaler) (arden.Operation, error) {
	if request == nil {
		return arden.Operation{}, errors.New("rfc4511: nil CompareRequest")
	}
	op := arden.Operation{Protocol: request, Controls: slices.Clone(controls), Responses: CompareResponsePattern(), Cancellation: arden.CancelDrain, Metadata: arden.OperationMetadata{Label: "ldap.compare"}}
	if err := op.Validate(); err != nil {
		return arden.Operation{}, err
	}
	return op, nil
}
