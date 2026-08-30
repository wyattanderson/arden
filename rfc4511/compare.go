package rfc4511

import (
	"errors"
	"slices"

	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/protocol"
)

var (
	compareRequestIdentifier  = applicationConstructed(14)
	compareResponseIdentifier = applicationConstructed(15)
	compareResponsePattern    = mustResponsePattern[CompareResponse](protocol.ResponseSpec{Complete: []ber.Identifier{compareResponseIdentifier}})
)

// CompareRequestIdentifier returns the application identifier for CompareRequest.
func CompareRequestIdentifier() ber.Identifier { return compareRequestIdentifier }

// CompareResponseIdentifier returns the application identifier for CompareResponse.
func CompareResponseIdentifier() ber.Identifier { return compareResponseIdentifier }

// CompareRequest is the RFC 4511 CompareRequest protocol operation.
type CompareRequest struct {
	Entry      LDAPDN
	Assertion  AttributeValueAssertion
	Extensions []UnknownField
}

//revive:disable-next-line:exported
func (*CompareRequest) ProtocolIdentifier() ber.Identifier { return compareRequestIdentifier }

//revive:disable-next-line:exported
func (v *CompareRequest) AppendBER(dst []byte) ([]byte, error) {
	start := len(dst)
	contents, err := ber.AppendOctetString(nil, []byte(v.Entry))
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

//revive:disable-next-line:exported
func (v *CompareRequest) UnmarshalBER(r *ber.Reader) error {
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
	*v = CompareRequest{Entry: LDAPDN(string(entry)), Assertion: assertion, Extensions: extensions}
	return nil
}

// CompareResponse is the terminal LDAPResult for CompareRequest. Its
// ResultCode may be ResultCompareTrue or ResultCompareFalse as well as errors.
type CompareResponse struct{ Result LDAPResult }

// LDAPResult returns the operation result carried by v.
func (v CompareResponse) LDAPResult() LDAPResult { return v.Result }

//revive:disable-next-line:exported
func (v CompareResponse) AppendBER(dst []byte) ([]byte, error) {
	return appendResultResponse(dst, compareResponseIdentifier, v.Result)
}

//revive:disable-next-line:exported
func (v *CompareResponse) UnmarshalBER(r *ber.Reader) error {
	result, err := decodeResultResponse(r, compareResponseIdentifier)
	if err != nil {
		return err
	}
	*v = CompareResponse{Result: result}
	return nil
}

// CompareResponsePattern returns the terminal response pattern for CompareRequest.
func CompareResponsePattern() protocol.ResponsePattern[CompareResponse] {
	return compareResponsePattern
}

// NewCompareOperation creates a complete Compare request declaration.
func NewCompareOperation(request *CompareRequest, controls []ber.Marshaler) (protocol.Operation[CompareResponse], error) {
	if request == nil {
		return protocol.Operation[CompareResponse]{}, errors.New("arden: nil CompareRequest")
	}
	op := protocol.Operation[CompareResponse]{Protocol: request, Controls: slices.Clone(controls), Responses: CompareResponsePattern(), Cancellation: protocol.CancelDrain, Metadata: protocol.OperationMetadata{Label: "ldap.compare"}}
	if err := op.Validate(); err != nil {
		return protocol.Operation[CompareResponse]{}, err
	}
	return op, nil
}
