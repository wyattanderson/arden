package rfc4511

import (
	"errors"
	"fmt"
	"slices"

	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/protocol"
)

var (
	extendedRequestIdentifier           = applicationConstructed(23)
	extendedResponseIdentifier          = applicationConstructed(24)
	intermediateResponseIdentifier      = applicationConstructed(25)
	extendedRequestNameIdentifier       = contextPrimitive(0)
	extendedRequestValueIdentifier      = contextPrimitive(1)
	extendedResponseNameIdentifier      = contextPrimitive(10)
	extendedResponseValueIdentifier     = contextPrimitive(11)
	intermediateResponseNameIdentifier  = contextPrimitive(0)
	intermediateResponseValueIdentifier = contextPrimitive(1)
	extendedResponsePattern             = mustResponsePattern[ExtendedResult](protocol.ResponseSpec{
		Continue: []ber.Identifier{intermediateResponseIdentifier},
		Complete: []ber.Identifier{extendedResponseIdentifier},
	})
)

// ExtendedRequestIdentifier returns the application identifier for ExtendedRequest.
func ExtendedRequestIdentifier() ber.Identifier { return extendedRequestIdentifier }

// ExtendedResponseIdentifier returns the application identifier for ExtendedResponse.
func ExtendedResponseIdentifier() ber.Identifier { return extendedResponseIdentifier }

// IntermediateResponseIdentifier returns the application identifier for IntermediateResponse.
func IntermediateResponseIdentifier() ber.Identifier { return intermediateResponseIdentifier }

// ExtendedRequest is the RFC 4511 ExtendedRequest protocol operation.
type ExtendedRequest struct {
	Name       LDAPOID
	Value      []byte
	HasValue   bool
	Extensions []UnknownField
}

//revive:disable-next-line:exported
func (*ExtendedRequest) ProtocolIdentifier() ber.Identifier { return extendedRequestIdentifier }

//revive:disable-next-line:exported
func (v *ExtendedRequest) AppendBER(dst []byte) ([]byte, error) {
	start := len(dst)
	if v == nil {
		return dst, errors.New("arden: nil ExtendedRequest")
	}
	if err := requireNonEmpty("extended request name", v.Name); err != nil {
		return dst, err
	}
	if err := validateLDAPOID(v.Name); err != nil {
		return dst, err
	}
	contents, err := appendImplicitOctets(nil, extendedRequestNameIdentifier, v.Name)
	if err != nil {
		return dst[:start], err
	}
	if v.HasValue {
		contents, err = appendImplicitOctets(contents, extendedRequestValueIdentifier, v.Value)
		if err != nil {
			return dst[:start], err
		}
	}
	contents, err = appendUnknownFields(contents, v.Extensions)
	if err != nil {
		return dst[:start], err
	}
	encoded, err := ber.AppendConstructed(dst, extendedRequestIdentifier, contents)
	if err != nil {
		return dst[:start], err
	}
	return encoded, nil
}

//revive:disable-next-line:exported
func (v *ExtendedRequest) UnmarshalBER(r *ber.Reader) error {
	if v == nil {
		return nilReceiver("ExtendedRequest")
	}
	contents, err := r.Constructed(extendedRequestIdentifier)
	if err != nil {
		return err
	}
	name, err := readImplicitOctets(contents, extendedRequestNameIdentifier)
	if err != nil {
		return err
	}
	if err := requireNonEmpty("extended request name", name); err != nil {
		return err
	}
	if err := validateLDAPOID(name); err != nil {
		return err
	}
	decoded := ExtendedRequest{Name: LDAPOID(name)}
	if !contents.Empty() {
		id, err := contents.PeekIdentifier()
		if err != nil {
			return err
		}
		if id == extendedRequestValueIdentifier {
			decoded.Value, err = readImplicitOctets(contents, extendedRequestValueIdentifier)
			if err != nil {
				return err
			}
			decoded.HasValue = true
		}
	}
	if !contents.Empty() {
		id, err := contents.PeekIdentifier()
		if err != nil {
			return err
		}
		if id == extendedRequestNameIdentifier || id == extendedRequestValueIdentifier {
			return fmt.Errorf("arden: duplicate or out-of-order ExtendedRequest field %s", id)
		}
		decoded.Extensions, err = decodeUnknownFields(contents)
		if err != nil {
			return err
		}
	}
	*v = decoded
	return nil
}

// ExtendedResponse is LDAPResult plus optional extension-defined response
// name and response value. HasResponseValue distinguishes absence from an
// explicitly empty OCTET STRING.
type ExtendedResponse struct {
	Result           LDAPResult
	ResponseName     LDAPOID
	HasResponseName  bool
	ResponseValue    []byte
	HasResponseValue bool
	Extensions       []UnknownField
}

func (ExtendedResponse) isExtendedResultValue() {}

// LDAPResult returns the operation result carried by v.
func (v ExtendedResponse) LDAPResult() LDAPResult { return v.Result }

//revive:disable-next-line:exported
func (v ExtendedResponse) AppendBER(dst []byte) ([]byte, error) {
	start := len(dst)
	if len(v.Result.Extensions) != 0 {
		return dst, errors.New("arden: ExtendedResponse result extensions must be response extensions")
	}
	if v.HasResponseName {
		if err := requireNonEmpty("extended response name", v.ResponseName); err != nil {
			return dst, err
		}
		if err := validateLDAPOID(v.ResponseName); err != nil {
			return dst, err
		}
	}
	contents, err := v.Result.appendPrefix(nil)
	if err != nil {
		return dst[:start], err
	}
	if v.HasResponseName {
		contents, err = appendImplicitOctets(contents, extendedResponseNameIdentifier, v.ResponseName)
		if err != nil {
			return dst[:start], err
		}
	}
	if v.HasResponseValue {
		contents, err = appendImplicitOctets(contents, extendedResponseValueIdentifier, v.ResponseValue)
		if err != nil {
			return dst[:start], err
		}
	}
	contents, err = appendUnknownFields(contents, v.Extensions)
	if err != nil {
		return dst[:start], err
	}
	encoded, err := ber.AppendConstructed(dst, extendedResponseIdentifier, contents)
	if err != nil {
		return dst[:start], err
	}
	return encoded, nil
}

//revive:disable-next-line:exported
func (v *ExtendedResponse) UnmarshalBER(r *ber.Reader) error {
	if v == nil {
		return nilReceiver("ExtendedResponse")
	}
	contents, err := r.Constructed(extendedResponseIdentifier)
	if err != nil {
		return err
	}
	result, err := decodeLDAPResultPrefix(contents)
	if err != nil {
		return err
	}
	decoded := ExtendedResponse{Result: result}
	if !contents.Empty() {
		id, err := contents.PeekIdentifier()
		if err != nil {
			return err
		}
		if id == extendedResponseNameIdentifier {
			value, err := readImplicitOctets(contents, extendedResponseNameIdentifier)
			if err != nil {
				return err
			}
			if err := requireNonEmpty("extended response name", value); err != nil {
				return err
			}
			if err := validateLDAPOID(value); err != nil {
				return err
			}
			decoded.ResponseName, decoded.HasResponseName = LDAPOID(value), true
		}
	}
	if !contents.Empty() {
		id, err := contents.PeekIdentifier()
		if err != nil {
			return err
		}
		if id == extendedResponseValueIdentifier {
			decoded.ResponseValue, err = readImplicitOctets(contents, extendedResponseValueIdentifier)
			if err != nil {
				return err
			}
			decoded.HasResponseValue = true
		}
	}
	if !contents.Empty() {
		id, err := contents.PeekIdentifier()
		if err != nil {
			return err
		}
		if id == referralIdentifier || id == extendedResponseNameIdentifier || id == extendedResponseValueIdentifier {
			return fmt.Errorf("arden: duplicate or out-of-order ExtendedResponse field %s", id)
		}
		decoded.Extensions, err = decodeUnknownFields(contents)
		if err != nil {
			return err
		}
	}
	*v = decoded
	return nil
}

// IntermediateResponse is an extension-defined nonterminal response.
type IntermediateResponse struct {
	ResponseName     LDAPOID
	HasResponseName  bool
	ResponseValue    []byte
	HasResponseValue bool
	Extensions       []UnknownField
}

func (IntermediateResponse) isExtendedResultValue() {}

//revive:disable-next-line:exported
func (v IntermediateResponse) AppendBER(dst []byte) ([]byte, error) {
	start := len(dst)
	if v.HasResponseName {
		if err := requireNonEmpty("intermediate response name", v.ResponseName); err != nil {
			return dst, err
		}
		if err := validateLDAPOID(v.ResponseName); err != nil {
			return dst, err
		}
	}
	contents := make([]byte, 0)
	var err error
	if v.HasResponseName {
		contents, err = appendImplicitOctets(contents, intermediateResponseNameIdentifier, v.ResponseName)
		if err != nil {
			return dst[:start], err
		}
	}
	if v.HasResponseValue {
		contents, err = appendImplicitOctets(contents, intermediateResponseValueIdentifier, v.ResponseValue)
		if err != nil {
			return dst[:start], err
		}
	}
	contents, err = appendUnknownFields(contents, v.Extensions)
	if err != nil {
		return dst[:start], err
	}
	encoded, err := ber.AppendConstructed(dst, intermediateResponseIdentifier, contents)
	if err != nil {
		return dst[:start], err
	}
	return encoded, nil
}

//revive:disable-next-line:exported
func (v *IntermediateResponse) UnmarshalBER(r *ber.Reader) error {
	if v == nil {
		return nilReceiver("IntermediateResponse")
	}
	contents, err := r.Constructed(intermediateResponseIdentifier)
	if err != nil {
		return err
	}
	decoded := IntermediateResponse{}
	if !contents.Empty() {
		id, err := contents.PeekIdentifier()
		if err != nil {
			return err
		}
		if id == intermediateResponseNameIdentifier {
			value, err := readImplicitOctets(contents, intermediateResponseNameIdentifier)
			if err != nil {
				return err
			}
			if err := requireNonEmpty("intermediate response name", value); err != nil {
				return err
			}
			if err := validateLDAPOID(value); err != nil {
				return err
			}
			decoded.ResponseName, decoded.HasResponseName = LDAPOID(value), true
		}
	}
	if !contents.Empty() {
		id, err := contents.PeekIdentifier()
		if err != nil {
			return err
		}
		if id == intermediateResponseValueIdentifier {
			decoded.ResponseValue, err = readImplicitOctets(contents, intermediateResponseValueIdentifier)
			if err != nil {
				return err
			}
			decoded.HasResponseValue = true
		}
	}
	if !contents.Empty() {
		id, err := contents.PeekIdentifier()
		if err != nil {
			return err
		}
		if id == intermediateResponseNameIdentifier || id == intermediateResponseValueIdentifier {
			return fmt.Errorf("arden: duplicate or out-of-order IntermediateResponse field %s", id)
		}
		decoded.Extensions, err = decodeUnknownFields(contents)
		if err != nil {
			return err
		}
	}
	*v = decoded
	return nil
}

// ExtendedResultValue is one of the RFC 4511 response alternatives accepted
// for an ExtendedRequest.
type ExtendedResultValue interface {
	isExtendedResultValue()
}

// ExtendedResult is the typed response CHOICE for an Extended operation. Its
// zero value has no selected alternative.
type ExtendedResult struct {
	value ExtendedResultValue
}

// UnmarshalBER decodes an IntermediateResponse or terminal ExtendedResponse.
// The receiver is unchanged if decoding fails.
func (v *ExtendedResult) UnmarshalBER(r *ber.Reader) error {
	if v == nil {
		return nilReceiver("ExtendedResult")
	}
	id, err := r.PeekIdentifier()
	if err != nil {
		return err
	}
	var decoded ExtendedResultValue
	switch id {
	case intermediateResponseIdentifier:
		var intermediate IntermediateResponse
		if err := intermediate.UnmarshalBER(r); err != nil {
			return err
		}
		decoded = intermediate
	case extendedResponseIdentifier:
		var response ExtendedResponse
		if err := response.UnmarshalBER(r); err != nil {
			return err
		}
		decoded = response
	default:
		return fmt.Errorf("arden: unexpected ExtendedResult identifier %s", id)
	}
	*v = ExtendedResult{value: decoded}
	return nil
}

// Value returns the selected ExtendedResult alternative, or nil for the zero
// value.
func (v ExtendedResult) Value() ExtendedResultValue { return v.value }

// ExtendedResponsePattern returns the continuing and terminal response pattern for ExtendedRequest.
func ExtendedResponsePattern() protocol.ResponsePattern[ExtendedResult] {
	return extendedResponsePattern
}

// NewExtendedOperation creates a complete Extended request declaration.
func NewExtendedOperation(request *ExtendedRequest, controls []ber.Marshaler) (protocol.Operation[ExtendedResult], error) {
	if request == nil {
		return protocol.Operation[ExtendedResult]{}, errors.New("arden: nil ExtendedRequest")
	}
	op := protocol.Operation[ExtendedResult]{Protocol: request, Controls: slices.Clone(controls), Responses: ExtendedResponsePattern(), Cancellation: protocol.CancelDrain, Metadata: protocol.OperationMetadata{Label: "ldap.extended"}}
	if err := op.Validate(); err != nil {
		return protocol.Operation[ExtendedResult]{}, err
	}
	return op, nil
}

// NoticeOfDisconnectionOID returns the responseName identifying the RFC 4511
// unsolicited Notice of Disconnection extended response.
func NoticeOfDisconnectionOID() LDAPOID { return LDAPOID("1.3.6.1.4.1.1466.20036") }
