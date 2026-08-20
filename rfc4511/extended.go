package rfc4511

import (
	"errors"
	"fmt"
	"slices"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ber"
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
	extendedResponsePattern             = mustResponsePattern(arden.ResponseSpec{
		Continue: []ber.Identifier{intermediateResponseIdentifier},
		Complete: []ber.Identifier{extendedResponseIdentifier},
	})
)

func ExtendedRequestIdentifier() ber.Identifier      { return extendedRequestIdentifier }
func ExtendedResponseIdentifier() ber.Identifier     { return extendedResponseIdentifier }
func IntermediateResponseIdentifier() ber.Identifier { return intermediateResponseIdentifier }

// ExtendedRequest is the RFC 4511 ExtendedRequest protocol operation.
type ExtendedRequest struct {
	Name       LDAPOID
	Value      []byte
	HasValue   bool
	Extensions []UnknownField
}

func (*ExtendedRequest) ProtocolIdentifier() ber.Identifier { return extendedRequestIdentifier }
func (v *ExtendedRequest) AppendBER(dst []byte) ([]byte, error) {
	start := len(dst)
	if v == nil {
		return dst, errors.New("rfc4511: nil ExtendedRequest")
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
			return fmt.Errorf("rfc4511: duplicate or out-of-order ExtendedRequest field %s", id)
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

func (v ExtendedResponse) AppendBER(dst []byte) ([]byte, error) {
	start := len(dst)
	if len(v.Result.Extensions) != 0 {
		return dst, errors.New("rfc4511: ExtendedResponse result extensions must be response extensions")
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
			return fmt.Errorf("rfc4511: duplicate or out-of-order ExtendedResponse field %s", id)
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
			return fmt.Errorf("rfc4511: duplicate or out-of-order IntermediateResponse field %s", id)
		}
		decoded.Extensions, err = decodeUnknownFields(contents)
		if err != nil {
			return err
		}
	}
	*v = decoded
	return nil
}

func ExtendedResponsePattern() arden.ResponsePattern { return extendedResponsePattern }
func NewExtendedOperation(request *ExtendedRequest, controls []ber.Marshaler) (arden.Operation, error) {
	if request == nil {
		return arden.Operation{}, errors.New("rfc4511: nil ExtendedRequest")
	}
	op := arden.Operation{Protocol: request, Controls: slices.Clone(controls), Responses: ExtendedResponsePattern(), Cancellation: arden.CancelDrain, Metadata: arden.OperationMetadata{Label: "ldap.extended"}}
	if err := op.Validate(); err != nil {
		return arden.Operation{}, err
	}
	return op, nil
}

// NoticeOfDisconnectionOID returns the responseName identifying the RFC 4511
// unsolicited Notice of Disconnection extended response.
func NoticeOfDisconnectionOID() LDAPOID { return LDAPOID("1.3.6.1.4.1.1466.20036") }
