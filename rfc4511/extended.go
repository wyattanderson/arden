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

// BERPacket returns the extended-request packet.
func (v *ExtendedRequest) BERPacket() ber.Packet {
	request := ber.Constructed(extendedRequestIdentifier).
		Add(implicitOctetsPacket(extendedRequestNameIdentifier, v.Name))
	if v.HasValue {
		request.Add(implicitOctetsPacket(extendedRequestValueIdentifier, v.Value))
	}
	return request.Add(v.Extensions...).BERPacket()
}

//revive:disable-next-line:exported
func (v *ExtendedRequest) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r).Constructed(extendedRequestIdentifier)
	decoded := ExtendedRequest{Name: d.ReadAs[LDAPOID](extendedRequestNameIdentifier)}
	if d.NextIs(extendedRequestValueIdentifier) {
		decoded.Value = d.Primitive[[]byte](extendedRequestValueIdentifier)
		decoded.HasValue = true
	}
	decoded.Extensions = d.Extensions[UnknownField](extendedRequestNameIdentifier, extendedRequestValueIdentifier)
	if err := d.End(); err != nil {
		return err
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

// BERPacket returns the extended-response packet.
func (v ExtendedResponse) BERPacket() ber.Packet {
	response := ber.Constructed(extendedResponseIdentifier)
	v.Result.addPrefix(response)
	if v.HasResponseName {
		response.Add(implicitOctetsPacket(extendedResponseNameIdentifier, v.ResponseName))
	}
	if v.HasResponseValue {
		response.Add(implicitOctetsPacket(extendedResponseValueIdentifier, v.ResponseValue))
	}
	return response.Add(v.Extensions...).BERPacket()
}

//revive:disable-next-line:exported
func (v *ExtendedResponse) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r).Constructed(extendedResponseIdentifier)
	decoded := ExtendedResponse{Result: d.Embed[LDAPResult]()}
	if d.NextIs(extendedResponseNameIdentifier) {
		decoded.ResponseName = d.ReadAs[LDAPOID](extendedResponseNameIdentifier)
		decoded.HasResponseName = true
	}
	if d.NextIs(extendedResponseValueIdentifier) {
		decoded.ResponseValue = d.Primitive[[]byte](extendedResponseValueIdentifier)
		decoded.HasResponseValue = true
	}
	decoded.Extensions = d.Extensions[UnknownField](extendedResponseNameIdentifier, extendedResponseValueIdentifier)
	if err := d.End(); err != nil {
		return err
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

// BERPacket returns the intermediate-response packet.
func (v IntermediateResponse) BERPacket() ber.Packet {
	response := ber.Constructed(intermediateResponseIdentifier)
	if v.HasResponseName {
		response.Add(implicitOctetsPacket(intermediateResponseNameIdentifier, v.ResponseName))
	}
	if v.HasResponseValue {
		response.Add(implicitOctetsPacket(intermediateResponseValueIdentifier, v.ResponseValue))
	}
	return response.Add(v.Extensions...).BERPacket()
}

//revive:disable-next-line:exported
func (v *IntermediateResponse) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r).Constructed(intermediateResponseIdentifier)
	var decoded IntermediateResponse
	if d.NextIs(intermediateResponseNameIdentifier) {
		decoded.ResponseName = d.ReadAs[LDAPOID](intermediateResponseNameIdentifier)
		decoded.HasResponseName = true
	}
	if d.NextIs(intermediateResponseValueIdentifier) {
		decoded.ResponseValue = d.Primitive[[]byte](intermediateResponseValueIdentifier)
		decoded.HasResponseValue = true
	}
	decoded.Extensions = d.Extensions[UnknownField](intermediateResponseNameIdentifier, intermediateResponseValueIdentifier)
	if err := d.End(); err != nil {
		return err
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
	d := ber.NewDecoder(r)
	id := d.PeekIdentifier()
	var decoded ExtendedResultValue
	switch id {
	case intermediateResponseIdentifier:
		decoded = d.Read[IntermediateResponse]()
	case extendedResponseIdentifier:
		decoded = d.Read[ExtendedResponse]()
	default:
		d.Fail(fmt.Errorf("arden: unexpected ExtendedResult identifier %s", id))
	}
	if err := d.Err(); err != nil {
		return err
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
func NewExtendedOperation(request *ExtendedRequest, controls []ber.Packeter) (protocol.Operation[ExtendedResult], error) {
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
