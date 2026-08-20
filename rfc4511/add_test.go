package rfc4511_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
)

func TestAddRequestWireRoundTrip(t *testing.T) {
	request := &rfc4511.AddRequest{
		Entry: rfc4511.LDAPDN("cn=Jane,dc=example,dc=com"),
		Attributes: []rfc4511.Attribute{
			{
				Type: rfc4511.AttributeDescription("objectClass"),
				Values: []rfc4511.AttributeValue{
					rfc4511.AttributeValue("top"),
					rfc4511.AttributeValue("person"),
				},
			},
			{
				Type:   rfc4511.AttributeDescription("jpegPhoto"),
				Values: []rfc4511.AttributeValue{{0x00, 0xff, 0x80}, {}},
			},
		},
	}

	encoded, err := request.AppendBER([]byte{0xaa})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x68, 0x51,
		0x04, 0x19, 'c', 'n', '=', 'J', 'a', 'n', 'e', ',', 'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
		0x30, 0x34,
		0x30, 0x1c, 0x04, 0x0b, 'o', 'b', 'j', 'e', 'c', 't', 'C', 'l', 'a', 's', 's', 0x31, 0x0d, 0x04, 0x03, 't', 'o', 'p', 0x04, 0x06, 'p', 'e', 'r', 's', 'o', 'n',
		0x30, 0x14, 0x04, 0x09, 'j', 'p', 'e', 'g', 'P', 'h', 'o', 't', 'o', 0x31, 0x07, 0x04, 0x03, 0x00, 0xff, 0x80, 0x04, 0x00,
	}
	if !bytes.Equal(encoded, append([]byte{0xaa}, want...)) {
		t.Fatalf("AddRequest encoding = %x, want %x", encoded, append([]byte{0xaa}, want...))
	}

	r, err := ber.NewReader(want, ber.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var decoded rfc4511.AddRequest
	if err := decoded.UnmarshalBER(r); err != nil {
		t.Fatal(err)
	}
	if err := r.RequireEmpty(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, *request) {
		t.Fatalf("decoded AddRequest = %#v, want %#v", decoded, *request)
	}

	for i := range encoded {
		encoded[i] = 0
	}
	if got := string(decoded.Entry); got != "cn=Jane,dc=example,dc=com" {
		t.Fatalf("decoded Entry aliases input: %q", got)
	}
	if got := decoded.Attributes[1].Values[0]; !bytes.Equal(got, []byte{0x00, 0xff, 0x80}) {
		t.Fatalf("decoded binary value aliases input: %x", got)
	}
}

func TestAddRequestRejectsInvalidAttributeAtomically(t *testing.T) {
	dst := []byte{0xde, 0xad}
	request := &rfc4511.AddRequest{
		Attributes: []rfc4511.Attribute{{Type: rfc4511.AttributeDescription("cn")}},
	}
	got, err := request.AppendBER(dst)
	if err == nil {
		t.Fatal("AppendBER succeeded without Attribute values")
	}
	if !bytes.Equal(got, dst) {
		t.Fatalf("AppendBER changed destination on error: %x", got)
	}

	prior := rfc4511.AddRequest{Entry: rfc4511.LDAPDN("cn=keep")}
	malformed := []byte{0x68, 0x09, 0x04, 0x00, 0x30, 0x05, 0x30, 0x03, 0x04, 0x01, 'c'}
	r, err := ber.NewReader(malformed, ber.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := prior.UnmarshalBER(r); err == nil {
		t.Fatal("UnmarshalBER accepted Attribute with no SET OF values")
	}
	if got := string(prior.Entry); got != "cn=keep" {
		t.Fatalf("failed unmarshal changed receiver: %#v", prior)
	}
}

func TestAddResponsePreservesUnknownResultCode(t *testing.T) {
	encoded := []byte{0x69, 0x0c, 0x0a, 0x01, 0x46, 0x04, 0x00, 0x04, 0x05, 't', 'a', 'k', 'e', 'n'}
	r, err := ber.NewReader(encoded, ber.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var response rfc4511.AddResponse
	if err := response.UnmarshalBER(r); err != nil {
		t.Fatal(err)
	}
	if response.Result.ResultCode != rfc4511.ResultCode(70) {
		t.Fatalf("ResultCode = %d, want unknown 70", response.Result.ResultCode)
	}
	if got := string(response.Result.DiagnosticMessage); got != "taken" {
		t.Fatalf("DiagnosticMessage = %q", got)
	}
	roundTrip, err := response.AppendBER(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(roundTrip, encoded) {
		t.Fatalf("AddResponse round trip = %x, want %x", roundTrip, encoded)
	}
}

func TestAddResponseReferralValidationAndReceiverAtomicity(t *testing.T) {
	dst := []byte{0xde, 0xad}
	response := rfc4511.AddResponse{Result: rfc4511.LDAPResult{ResultCode: rfc4511.ResultReferral}}
	got, err := response.AppendBER(dst)
	if err == nil {
		t.Fatal("AppendBER accepted referral without URI")
	}
	if !bytes.Equal(got, dst) {
		t.Fatalf("AppendBER changed destination on error: %x", got)
	}

	prior := rfc4511.AddResponse{Result: rfc4511.LDAPResult{ResultCode: rfc4511.ResultSuccess}}
	malformed := []byte{0x69, 0x07, 0x0a, 0x01, 0x0a, 0x04, 0x00, 0x04, 0x00}
	r, err := ber.NewReader(malformed, ber.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := prior.UnmarshalBER(r); err == nil {
		t.Fatal("UnmarshalBER accepted referral result without referral")
	}
	if prior.Result.ResultCode != rfc4511.ResultSuccess {
		t.Fatalf("failed unmarshal changed receiver: %#v", prior)
	}
}

func TestAddRequestPreservesTrailingExtension(t *testing.T) {
	encoded := []byte{
		0x68, 0x13,
		0x04, 0x00,
		0x30, 0x0c,
		0x30, 0x0a, 0x04, 0x02, 'c', 'n', 0x31, 0x04, 0x04, 0x02, 'j', 's',
		0x83, 0x01, 0x7f,
	}
	r, err := ber.NewReader(encoded, ber.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var request rfc4511.AddRequest
	if err := request.UnmarshalBER(r); err != nil {
		t.Fatal(err)
	}
	if len(request.Extensions) != 1 || request.Extensions[0].Identifier() != (ber.Identifier{Class: ber.ClassContextSpecific, Number: 3}) {
		t.Fatalf("Extensions = %#v", request.Extensions)
	}
	if got := request.Extensions[0].Bytes(); !bytes.Equal(got, []byte{0x83, 0x01, 0x7f}) {
		t.Fatalf("extension = %x", got)
	}
	roundTrip, err := request.AppendBER(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(roundTrip, encoded) {
		t.Fatalf("AddRequest extension round trip = %x, want %x", roundTrip, encoded)
	}
}

func TestNewAddOperationUsesStandardPatternAndClonesControlSlice(t *testing.T) {
	controls := []ber.Marshaler{rawControl{}}
	op, err := rfc4511.NewAddOperation(&rfc4511.AddRequest{}, controls)
	if err != nil {
		t.Fatal(err)
	}
	controls[0] = nil
	if err := op.Validate(); err != nil {
		t.Fatalf("cloned controls changed after construction: %v", err)
	}
	if op.Cancellation != arden.CancelDrain || op.Metadata.Label != "ldap.add" {
		t.Fatalf("operation policy = %#v", op)
	}
	if got := op.Responses.Classify(rfc4511.AddResponseIdentifier()); got != arden.ClassificationComplete {
		t.Fatalf("Add response classification = %v", got)
	}
}

type rawControl struct{}

func (rawControl) AppendBER(dst []byte) ([]byte, error) { return append(dst, 0x30, 0x00), nil }

func TestRFCAndExtensionContractsArePublic(t *testing.T) {
	var _ arden.ProtocolOperation = (*rfc4511.AddRequest)(nil)
	var _ ber.Unmarshaler = (*rfc4511.AddResponse)(nil)
	var _ ber.Marshaler = rfc4511.Attribute{}

	_, err := rfc4511.NewAddOperation(nil, nil)
	if err == nil || err.Error() != "rfc4511: nil AddRequest" {
		t.Fatalf("nil request error = %v", err)
	}
}
