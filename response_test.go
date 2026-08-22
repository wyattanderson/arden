package arden_test

import (
	"bytes"
	"testing"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ber"
)

func TestParseResponseExposesOwnedEnvelopeViews(t *testing.T) {
	protocol := []byte{0x69, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}
	message := ldapMessage(t, 7, protocol,
		[]byte{0x30, 0x00},
		[]byte{0x83, 0x01, 0x7f},
	)

	response, err := arden.ParseResponse(message, ber.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if response.Header() != (arden.ResponseHeader{
		MessageID:  7,
		ProtocolID: ber.Identifier{Class: ber.ClassApplication, Constructed: true, Number: 9},
	}) {
		t.Fatalf("Header = %#v", response.Header())
	}
	if !bytes.Equal(response.Protocol, protocol) {
		t.Fatalf("Protocol = %x, want %x", response.Protocol, protocol)
	}
	if len(response.Controls) != 1 || !bytes.Equal(response.Controls[0].Raw, []byte{0x30, 0x00}) {
		t.Fatalf("Controls = %#v", response.Controls)
	}
	if len(response.Extensions) != 1 || !bytes.Equal(response.Extensions[0].Raw, []byte{0x83, 0x01, 0x7f}) {
		t.Fatalf("Extensions = %#v", response.Extensions)
	}

	for i := range message {
		message[i] = 0
	}
	if !bytes.Equal(response.Protocol, protocol) {
		t.Fatalf("response aliases parser input: %x", response.Protocol)
	}
	isView := false
	for i := range response.Bytes {
		if &response.Protocol[0] == &response.Bytes[i] {
			isView = true
			break
		}
	}
	if !isView {
		t.Fatal("response protocol is not a view into response-owned bytes")
	}
}

func TestParseResponseRejectsMalformedEnvelopeShapes(t *testing.T) {
	validProtocol := []byte{0x69, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}
	tests := []struct {
		name    string
		message []byte
	}{
		{"missing protocol", []byte{0x30, 0x03, 0x02, 0x01, 0x01}},
		{"negative message ID", ldapMessageRaw([]byte{0x02, 0x01, 0xff}, validProtocol)},
		{"out of range message ID", ldapMessageRaw([]byte{0x02, 0x05, 0x00, 0x80, 0x00, 0x00, 0x00}, validProtocol)},
		{"non application protocol", ldapMessage(t, 1, []byte{0x04, 0x00})},
		{"non sequence control", ldapMessage(t, 1, validProtocol, []byte{0x04, 0x00})},
		{"duplicate controls", ldapMessageRaw(
			[]byte{0x02, 0x01, 0x01},
			validProtocol,
			[]byte{0xa0, 0x02, 0x30, 0x00},
			[]byte{0xa0, 0x02, 0x30, 0x00},
		)},
		{"invalid nested control BER", ldapMessageRaw(
			[]byte{0x02, 0x01, 0x01},
			validProtocol,
			[]byte{0xa0, 0x04, 0x30, 0x02, 0x04, 0x80},
		)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := arden.ParseResponse(test.message, ber.DefaultLimits()); err == nil {
				t.Fatalf("ParseResponse(%x) succeeded", test.message)
			}
		})
	}
}

func ldapMessage(t *testing.T, messageID int64, protocol []byte, controlsAndExtensions ...[]byte) []byte {
	t.Helper()
	messageIDElement, err := ber.AppendInteger(nil, messageID)
	if err != nil {
		t.Fatal(err)
	}
	contents := append([]byte(nil), messageIDElement...)
	contents = append(contents, protocol...)
	if len(controlsAndExtensions) > 0 {
		controls := make([]byte, 0)
		for _, control := range controlsAndExtensions[:1] {
			controls = append(controls, control...)
		}
		contents, err = ber.AppendConstructed(contents, ber.Identifier{
			Class:       ber.ClassContextSpecific,
			Constructed: true,
			Number:      0,
		}, controls)
		if err != nil {
			t.Fatal(err)
		}
		for _, extension := range controlsAndExtensions[1:] {
			contents = append(contents, extension...)
		}
	}
	message, err := ber.AppendSequence(nil, contents)
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func ldapMessageRaw(parts ...[]byte) []byte {
	contents := make([]byte, 0)
	for _, part := range parts {
		contents = append(contents, part...)
	}
	message, err := ber.AppendSequence(nil, contents)
	if err != nil {
		panic(err)
	}
	return message
}
