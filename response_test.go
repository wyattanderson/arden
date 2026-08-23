package arden_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	require.NoError(t, err)
	require.Equal(t, arden.ResponseHeader{
		MessageID:  7,
		ProtocolID: ber.Identifier{Class: ber.ClassApplication, Constructed: true, Number: 9},
	}, response.Header())
	require.Equal(t, protocol, response.Protocol)
	require.Len(t, response.Controls, 1)
	require.Equal(t, []byte{0x30, 0x00}, response.Controls[0].Raw)
	require.Len(t, response.Extensions, 1)
	require.Equal(t, []byte{0x83, 0x01, 0x7f}, response.Extensions[0].Raw)

	for i := range message {
		message[i] = 0
	}
	assert.Equal(t, protocol, response.Protocol)
	isView := false
	for i := range response.Bytes {
		if &response.Protocol[0] == &response.Bytes[i] {
			isView = true
			break
		}
	}
	assert.True(t, isView)
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
			_, err := arden.ParseResponse(test.message, ber.DefaultLimits())
			assert.Error(t, err)
		})
	}
}

func ldapMessage(t *testing.T, messageID int64, protocol []byte, controlsAndExtensions ...[]byte) []byte {
	t.Helper()
	messageIDElement, err := ber.AppendInteger(nil, messageID)
	require.NoError(t, err)
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
		require.NoError(t, err)
		for _, extension := range controlsAndExtensions[1:] {
			contents = append(contents, extension...)
		}
	}
	message, err := ber.AppendSequence(nil, contents)
	require.NoError(t, err)
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
