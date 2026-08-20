package arden

import (
	"bytes"
	"fmt"

	"github.com/wyattanderson/arden/ber"
)

var controlsIdentifier = ber.Identifier{
	Class:       ber.ClassContextSpecific,
	Constructed: true,
	Number:      0,
}

// ResponseHeader is the routing information in an LDAP response envelope.
// It deliberately contains no decoded protocol payload.
type ResponseHeader struct {
	MessageID  MessageID
	ProtocolID ber.Identifier
}

// Header returns the response's routing information.
func (r Response) Header() ResponseHeader {
	return ResponseHeader{MessageID: r.MessageID, ProtocolID: r.ProtocolID}
}

// ParseResponse validates one complete LDAPMessage and returns an owned
// response envelope. Protocol, Controls, and Extensions are views into Bytes.
// It intentionally does not select or invoke a typed protocol decoder; that
// belongs to the consumer after a response pattern has routed this message.
//
// RFC 4511, section 4.1.1 defines the envelope and its MessageID range.
func ParseResponse(message []byte, limits ber.Limits) (Response, error) {
	owned := bytes.Clone(message)
	return parseOwnedResponse(owned, limits)
}

// parseOwnedResponse is the reader-path variant of ParseResponse. The caller
// transfers exclusive ownership of message to the returned Response.
func parseOwnedResponse(message []byte, limits ber.Limits) (Response, error) {
	r, err := ber.NewReader(message, limits)
	if err != nil {
		return Response{}, err
	}
	envelope, err := r.Sequence()
	if err != nil {
		return Response{}, fmt.Errorf("arden: LDAPMessage: %w", err)
	}
	if err := r.RequireEmpty(); err != nil {
		return Response{}, fmt.Errorf("arden: LDAPMessage: %w", err)
	}

	messageID, err := envelope.Integer()
	if err != nil {
		return Response{}, fmt.Errorf("arden: LDAPMessage messageID: %w", err)
	}
	if messageID < 0 || messageID > int64(MaxMessageID) {
		return Response{}, fmt.Errorf("arden: LDAPMessage messageID %d is outside [0, %d]", messageID, MaxMessageID)
	}

	protocol, err := envelope.ReadElement()
	if err != nil {
		return Response{}, fmt.Errorf("arden: LDAPMessage protocolOp: %w", err)
	}
	if protocol.Identifier.Class != ber.ClassApplication {
		return Response{}, fmt.Errorf("arden: LDAPMessage protocolOp identifier %s is not an application identifier", protocol.Identifier)
	}

	response := Response{
		MessageID:  MessageID(messageID),
		ProtocolID: protocol.Identifier,
		Bytes:      message,
		Protocol:   protocol.Raw,
	}

	if !envelope.Empty() {
		id, err := envelope.PeekIdentifier()
		if err != nil {
			return Response{}, fmt.Errorf("arden: LDAPMessage controls: %w", err)
		}
		if id == controlsIdentifier {
			controls, err := envelope.Constructed(controlsIdentifier)
			if err != nil {
				return Response{}, fmt.Errorf("arden: LDAPMessage controls: %w", err)
			}
			for !controls.Empty() {
				control, err := controls.SkipElement()
				if err != nil {
					return Response{}, fmt.Errorf("arden: LDAPMessage controls: %w", err)
				}
				if control.Identifier != ber.SequenceIdentifier {
					return Response{}, fmt.Errorf("arden: LDAPMessage control identifier %s is not a SEQUENCE", control.Identifier)
				}
				response.Controls = append(response.Controls, control)
			}
		}
	}

	for !envelope.Empty() {
		id, err := envelope.PeekIdentifier()
		if err != nil {
			return Response{}, fmt.Errorf("arden: LDAPMessage extension: %w", err)
		}
		if id == controlsIdentifier {
			return Response{}, fmt.Errorf("arden: LDAPMessage has duplicate or out-of-order controls")
		}
		extension, err := envelope.SkipElement()
		if err != nil {
			return Response{}, fmt.Errorf("arden: LDAPMessage extension: %w", err)
		}
		response.Extensions = append(response.Extensions, extension)
	}

	return response, nil
}
