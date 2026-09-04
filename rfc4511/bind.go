package rfc4511

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/protocol"
)

var (
	bindRequestIdentifier   = applicationConstructed(0)
	bindResponseIdentifier  = applicationConstructed(1)
	unbindRequestIdentifier = applicationPrimitive(2)
	bindResponsePattern     = mustResponsePattern[BindResponse](protocol.ResponseSpec{
		Complete: []ber.Identifier{bindResponseIdentifier},
	})
	unbindResponsePattern           = protocol.NewNoResponsePattern()
	simpleAuthenticationIdentifier  = contextPrimitive(0)
	saslAuthenticationIdentifier    = contextConstructed(3)
	serverSASLCredentialsIdentifier = contextPrimitive(7)
)

// BindRequestIdentifier returns the application identifier for BindRequest.
func BindRequestIdentifier() ber.Identifier { return bindRequestIdentifier }

// BindResponseIdentifier returns the application identifier for BindResponse.
func BindResponseIdentifier() ber.Identifier { return bindResponseIdentifier }

// UnbindRequestIdentifier returns the application identifier for UnbindRequest.
func UnbindRequestIdentifier() ber.Identifier { return unbindRequestIdentifier }

// AuthenticationChoice is an unsealed BindRequest authentication CHOICE.
type AuthenticationChoice interface {
	ber.Packeter
}

// SimpleAuthentication is the [0] OCTET STRING simple Bind choice. It is a
// byte type so applications can avoid converting credentials through strings.
type SimpleAuthentication []byte

// AuthenticationIdentifier returns the context-specific simple authentication identifier.
func (v SimpleAuthentication) AuthenticationIdentifier() ber.Identifier {
	return simpleAuthenticationIdentifier
}

// BERPacket returns the simple-authentication packet.
func (v SimpleAuthentication) BERPacket() ber.Packet {
	return ber.Primitive(simpleAuthenticationIdentifier, v)
}

//revive:disable-next-line:exported
func (v *SimpleAuthentication) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r)
	value := d.Primitive[SimpleAuthentication](simpleAuthenticationIdentifier)
	if err := d.Err(); err != nil {
		return err
	}
	*v = value
	return nil
}

// SASLAuthentication is the [3] SASL credentials Bind choice. HasCredentials
// distinguishes omitted credentials from a present, empty OCTET STRING.
type SASLAuthentication struct {
	Mechanism      LDAPString
	Credentials    []byte
	HasCredentials bool
	Extensions     []UnknownField
}

// AuthenticationIdentifier returns the context-specific SASL authentication identifier.
func (SASLAuthentication) AuthenticationIdentifier() ber.Identifier {
	return saslAuthenticationIdentifier
}

// BERPacket returns the SASL-authentication packet.
func (v SASLAuthentication) BERPacket() ber.Packet {
	authentication := ber.Constructed(saslAuthenticationIdentifier).
		Add(ber.OctetString(v.Mechanism))
	if v.HasCredentials {
		authentication.Add(ber.OctetString(v.Credentials))
	}
	return authentication.Add(v.Extensions...).BERPacket()
}

//revive:disable-next-line:exported
func (v *SASLAuthentication) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r).Constructed(saslAuthenticationIdentifier)
	decoded := SASLAuthentication{Mechanism: d.Read[LDAPString]()}
	if d.NextIs(ber.OctetStringIdentifier) {
		decoded.Credentials = d.OctetString[[]byte]()
		decoded.HasCredentials = true
	}
	decoded.Extensions = d.Extensions[UnknownField](ber.OctetStringIdentifier)
	if err := d.End(); err != nil {
		return err
	}
	if err := requireNonEmpty("SASL mechanism", decoded.Mechanism); err != nil {
		return err
	}
	*v = decoded
	return nil
}

// UnknownAuthentication preserves an unrecognized extensible authentication
// choice without giving the RFC package a registry or extension privilege.
type UnknownAuthentication struct {
	identifier ber.Identifier
	raw        []byte
}

// AuthenticationIdentifier returns the preserved authentication choice identifier.
func (v UnknownAuthentication) AuthenticationIdentifier() ber.Identifier { return v.identifier }

// BERPacket returns the preserved authentication packet.
func (v UnknownAuthentication) BERPacket() ber.Packet { return ber.Encoded(v.raw) }

// Raw returns an independent copy of the complete preserved BER encoding.
func (v UnknownAuthentication) Raw() []byte { return bytes.Clone(v.raw) }

// BindRequest is the RFC 4511 BindRequest protocol operation.
type BindRequest struct {
	Version        int64
	Name           LDAPDN
	Authentication AuthenticationChoice
	Extensions     []UnknownField
}

//revive:disable-next-line:exported
func (*BindRequest) ProtocolIdentifier() ber.Identifier { return bindRequestIdentifier }

// BERPacket returns the bind-request packet.
func (v *BindRequest) BERPacket() ber.Packet {
	return ber.Constructed(bindRequestIdentifier).
		Add(ber.Integer(v.Version), ber.OctetString(v.Name)).
		Add(v.Authentication).
		Add(v.Extensions...).
		BERPacket()
}

//revive:disable-next-line:exported
func (v *BindRequest) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r).Constructed(bindRequestIdentifier)
	decoded := BindRequest{
		Version:        d.Integer[int64](),
		Name:           d.Read[LDAPDN](),
		Authentication: d.Using(decodeAuthentication),
		Extensions:     d.Extensions[UnknownField](),
	}
	if err := d.End(); err != nil {
		return err
	}
	if decoded.Version < 1 || decoded.Version > 127 {
		return fmt.Errorf("arden: BindRequest version %d is outside [1, 127]", decoded.Version)
	}
	*v = decoded
	return nil
}

// BindResponse is LDAPResult plus optional server SASL credentials.
type BindResponse struct {
	Result                   LDAPResult
	ServerSASLCredentials    []byte
	HasServerSASLCredentials bool
	Extensions               []UnknownField
}

// LDAPResult returns the operation result carried by v.
func (v BindResponse) LDAPResult() LDAPResult { return v.Result }

// BERPacket returns the bind-response packet.
func (v BindResponse) BERPacket() ber.Packet {
	response := ber.Constructed(bindResponseIdentifier)
	v.Result.addPrefix(response)
	if v.HasServerSASLCredentials {
		response.Add(implicitOctetsPacket(serverSASLCredentialsIdentifier, v.ServerSASLCredentials))
	}
	return response.Add(v.Extensions...).BERPacket()
}

//revive:disable-next-line:exported
func (v *BindResponse) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r).Constructed(bindResponseIdentifier)
	decoded := BindResponse{Result: d.Embed[LDAPResult]()}
	if d.NextIs(serverSASLCredentialsIdentifier) {
		decoded.ServerSASLCredentials = d.Primitive[[]byte](serverSASLCredentialsIdentifier)
		decoded.HasServerSASLCredentials = true
	}
	decoded.Extensions = d.Extensions[UnknownField](serverSASLCredentialsIdentifier)
	if err := d.End(); err != nil {
		return err
	}
	*v = decoded
	return nil
}

// UnbindRequest is the no-response RFC 4511 UnbindRequest operation.
type UnbindRequest struct{}

//revive:disable-next-line:exported
func (*UnbindRequest) ProtocolIdentifier() ber.Identifier { return unbindRequestIdentifier }

// BERPacket returns the unbind-request packet.
func (*UnbindRequest) BERPacket() ber.Packet {
	return ber.Primitive(unbindRequestIdentifier, nil)
}

//revive:disable-next-line:exported
func (v *UnbindRequest) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r)
	d.NullAs(unbindRequestIdentifier)
	if err := d.Err(); err != nil {
		return err
	}
	*v = UnbindRequest{}
	return nil
}

// BindResponsePattern returns the terminal response pattern for BindRequest.
func BindResponsePattern() protocol.ResponsePattern[BindResponse] { return bindResponsePattern }

// UnbindResponsePattern returns the no-response pattern for UnbindRequest.
func UnbindResponsePattern() protocol.ResponsePattern[protocol.NoResponse] {
	return unbindResponsePattern
}

// NewBindOperation creates a complete Bind request declaration.
func NewBindOperation(request *BindRequest, controls []ber.Packeter) (protocol.Operation[BindResponse], error) {
	if request == nil {
		return protocol.Operation[BindResponse]{}, errors.New("arden: nil BindRequest")
	}
	op := protocol.Operation[BindResponse]{
		Protocol:     request,
		Controls:     slices.Clone(controls),
		Responses:    BindResponsePattern(),
		Cancellation: protocol.CancelClose,
		Metadata:     protocol.OperationMetadata{Label: "ldap.bind"},
	}
	if err := op.Validate(); err != nil {
		return protocol.Operation[BindResponse]{}, err
	}
	return op, nil
}

// NewUnbindOperation creates a complete Unbind request declaration.
func NewUnbindOperation(request *UnbindRequest, controls []ber.Packeter) (protocol.Operation[protocol.NoResponse], error) {
	if request == nil {
		return protocol.Operation[protocol.NoResponse]{}, errors.New("arden: nil UnbindRequest")
	}
	op := protocol.Operation[protocol.NoResponse]{
		Protocol:     request,
		Controls:     slices.Clone(controls),
		Responses:    UnbindResponsePattern(),
		Cancellation: protocol.CancelClose,
		Metadata:     protocol.OperationMetadata{Label: "ldap.unbind"},
	}
	if err := op.Validate(); err != nil {
		return protocol.Operation[protocol.NoResponse]{}, err
	}
	return op, nil
}

func decodeAuthentication(r *ber.Reader) (AuthenticationChoice, error) {
	d := ber.NewDecoder(r)
	id := d.PeekIdentifier()
	var decoded AuthenticationChoice
	switch id {
	case simpleAuthenticationIdentifier:
		decoded = d.Read[SimpleAuthentication]()
	case saslAuthenticationIdentifier:
		decoded = d.Read[SASLAuthentication]()
	default:
		if id.Class != ber.ClassContextSpecific {
			d.Fail(fmt.Errorf("arden: authentication identifier %s is not context-specific", id))
		}
		field := d.Read[UnknownField]()
		decoded = UnknownAuthentication(field)
	}
	if err := d.Err(); err != nil {
		return nil, err
	}
	return decoded, nil
}
