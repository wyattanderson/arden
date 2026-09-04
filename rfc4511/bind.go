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

//revive:disable-next-line:exported
func (v SimpleAuthentication) AppendBER(dst []byte) ([]byte, error) {
	return v.BERPacket().AppendBER(dst)
}

// BERPacket returns the simple-authentication packet.
func (v SimpleAuthentication) BERPacket() ber.Packet {
	return ber.Primitive(simpleAuthenticationIdentifier, v)
}

//revive:disable-next-line:exported
func (v *SimpleAuthentication) UnmarshalBER(r *ber.Reader) error {
	value, err := readImplicitOctets(r, simpleAuthenticationIdentifier)
	if err != nil {
		return err
	}
	*v = SimpleAuthentication(value)
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

//revive:disable-next-line:exported
func (v SASLAuthentication) AppendBER(dst []byte) ([]byte, error) {
	if err := requireNonEmpty("SASL mechanism", v.Mechanism); err != nil {
		return dst, err
	}
	return v.BERPacket().AppendBER(dst)
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
	contents, err := r.Constructed(saslAuthenticationIdentifier)
	if err != nil {
		return err
	}
	mechanism, err := contents.OctetString()
	if err != nil {
		return err
	}
	if err := requireNonEmpty("SASL mechanism", mechanism); err != nil {
		return err
	}
	decoded := SASLAuthentication{Mechanism: LDAPString(string(mechanism))}
	if !contents.Empty() {
		id, err := contents.PeekIdentifier()
		if err != nil {
			return err
		}
		if id == ber.OctetStringIdentifier {
			credentials, err := contents.OctetString()
			if err != nil {
				return err
			}
			decoded.Credentials, decoded.HasCredentials = bytes.Clone(credentials), true
		}
	}
	if !contents.Empty() {
		id, err := contents.PeekIdentifier()
		if err != nil {
			return err
		}
		if id == ber.OctetStringIdentifier {
			return fmt.Errorf("arden: duplicate SASL credentials field %s", id)
		}
		decoded.Extensions, err = decodeUnknownFields(contents)
		if err != nil {
			return err
		}
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

//revive:disable-next-line:exported
func (v UnknownAuthentication) AppendBER(dst []byte) ([]byte, error) {
	if len(v.raw) == 0 {
		return dst, errors.New("arden: unknown authentication was not decoded")
	}
	return v.BERPacket().AppendBER(dst)
}

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

//revive:disable-next-line:exported
func (v *BindRequest) AppendBER(dst []byte) ([]byte, error) {
	if v.Version < 1 || v.Version > 127 {
		return dst, fmt.Errorf("arden: BindRequest version %d is outside [1, 127]", v.Version)
	}
	if v.Authentication == nil {
		return dst, errors.New("arden: BindRequest has no authentication choice")
	}
	if authentication, ok := v.Authentication.(SASLAuthentication); ok {
		if err := requireNonEmpty("SASL mechanism", authentication.Mechanism); err != nil {
			return dst, err
		}
	}
	return v.BERPacket().AppendBER(dst)
}

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
	contents, err := r.Constructed(bindRequestIdentifier)
	if err != nil {
		return err
	}
	version, err := contents.Integer()
	if err != nil {
		return err
	}
	if version < 1 || version > 127 {
		return fmt.Errorf("arden: BindRequest version %d is outside [1, 127]", version)
	}
	name, err := contents.OctetString()
	if err != nil {
		return err
	}
	authentication, err := decodeAuthentication(contents)
	if err != nil {
		return err
	}
	extensions, err := decodeUnknownFields(contents)
	if err != nil {
		return err
	}
	*v = BindRequest{Version: version, Name: LDAPDN(string(name)), Authentication: authentication, Extensions: extensions}
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

//revive:disable-next-line:exported
func (v BindResponse) AppendBER(dst []byte) ([]byte, error) {
	if len(v.Result.Extensions) != 0 {
		return dst, errors.New("arden: BindResponse result extensions must be response extensions")
	}
	if err := v.Result.validateReferral(); err != nil {
		return dst, err
	}
	return v.BERPacket().AppendBER(dst)
}

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
	contents, err := r.Constructed(bindResponseIdentifier)
	if err != nil {
		return err
	}
	result, err := decodeLDAPResultPrefix(contents)
	if err != nil {
		return err
	}
	decoded := BindResponse{Result: result}
	if !contents.Empty() {
		id, err := contents.PeekIdentifier()
		if err != nil {
			return err
		}
		if id == serverSASLCredentialsIdentifier {
			credentials, err := readImplicitOctets(contents, serverSASLCredentialsIdentifier)
			if err != nil {
				return err
			}
			decoded.ServerSASLCredentials, decoded.HasServerSASLCredentials = credentials, true
		}
	}
	if !contents.Empty() {
		id, err := contents.PeekIdentifier()
		if err != nil {
			return err
		}
		if id == referralIdentifier || id == serverSASLCredentialsIdentifier {
			return fmt.Errorf("arden: duplicate or out-of-order BindResponse field %s", id)
		}
		decoded.Extensions, err = decodeUnknownFields(contents)
		if err != nil {
			return err
		}
	}
	*v = decoded
	return nil
}

// UnbindRequest is the no-response RFC 4511 UnbindRequest operation.
type UnbindRequest struct{}

//revive:disable-next-line:exported
func (*UnbindRequest) ProtocolIdentifier() ber.Identifier { return unbindRequestIdentifier }

//revive:disable-next-line:exported
func (*UnbindRequest) AppendBER(dst []byte) ([]byte, error) {
	return ber.Primitive(unbindRequestIdentifier, nil).AppendBER(dst)
}

// BERPacket returns the unbind-request packet.
func (*UnbindRequest) BERPacket() ber.Packet {
	return ber.Primitive(unbindRequestIdentifier, nil)
}

//revive:disable-next-line:exported
func (v *UnbindRequest) UnmarshalBER(r *ber.Reader) error {
	value, err := r.Primitive(unbindRequestIdentifier)
	if err != nil {
		return err
	}
	if len(value) != 0 {
		return errors.New("arden: UnbindRequest has nonempty contents")
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
func NewBindOperation(request *BindRequest, controls []ber.Marshaler) (protocol.Operation[BindResponse], error) {
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
func NewUnbindOperation(request *UnbindRequest, controls []ber.Marshaler) (protocol.Operation[protocol.NoResponse], error) {
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
	id, err := r.PeekIdentifier()
	if err != nil {
		return nil, err
	}
	switch id {
	case simpleAuthenticationIdentifier:
		var value SimpleAuthentication
		if err := value.UnmarshalBER(r); err != nil {
			return nil, err
		}
		return value, nil
	case saslAuthenticationIdentifier:
		var value SASLAuthentication
		if err := value.UnmarshalBER(r); err != nil {
			return nil, err
		}
		return value, nil
	default:
		if id.Class != ber.ClassContextSpecific {
			return nil, fmt.Errorf("arden: authentication identifier %s is not context-specific", id)
		}
		e, err := r.SkipElement()
		if err != nil {
			return nil, err
		}
		return UnknownAuthentication{identifier: e.Identifier, raw: bytes.Clone(e.Raw)}, nil
	}
}
