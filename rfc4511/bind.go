package rfc4511

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ber"
)

var (
	bindRequestIdentifier   = applicationConstructed(0)
	bindResponseIdentifier  = applicationConstructed(1)
	unbindRequestIdentifier = applicationPrimitive(2)
	bindResponsePattern     = mustResponsePattern(arden.ResponseSpec{
		Complete: []ber.Identifier{bindResponseIdentifier},
	})
	unbindResponsePattern           = mustResponsePattern(arden.ResponseSpec{NoResponse: true})
	simpleAuthenticationIdentifier  = contextPrimitive(0)
	saslAuthenticationIdentifier    = contextConstructed(3)
	serverSASLCredentialsIdentifier = contextPrimitive(7)
)

func BindRequestIdentifier() ber.Identifier   { return bindRequestIdentifier }
func BindResponseIdentifier() ber.Identifier  { return bindResponseIdentifier }
func UnbindRequestIdentifier() ber.Identifier { return unbindRequestIdentifier }

// AuthenticationChoice is an unsealed BindRequest authentication CHOICE.
type AuthenticationChoice interface {
	ber.Marshaler
	AuthenticationIdentifier() ber.Identifier
}

// SimpleAuthentication is the [0] OCTET STRING simple Bind choice. It is a
// byte type so applications can avoid converting credentials through strings.
type SimpleAuthentication []byte

func (v SimpleAuthentication) AuthenticationIdentifier() ber.Identifier {
	return simpleAuthenticationIdentifier
}
func (v SimpleAuthentication) AppendBER(dst []byte) ([]byte, error) {
	return ber.AppendPrimitive(dst, simpleAuthenticationIdentifier, v)
}
func (v *SimpleAuthentication) UnmarshalBER(r *ber.Reader) error {
	if v == nil {
		return nilReceiver("SimpleAuthentication")
	}
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

func (SASLAuthentication) AuthenticationIdentifier() ber.Identifier {
	return saslAuthenticationIdentifier
}
func (v SASLAuthentication) AppendBER(dst []byte) ([]byte, error) {
	start := len(dst)
	if err := requireNonEmpty("SASL mechanism", v.Mechanism); err != nil {
		return dst, err
	}
	contents, err := ber.AppendOctetString(nil, v.Mechanism)
	if err != nil {
		return dst[:start], err
	}
	if v.HasCredentials {
		contents, err = ber.AppendOctetString(contents, v.Credentials)
		if err != nil {
			return dst[:start], err
		}
	}
	contents, err = appendUnknownFields(contents, v.Extensions)
	if err != nil {
		return dst[:start], err
	}
	encoded, err := ber.AppendConstructed(dst, saslAuthenticationIdentifier, contents)
	if err != nil {
		return dst[:start], err
	}
	return encoded, nil
}
func (v *SASLAuthentication) UnmarshalBER(r *ber.Reader) error {
	if v == nil {
		return nilReceiver("SASLAuthentication")
	}
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
	decoded := SASLAuthentication{Mechanism: LDAPString(bytes.Clone(mechanism))}
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
			return fmt.Errorf("rfc4511: duplicate SASL credentials field %s", id)
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

func (v UnknownAuthentication) AuthenticationIdentifier() ber.Identifier { return v.identifier }
func (v UnknownAuthentication) AppendBER(dst []byte) ([]byte, error) {
	if len(v.raw) == 0 {
		return dst, errors.New("rfc4511: unknown authentication was not decoded")
	}
	return append(dst, v.raw...), nil
}
func (v UnknownAuthentication) Raw() []byte { return bytes.Clone(v.raw) }

// BindRequest is the RFC 4511 BindRequest protocol operation.
type BindRequest struct {
	Version        int64
	Name           LDAPDN
	Authentication AuthenticationChoice
	Extensions     []UnknownField
}

func (*BindRequest) ProtocolIdentifier() ber.Identifier { return bindRequestIdentifier }
func (v *BindRequest) AppendBER(dst []byte) ([]byte, error) {
	start := len(dst)
	if v == nil {
		return dst, errors.New("rfc4511: nil BindRequest")
	}
	if v.Version < 1 || v.Version > 127 {
		return dst, fmt.Errorf("rfc4511: BindRequest version %d is outside [1, 127]", v.Version)
	}
	if v.Authentication == nil {
		return dst, errors.New("rfc4511: BindRequest has no authentication choice")
	}
	contents, err := ber.AppendInteger(nil, v.Version)
	if err != nil {
		return dst[:start], err
	}
	if contents, err = ber.AppendOctetString(contents, v.Name); err != nil {
		return dst[:start], err
	}
	if contents, err = appendAuthentication(contents, v.Authentication); err != nil {
		return dst[:start], err
	}
	if contents, err = appendUnknownFields(contents, v.Extensions); err != nil {
		return dst[:start], err
	}
	encoded, err := ber.AppendConstructed(dst, bindRequestIdentifier, contents)
	if err != nil {
		return dst[:start], err
	}
	return encoded, nil
}
func (v *BindRequest) UnmarshalBER(r *ber.Reader) error {
	if v == nil {
		return nilReceiver("BindRequest")
	}
	contents, err := r.Constructed(bindRequestIdentifier)
	if err != nil {
		return err
	}
	version, err := contents.Integer()
	if err != nil {
		return err
	}
	if version < 1 || version > 127 {
		return fmt.Errorf("rfc4511: BindRequest version %d is outside [1, 127]", version)
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
	*v = BindRequest{Version: version, Name: LDAPDN(bytes.Clone(name)), Authentication: authentication, Extensions: extensions}
	return nil
}

// BindResponse is LDAPResult plus optional server SASL credentials.
type BindResponse struct {
	Result                   LDAPResult
	ServerSASLCredentials    []byte
	HasServerSASLCredentials bool
	Extensions               []UnknownField
}

func (v BindResponse) AppendBER(dst []byte) ([]byte, error) {
	start := len(dst)
	if len(v.Result.Extensions) != 0 {
		return dst, errors.New("rfc4511: BindResponse result extensions must be response extensions")
	}
	contents, err := v.Result.appendPrefix(nil)
	if err != nil {
		return dst[:start], err
	}
	if v.HasServerSASLCredentials {
		contents, err = appendImplicitOctets(contents, serverSASLCredentialsIdentifier, v.ServerSASLCredentials)
		if err != nil {
			return dst[:start], err
		}
	}
	contents, err = appendUnknownFields(contents, v.Extensions)
	if err != nil {
		return dst[:start], err
	}
	encoded, err := ber.AppendConstructed(dst, bindResponseIdentifier, contents)
	if err != nil {
		return dst[:start], err
	}
	return encoded, nil
}
func (v *BindResponse) UnmarshalBER(r *ber.Reader) error {
	if v == nil {
		return nilReceiver("BindResponse")
	}
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
			return fmt.Errorf("rfc4511: duplicate or out-of-order BindResponse field %s", id)
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

func (*UnbindRequest) ProtocolIdentifier() ber.Identifier { return unbindRequestIdentifier }
func (*UnbindRequest) AppendBER(dst []byte) ([]byte, error) {
	return ber.AppendPrimitive(dst, unbindRequestIdentifier, nil)
}
func (v *UnbindRequest) UnmarshalBER(r *ber.Reader) error {
	if v == nil {
		return nilReceiver("UnbindRequest")
	}
	value, err := r.Primitive(unbindRequestIdentifier)
	if err != nil {
		return err
	}
	if len(value) != 0 {
		return errors.New("rfc4511: UnbindRequest has nonempty contents")
	}
	*v = UnbindRequest{}
	return nil
}

func BindResponsePattern() arden.ResponsePattern   { return bindResponsePattern }
func UnbindResponsePattern() arden.ResponsePattern { return unbindResponsePattern }

func NewBindOperation(request *BindRequest, controls []ber.Marshaler) (arden.Operation, error) {
	if request == nil {
		return arden.Operation{}, errors.New("rfc4511: nil BindRequest")
	}
	op := arden.Operation{
		Protocol:     request,
		Controls:     slices.Clone(controls),
		Responses:    BindResponsePattern(),
		Cancellation: arden.CancelClose,
		Metadata:     arden.OperationMetadata{Label: "ldap.bind"},
	}
	if err := op.Validate(); err != nil {
		return arden.Operation{}, err
	}
	return op, nil
}

func NewUnbindOperation(request *UnbindRequest, controls []ber.Marshaler) (arden.Operation, error) {
	if request == nil {
		return arden.Operation{}, errors.New("rfc4511: nil UnbindRequest")
	}
	op := arden.Operation{
		Protocol:     request,
		Controls:     slices.Clone(controls),
		Responses:    UnbindResponsePattern(),
		Cancellation: arden.CancelClose,
		Metadata:     arden.OperationMetadata{Label: "ldap.unbind"},
	}
	if err := op.Validate(); err != nil {
		return arden.Operation{}, err
	}
	return op, nil
}

func appendAuthentication(dst []byte, value AuthenticationChoice) ([]byte, error) {
	start := len(dst)
	if value == nil {
		return dst, errors.New("rfc4511: nil authentication choice")
	}
	id := value.AuthenticationIdentifier()
	if !id.Valid() || id.Class != ber.ClassContextSpecific {
		return dst, fmt.Errorf("rfc4511: authentication identifier %s is not context-specific", id)
	}
	encoded, err := value.AppendBER(dst)
	if err != nil {
		return dst[:start], err
	}
	e, err := ber.DecodeElement(encoded[start:], validationLimits())
	if err != nil {
		return dst[:start], err
	}
	if e.Identifier != id {
		return dst[:start], fmt.Errorf("rfc4511: authentication encoded %s, declared %s", e.Identifier, id)
	}
	return encoded, nil
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
			return nil, fmt.Errorf("rfc4511: authentication identifier %s is not context-specific", id)
		}
		e, err := r.SkipElement()
		if err != nil {
			return nil, err
		}
		return UnknownAuthentication{identifier: e.Identifier, raw: bytes.Clone(e.Raw)}, nil
	}
}
