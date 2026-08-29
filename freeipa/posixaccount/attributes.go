package posixaccount

import (
	"fmt"
	"strconv"

	"github.com/wyattanderson/arden/schema"
)

var uint32Codec schema.ValueCodec[uint32] = schema.Codec[uint32]{
	EncodeFunc: func(value uint32) ([]byte, error) {
		return strconv.AppendUint(nil, uint64(value), 10), nil
	},
	DecodeFunc: func(value []byte) (uint32, error) {
		decoded, err := strconv.ParseUint(string(value), 10, 32)
		if err != nil {
			return 0, fmt.Errorf("decode unsigned 32-bit integer: %w", err)
		}
		return uint32(decoded), nil
	},
}

// UserAttributes is the generated, typed vocabulary shared by model decoding,
// indexed predicates, and patches. Go field names are application vocabulary;
// descriptor names are LDAP schema vocabulary.
var UserAttributes = struct {
	AccountName    schema.Attribute[string]
	CommonName     schema.Attribute[string]
	UIDNumber      schema.Attribute[uint32]
	GIDNumber      schema.Attribute[uint32]
	HomeDirectory  schema.Attribute[string]
	GECOS          schema.Attribute[string]
	LoginShell     schema.Attribute[string]
	EmailAddresses schema.Attribute[string]
}{
	AccountName:    schema.NewAttribute("uid", schema.StringCodec),
	CommonName:     schema.NewAttribute("cn", schema.StringCodec),
	UIDNumber:      schema.NewAttribute("uidNumber", uint32Codec),
	GIDNumber:      schema.NewAttribute("gidNumber", uint32Codec),
	HomeDirectory:  schema.NewAttribute("homeDirectory", schema.StringCodec),
	GECOS:          schema.NewAttribute("gecos", schema.StringCodec),
	LoginShell:     schema.NewAttribute("loginShell", schema.StringCodec),
	EmailAddresses: schema.NewAttribute("mail", schema.StringCodec),
}

var userProjection = []string{
	UserAttributes.AccountName.Name,
	UserAttributes.CommonName.Name,
	UserAttributes.UIDNumber.Name,
	UserAttributes.GIDNumber.Name,
	UserAttributes.HomeDirectory.Name,
	UserAttributes.GECOS.Name,
	UserAttributes.LoginShell.Name,
	UserAttributes.EmailAddresses.Name,
}
