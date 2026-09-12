package gen_test

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/gen/internal/clientmodel"
	"github.com/wyattanderson/arden/ldapmodel"
	"github.com/wyattanderson/arden/rfc4511"
)

func TestGeneratedClientStorage(t *testing.T) {
	ex := &modelExecutor{responses: []arden.Response{modelResponse(rfc4511.AddResponseIdentifier(), rfc4511.AddResponse{Result: rfc4511.LDAPResult{ResultCode: rfc4511.ResultSuccess}})}}
	dao := ldapmodel.NewDAO(arden.NewClient(ex), clientmodel.Clients("cn=clients,dc=test"))
	a := clientmodel.ClientAttributes
	require.NoError(t, dao.Add("immutable-id", ldapmodel.Set(a.ClientID, "grafana"), ldapmodel.Set(a.Enabled, false),
		ldapmodel.Set(a.RedirectURIs, "https://grafana.test/callback"), ldapmodel.Set(a.ResponseTypes, "code"),
		ldapmodel.Set(a.RequireConsent, false), ldapmodel.Set(a.SecretDigest, []byte{0, 255, 1}), ldapmodel.Set(a.MaxAuthenticationAgeSeconds, uint64(900))))
	require.Len(t, ex.operations, 1)
	var added rfc4511.AddRequest
	reader, err := ber.NewReader(ex.operations[0].Untyped().Protocol.BERPacket().Encode(), ber.DefaultLimits())
	require.NoError(t, err)
	require.NoError(t, added.UnmarshalBER(reader))
	assert.Equal(t, arden.LDAPDN("ipaUniqueID=immutable-id,cn=clients,dc=test"), added.Entry)
	entry := arden.Entry{DN: added.Entry, Attributes: added.Attributes}
	assert.ElementsMatch(t, []string{"top", "ipaOidcIdpClient"}, entry.Values("objectClass"))
	assert.Equal(t, "FALSE", entry.Value("ipaOidcIdpEnabled"))
	record, err := clientmodel.DecodeClient(entry)
	require.NoError(t, err)
	assert.Equal(t, "grafana", record.ClientID)
	assert.Equal(t, []string{"code"}, record.ResponseTypes)
	require.NotNil(t, record.RequireConsent)
	assert.False(t, *record.RequireConsent)
	assert.Nil(t, record.DisplayName)
	require.NotNil(t, record.SecretDigest)
	assert.Equal(t, []byte{0, 255, 1}, *record.SecretDigest)
	// Missing optional values remain distinct from explicit false and empty bytes.
	minimal := arden.NewEntry(entry.DN)
	minimal.Set("ipaUniqueID", "immutable-id")
	minimal.Set("ipaOidcIdpClientId", "grafana")
	minimal.Set("ipaOidcIdpEnabled", "TRUE")
	record, err = clientmodel.DecodeClient(*minimal)
	require.NoError(t, err)
	assert.Nil(t, record.RequireConsent)
	assert.Nil(t, record.SecretDigest)
	minimal.Set("ipaOidcIdpMaxAuthAge", "0")
	_, err = clientmodel.DecodeClient(*minimal)
	require.ErrorIs(t, err, clientmodel.ErrInvalidMaxAge)
	minimal.Set("ipaOidcIdpMaxAuthAge", "900")
	minimal.Set("ipaOidcIdpEnabled", "TRUE", "FALSE")
	_, err = clientmodel.DecodeClient(*minimal)
	require.ErrorContains(t, err, "ipaOidcIdpEnabled")
	require.ErrorContains(t, err, string(entry.DN))

	ex.responses = []arden.Response{
		modelResponse(rfc4511.SearchResultEntryIdentifier(), rfc4511.SearchResultEntry{ObjectName: entry.DN, Attributes: entry.Attributes}),
		modelResponse(rfc4511.SearchResultDoneIdentifier(), rfc4511.SearchResultDone{Result: rfc4511.LDAPResult{ResultCode: rfc4511.ResultSuccess}}),
	}
	record, err = dao.Where(clientmodel.ClientIDIs("grafana")).One()
	require.NoError(t, err)
	assert.Equal(t, "immutable-id", record.UniqueID)
	assert.Equal(t, 2, ex.closed)
	var search rfc4511.SearchRequest
	reader, err = ber.NewReader(ex.operations[1].Untyped().Protocol.BERPacket().Encode(), ber.DefaultLimits())
	require.NoError(t, err)
	require.NoError(t, search.UnmarshalBER(reader))
	assert.Equal(t, int32(2), int32(search.SizeLimit))
	assert.Contains(t, string(search.Filter.BERPacket().Encode()), "ipaOidcIdpClientId")
	assert.Contains(t, string(search.Filter.BERPacket().Encode()), "ipaOidcIdpClient")

	ex.responses = []arden.Response{modelResponse(rfc4511.ModifyResponseIdentifier(), rfc4511.ModifyResponse{Result: rfc4511.LDAPResult{ResultCode: rfc4511.ResultSuccess}})}
	require.NoError(t, dao.Modify(entry.DN, ldapmodel.Replace(a.Enabled, true), ldapmodel.Delete(a.SecretDigest), ldapmodel.Replace(a.RedirectURIs, "https://new.test/callback")))
	var modified rfc4511.ModifyRequest
	reader, err = ber.NewReader(ex.operations[2].Untyped().Protocol.BERPacket().Encode(), ber.DefaultLimits())
	require.NoError(t, err)
	require.NoError(t, modified.UnmarshalBER(reader))
	require.Len(t, modified.Changes, 3)
	assert.Equal(t, entry.DN, modified.Object)
	assert.Equal(t, "TRUE", string(modified.Changes[0].Modification.Values[0]))
	assert.Empty(t, modified.Changes[1].Modification.Values)

	_, err = dao.Where(clientmodel.ClientIDIs("")).One()
	require.ErrorContains(t, err, "encode ipaOidcIdpClientId")
	require.Error(t, dao.Add("id", ldapmodel.Set(a.ClientID, "")))
	require.Len(t, ex.operations, 3, "encoding errors must not send LDAP requests")
}

type modelExecutor struct {
	responses  []arden.Response
	operations []arden.AnyOperation
	closed     int
}

func (e *modelExecutor) Do(_ context.Context, op arden.AnyOperation) (arden.ResponseStream, error) {
	e.operations = append(e.operations, op)
	return &modelStream{owner: e}, nil
}

type modelStream struct {
	owner *modelExecutor
	index int
}

func (s *modelStream) Next(context.Context) (arden.Response, error) {
	if s.index == len(s.owner.responses) {
		return arden.Response{}, io.EOF
	}
	response := s.owner.responses[s.index]
	s.index++
	return response, nil
}
func (s *modelStream) Close() error { s.owner.closed++; return nil }
func modelResponse(id ber.Identifier, packet ber.Packeter) arden.Response {
	raw := packet.BERPacket().Encode()
	return arden.Response{ProtocolID: id, Protocol: raw, Bytes: raw}
}
