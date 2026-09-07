package posixaccount_test

import (
	"context"
	"io"
	"slices"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/ldapmodel"
	"github.com/wyattanderson/arden/rfc4511"

	"github.com/wyattanderson/arden/freeipa/posixaccount"
)

const usersBaseDN = "cn=users,cn=accounts,dc=arden,dc=test"

func TestResultSetAll(t *testing.T) {
	dao := testDAO(
		t,
		searchEntryResponse(t, testUserEntry("alice", 1200, 1200)),
		searchEntryResponse(t, testUserEntry("bob", 1201, 1200)),
		searchDoneResponse(t, emptyPageControl(t)),
	)

	users, err := dao.Where(posixaccount.GIDNumberIs(1200)).All()
	require.NoError(t, err)
	require.Len(t, users, 2)
	assert.Equal(t, "alice", users[0].AccountName)
	assert.Equal(t, "bob", users[1].AccountName)
}

func TestResultSetOne(t *testing.T) {
	t.Run("one", func(t *testing.T) {
		dao := testDAO(
			t,
			searchEntryResponse(t, testUserEntry("alice", 1200, 1200)),
			searchDoneResponse(t),
		)

		user, err := dao.Where(posixaccount.AccountNameIs("alice")).One()
		require.NoError(t, err)
		assert.Equal(t, "alice", user.AccountName)
	})

	t.Run("none", func(t *testing.T) {
		dao := testDAO(t, searchDoneResponse(t))

		_, err := dao.Where(posixaccount.AccountNameIs("missing")).One()
		assert.ErrorIs(t, err, arden.ErrNotFound)
	})

	t.Run("many", func(t *testing.T) {
		dao := testDAO(
			t,
			searchEntryResponse(t, testUserEntry("alice", 1200, 1200)),
			searchEntryResponse(t, testUserEntry("alice", 1201, 1200)),
			searchDoneResponse(t),
		)

		_, err := dao.Where(posixaccount.AccountNameIs("alice")).One()
		assert.ErrorIs(t, err, ldapmodel.ErrNotUnique)
	})
}

func TestResultSetFirst(t *testing.T) {
	dao := testDAO(
		t,
		searchEntryResponse(t, testUserEntry("alice", 1200, 1200)),
		searchEntryResponse(t, testUserEntry("bob", 1201, 1200)),
		searchDoneResponse(t),
	)

	user, err := dao.Where(posixaccount.GIDNumberIs(1200)).First()
	require.NoError(t, err)
	assert.Equal(t, "alice", user.AccountName)
}

func TestResultSetStream(t *testing.T) {
	dao := testDAO(
		t,
		searchEntryResponse(t, testUserEntry("alice", 1200, 1200)),
		searchEntryResponse(t, testUserEntry("bob", 1201, 1200)),
		searchDoneResponse(t, emptyPageControl(t)),
	)

	stream, closeStream, err := dao.Where(posixaccount.GIDNumberIs(1200)).Stream()
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, closeStream())
	}()

	var names []string
	for stream.Next() {
		names = append(names, stream.Value().AccountName)
	}
	require.NoError(t, stream.Err())
	assert.Equal(t, []string{"alice", "bob"}, names)
}

func TestGenericDAOModify(t *testing.T) {
	var operations []arden.AnyOperation
	executor := &scriptedExecutor{
		responses: []arden.Response{modifyDoneResponse(t)},
		onOperation: func(operation arden.AnyOperation) {
			operations = append(operations, operation)
		},
	}
	dao := ldapmodel.NewDAO(arden.NewClient(executor), posixaccount.Users(usersBaseDN))

	attributes := posixaccount.UserAttributes
	emails := []string{"alice@example.test", "other@example.test"}
	mailChange := ldapmodel.Replace(attributes.EmailAddresses, emails...)
	emails[0] = "changed"
	err := dao.Modify("uid=alice,"+usersBaseDN,
		ldapmodel.Add(attributes.EmailAddresses, "old@example.test"),
		ldapmodel.Delete(attributes.EmailAddresses, "old@example.test", "another@example.test"),
		mailChange,
		ldapmodel.Replace(attributes.LoginShell, "/bin/bash"),
		ldapmodel.Delete(attributes.LoginShell),
		ldapmodel.Replace(attributes.LoginShell, "/bin/zsh"),
		ldapmodel.Replace(attributes.GECOS),
		ldapmodel.Replace(attributes.HomeDirectory, "/home/alice"),
		ldapmodel.Replace(attributes.GIDNumber, 1200),
		ldapmodel.Replace(attributes.UIDNumber, 1201),
		ldapmodel.Replace(attributes.CommonName, "Alice Example"),
	)
	require.NoError(t, err)
	require.Len(t, operations, 1)
	reader, err := ber.NewReader(operations[0].Untyped().Protocol.BERPacket().Encode(), ber.DefaultLimits())
	require.NoError(t, err)
	var request rfc4511.ModifyRequest
	require.NoError(t, request.UnmarshalBER(reader))
	want := []arden.Change{
		arden.AddValues("mail", "old@example.test"),
		arden.DeleteValues("mail", "old@example.test", "another@example.test"),
		arden.Replace("mail", "alice@example.test", "other@example.test"),
		arden.Replace("loginShell", "/bin/bash"),
		arden.DeleteValues("loginShell"),
		arden.Replace("loginShell", "/bin/zsh"),
		arden.Replace("gecos"),
		arden.Replace("homeDirectory", "/home/alice"),
		arden.Replace("gidNumber", "1200"),
		arden.Replace("uidNumber", "1201"),
		arden.Replace("cn", "Alice Example"),
	}
	// Compare wire encodings so nil and empty value slices are equivalent.
	assert.Equal(t, (&rfc4511.ModifyRequest{
		Object: "uid=alice," + usersBaseDN, Changes: want,
	}).BERPacket().Encode(), request.BERPacket().Encode())

	require.ErrorIs(t, dao.Modify("uid=alice,"+usersBaseDN), ldapmodel.ErrEmptyChanges)
	assert.Len(t, operations, 1, "empty changes must not issue an operation")
}

func TestGenericDAOAddAndSearchIdentity(t *testing.T) {
	var operations []arden.AnyOperation
	executor := &scriptedExecutor{
		responses: []arden.Response{protocolResponse(t, rfc4511.AddResponseIdentifier(), rfc4511.AddResponse{
			Result: rfc4511.LDAPResult{ResultCode: rfc4511.ResultSuccess},
		})},
		onOperation: func(operation arden.AnyOperation) {
			operations = append(operations, operation)
		},
	}
	dao := ldapmodel.NewDAO(arden.NewClient(executor), posixaccount.Users(usersBaseDN))
	a := posixaccount.UserAttributes
	dn := arden.LDAPDN("uid=alice," + usersBaseDN)
	err := dao.Add("alice",
		ldapmodel.Set(a.CommonName, "Alice Example"),
		ldapmodel.Set(a.Surname, "Example"),
		ldapmodel.Set(a.UIDNumber, 1200),
		ldapmodel.Set(a.GIDNumber, 1200),
		ldapmodel.Set(a.HomeDirectory, "/home/alice"),
		ldapmodel.Set(a.EmailAddresses, "alice@example.test", "other@example.test"),
	)
	require.NoError(t, err)
	require.Len(t, operations, 1)
	reader, err := ber.NewReader(operations[0].Untyped().Protocol.BERPacket().Encode(), ber.DefaultLimits())
	require.NoError(t, err)
	var request rfc4511.AddRequest
	require.NoError(t, request.UnmarshalBER(reader))
	classes := []string{"top", "person", "organizationalPerson", "inetOrgPerson", "posixAccount"}
	want := arden.NewEntry(dn)
	want.Set("objectClass", classes...)
	want.Set("uid", "alice")
	want.Set("cn", "Alice Example")
	want.Set("sn", "Example")
	want.Set("uidNumber", "1200")
	want.Set("gidNumber", "1200")
	want.Set("homeDirectory", "/home/alice")
	want.Set("mail", "alice@example.test", "other@example.test")
	assert.Equal(t, dn, request.Entry)
	assert.Equal(t, slices.Collect(want.Attributes.All()), slices.Collect(request.Attributes.All()))
	_, err = posixaccount.DecodeUser(arden.Entry{DN: request.Entry, Attributes: request.Attributes})
	require.NoError(t, err)

	executor.responses = []arden.Response{searchDoneResponse(t)}
	_, err = dao.Where(posixaccount.AccountNameIs("alice")).First()
	require.ErrorIs(t, err, arden.ErrNotFound)
	require.Len(t, operations, 2)
	require.IsType(t, &rfc4511.SearchRequest{}, operations[1].Untyped().Protocol)
	search := operations[1].Untyped().Protocol.(*rfc4511.SearchRequest)
	filters := make([]arden.Filter, len(classes))
	for i, class := range classes {
		filters[i] = arden.Equal("objectClass", class)
	}
	wantFilter := arden.All(arden.All(filters...), arden.Equal("uid", "alice"))
	assert.Equal(t, wantFilter, search.Filter, "search must require every creation class and caller criterion")
	selection := slices.Collect(search.Attributes.All())
	assert.NotContains(t, selection, rfc4511.AttributeSelector("sn"))
	assert.NotContains(t, selection, rfc4511.AttributeSelector("objectClass"))
}

func testDAO(t *testing.T, responses ...arden.Response) ldapmodel.DAO[posixaccount.User] {
	t.Helper()
	client := arden.NewClient(&scriptedExecutor{responses: responses})
	return ldapmodel.NewDAO(client, posixaccount.Users(usersBaseDN)).WithContext(context.Background())
}

func testUserEntry(accountName string, uidNumber, gidNumber uint32) arden.Entry {
	entry := arden.NewEntry(arden.LDAPDN("uid=" + accountName + "," + usersBaseDN))
	entry.Set("uid", accountName)
	entry.Set("cn", accountName+" Example")
	entry.Set("uidNumber", strconv.FormatUint(uint64(uidNumber), 10))
	entry.Set("gidNumber", strconv.FormatUint(uint64(gidNumber), 10))
	entry.Set("homeDirectory", "/home/"+accountName)
	entry.Set("loginShell", "/bin/bash")
	entry.Set("mail", accountName+"@example.test")
	return *entry
}

type scriptedExecutor struct {
	responses   []arden.Response
	onOperation func(arden.AnyOperation)
}

func (e *scriptedExecutor) Do(_ context.Context, operation arden.AnyOperation) (arden.ResponseStream, error) {
	if e.onOperation != nil {
		e.onOperation(operation)
	}
	return &scriptedStream{responses: e.responses}, nil
}

type scriptedStream struct {
	responses []arden.Response
	index     int
}

func (s *scriptedStream) Next(context.Context) (arden.Response, error) {
	if s.index == len(s.responses) {
		return arden.Response{}, io.EOF
	}
	response := s.responses[s.index]
	s.index++
	return response, nil
}

func (*scriptedStream) Close() error { return nil }

func searchEntryResponse(t *testing.T, entry arden.Entry) arden.Response {
	t.Helper()
	return protocolResponse(t, rfc4511.SearchResultEntryIdentifier(), rfc4511.SearchResultEntry{
		ObjectName: entry.DN,
		Attributes: entry.Attributes,
	})
}

func searchDoneResponse(t *testing.T, controls ...rfc4511.Control) arden.Response {
	t.Helper()
	return protocolResponseWithControls(t, rfc4511.SearchResultDoneIdentifier(), rfc4511.SearchResultDone{
		Result: rfc4511.LDAPResult{ResultCode: rfc4511.ResultSuccess},
	}, controls...)
}

func modifyDoneResponse(t *testing.T) arden.Response {
	t.Helper()
	return protocolResponse(t, rfc4511.ModifyResponseIdentifier(), rfc4511.ModifyResponse{
		Result: rfc4511.LDAPResult{ResultCode: rfc4511.ResultSuccess},
	})
}

func protocolResponse(t *testing.T, identifier ber.Identifier, value ber.Packeter) arden.Response {
	t.Helper()
	protocol := value.BERPacket().Encode()
	return arden.Response{ProtocolID: identifier, Protocol: protocol, Bytes: protocol}
}

func protocolResponseWithControls(
	t *testing.T,
	identifier ber.Identifier,
	value ber.Packeter,
	controls ...rfc4511.Control,
) arden.Response {
	t.Helper()
	response := protocolResponse(t, identifier, value)
	for _, control := range controls {
		raw := control.BERPacket().Encode()
		response.Controls = append(response.Controls, ber.Element{Raw: raw})
	}
	return response
}

func emptyPageControl(t *testing.T) rfc4511.Control {
	t.Helper()
	value := ber.Sequence().
		Add(ber.Integer(0), ber.OctetString([]byte(nil))).
		BERPacket().Encode()
	return rfc4511.Control{
		Type:     "1.2.840.113556.1.4.319",
		Value:    value,
		HasValue: true,
	}
}
