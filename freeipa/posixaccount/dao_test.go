package posixaccount_test

import (
	"context"
	"errors"
	"io"
	"strconv"
	"testing"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/freeipa/posixaccount"
	"github.com/wyattanderson/arden/ldapmodel"
	"github.com/wyattanderson/arden/rfc4511"
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
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	if len(users) != 2 || users[0].AccountName != "alice" || users[1].AccountName != "bob" {
		t.Fatalf("unexpected users: %#v", users)
	}
}

func TestResultSetOne(t *testing.T) {
	t.Run("one", func(t *testing.T) {
		dao := testDAO(
			t,
			searchEntryResponse(t, testUserEntry("alice", 1200, 1200)),
			searchDoneResponse(t),
		)

		user, err := dao.Where(posixaccount.AccountNameIs("alice")).One()
		if err != nil {
			t.Fatalf("One: %v", err)
		}
		if user.AccountName != "alice" {
			t.Fatalf("unexpected user: %#v", user)
		}
	})

	t.Run("none", func(t *testing.T) {
		dao := testDAO(t, searchDoneResponse(t))

		_, err := dao.Where(posixaccount.AccountNameIs("missing")).One()
		if !errors.Is(err, arden.ErrNotFound) {
			t.Fatalf("got %v, want arden.ErrNotFound", err)
		}
	})

	t.Run("many", func(t *testing.T) {
		dao := testDAO(
			t,
			searchEntryResponse(t, testUserEntry("alice", 1200, 1200)),
			searchEntryResponse(t, testUserEntry("alice", 1201, 1200)),
			searchDoneResponse(t),
		)

		_, err := dao.Where(posixaccount.AccountNameIs("alice")).One()
		if !errors.Is(err, ldapmodel.ErrNotUnique) {
			t.Fatalf("got %v, want ldapmodel.ErrNotUnique", err)
		}
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
	if err != nil {
		t.Fatalf("First: %v", err)
	}
	if user.AccountName != "alice" {
		t.Fatalf("unexpected user: %#v", user)
	}
}

func TestResultSetStream(t *testing.T) {
	dao := testDAO(
		t,
		searchEntryResponse(t, testUserEntry("alice", 1200, 1200)),
		searchEntryResponse(t, testUserEntry("bob", 1201, 1200)),
		searchDoneResponse(t, emptyPageControl(t)),
	)

	stream, closeStream, err := dao.Where(posixaccount.GIDNumberIs(1200)).Stream()
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	defer func() {
		if err := closeStream(); err != nil {
			t.Errorf("close stream: %v", err)
		}
	}()

	var names []string
	for stream.Next() {
		names = append(names, stream.Value().AccountName)
	}
	if err := stream.Err(); err != nil {
		t.Fatalf("stream.Err: %v", err)
	}
	if len(names) != 2 || names[0] != "alice" || names[1] != "bob" {
		t.Fatalf("unexpected names: %#v", names)
	}
}

func TestGenericDAOUpdate(t *testing.T) {
	dao := testDAO(t, modifyDoneResponse(t))

	var patch posixaccount.UserPatch
	patch.ClearGECOS()
	patch.SetLoginShell("/bin/zsh")
	patch.ReplaceEmailAddresses("alice@example.test")
	if err := dao.Update("uid=alice,"+usersBaseDN, patch); err != nil {
		t.Fatalf("Update: %v", err)
	}
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
	responses []arden.Response
}

func (e *scriptedExecutor) Do(context.Context, arden.AnyOperation) (arden.ResponseStream, error) {
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
	attributes := make([]rfc4511.PartialAttribute, len(entry.Attributes))
	for i, attribute := range entry.Attributes {
		attributes[i] = rfc4511.PartialAttribute{
			Type:       attribute.Type,
			Values:     attribute.Values,
			Extensions: attribute.Extensions,
		}
	}
	return protocolResponse(t, rfc4511.SearchResultEntryIdentifier(), rfc4511.SearchResultEntry{
		ObjectName: entry.DN,
		Attributes: attributes,
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

func protocolResponse(t *testing.T, identifier ber.Identifier, value ber.Marshaler) arden.Response {
	t.Helper()
	protocol, err := value.AppendBER(nil)
	if err != nil {
		t.Fatalf("encode protocol response: %v", err)
	}
	return arden.Response{ProtocolID: identifier, Protocol: protocol, Bytes: protocol}
}

func protocolResponseWithControls(
	t *testing.T,
	identifier ber.Identifier,
	value ber.Marshaler,
	controls ...rfc4511.Control,
) arden.Response {
	t.Helper()
	response := protocolResponse(t, identifier, value)
	for _, control := range controls {
		raw, err := control.AppendBER(nil)
		if err != nil {
			t.Fatalf("encode response control: %v", err)
		}
		response.Controls = append(response.Controls, ber.Element{Raw: raw})
	}
	return response
}

func emptyPageControl(t *testing.T) rfc4511.Control {
	t.Helper()
	value, err := ber.Sequence().
		Add(ber.Integer(0), ber.OctetString([]byte(nil))).
		AppendBER(nil)
	if err != nil {
		t.Fatalf("encode page control: %v", err)
	}
	return rfc4511.Control{
		Type:     "1.2.840.113556.1.4.319",
		Value:    value,
		HasValue: true,
	}
}
