package posixaccount_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strconv"
	"testing"

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
	if err := dao.Modify("uid=alice,"+usersBaseDN,
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
	); err != nil {
		t.Fatalf("Modify: %v", err)
	}
	if len(operations) != 1 {
		t.Fatalf("got %d operations, want one Modify", len(operations))
	}
	reader, err := ber.NewReader(operations[0].Untyped().Protocol.BERPacket().Encode(), ber.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var request rfc4511.ModifyRequest
	if err := request.UnmarshalBER(reader); err != nil {
		t.Fatal(err)
	}
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
	if !bytes.Equal(request.BERPacket().Encode(), (&rfc4511.ModifyRequest{
		Object: "uid=alice," + usersBaseDN, Changes: want,
	}).BERPacket().Encode()) {
		t.Fatalf("unexpected Modify request: %#v", request)
	}

	if err := dao.Modify("uid=alice," + usersBaseDN); !errors.Is(err, ldapmodel.ErrEmptyChanges) {
		t.Fatalf("empty changes: got %v, want ErrEmptyChanges", err)
	}
	if len(operations) != 1 {
		t.Fatal("empty changes issued an operation")
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
