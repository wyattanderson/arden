package posixaccount_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"

	"github.com/wyattanderson/arden/freeipa/posixaccount"
)

var benchmarkUser posixaccount.User
var benchmarkAddBytes []byte

func BenchmarkDecodeUser(b *testing.B) {
	for _, extras := range []int{0, 32} {
		b.Run(fmt.Sprintf("extra_attributes_%d", extras), func(b *testing.B) {
			entry := benchmarkUserEntry(extras)
			b.ReportAllocs()
			for b.Loop() {
				var err error
				benchmarkUser, err = posixaccount.DecodeUser(entry)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkUnmarshalDecodeUser(b *testing.B) {
	entry := benchmarkUserEntry(0)
	wire := rfc4511.SearchResultEntry{ObjectName: entry.DN, Attributes: entry.Attributes}
	encoded := wire.BERPacket().Encode()
	b.ReportAllocs()
	for b.Loop() {
		r, err := ber.NewReader(encoded, ber.DefaultLimits())
		if err != nil {
			b.Fatal(err)
		}
		var decoded rfc4511.SearchResultEntry
		if err := decoded.UnmarshalBER(r); err != nil {
			b.Fatal(err)
		}
		benchmarkUser, err = posixaccount.DecodeUser(arden.Entry{DN: decoded.ObjectName, Attributes: decoded.Attributes})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkModelEntryAddEncoding(b *testing.B) {
	user, err := posixaccount.DecodeUser(testUserEntry("alice", 1001, 1001))
	if err != nil {
		b.Fatal(err)
	}
	a := posixaccount.UserAttributes
	b.ReportAllocs()
	for b.Loop() {
		entry := arden.NewEntry(user.DN)
		entry.Set("objectClass", "top", "person", "posixAccount")
		if err := a.AccountName.Set(entry, user.AccountName); err != nil {
			b.Fatal(err)
		}
		if err := a.CommonName.Set(entry, user.CommonName); err != nil {
			b.Fatal(err)
		}
		if err := a.UIDNumber.Set(entry, user.UIDNumber); err != nil {
			b.Fatal(err)
		}
		if err := a.GIDNumber.Set(entry, user.GIDNumber); err != nil {
			b.Fatal(err)
		}
		if err := a.HomeDirectory.Set(entry, user.HomeDirectory); err != nil {
			b.Fatal(err)
		}
		if err := a.LoginShell.Set(entry, *user.LoginShell); err != nil {
			b.Fatal(err)
		}
		if err := a.EmailAddresses.Set(entry, user.EmailAddresses...); err != nil {
			b.Fatal(err)
		}
		request := rfc4511.AddRequest{Entry: entry.DN, Attributes: entry.Attributes}
		benchmarkAddBytes = request.BERPacket().Encode()
	}
}

// Put unused attributes first to exercise lookup cost independently of wire order.
func benchmarkUserEntry(extras int) arden.Entry {
	entry := arden.NewEntry("uid=alice," + usersBaseDN)
	for i := range extras {
		entry.Set(fmt.Sprintf("extra%d", i), "unused")
	}
	entry.Set("uid", "alice")
	entry.Set("cn", "alice Example")
	entry.Set("uidNumber", "1001")
	entry.Set("gidNumber", "1001")
	entry.Set("homeDirectory", "/home/alice")
	entry.Set("loginShell", "/bin/bash")
	entry.Set("mail", "alice@example.test")
	entry.Set("gecos", "Alice Example")
	return *entry
}

// Include the real Client.Get wire-to-Entry conversion, using an in-memory
// response stream so network latency does not obscure allocations.
func BenchmarkClientGetDecodeUser(b *testing.B) {
	entry := benchmarkUserEntry(0)
	wire := rfc4511.SearchResultEntry{ObjectName: entry.DN, Attributes: entry.Attributes}
	encoded := wire.BERPacket().Encode()
	done := rfc4511.SearchResultDone{Result: rfc4511.LDAPResult{ResultCode: rfc4511.ResultSuccess}}.BERPacket().Encode()
	client := arden.NewClient(&scriptedExecutor{responses: []arden.Response{
		{ProtocolID: rfc4511.SearchResultEntryIdentifier(), Protocol: encoded, Bytes: encoded},
		{ProtocolID: rfc4511.SearchResultDoneIdentifier(), Protocol: done, Bytes: done},
	}})
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		decoded, err := client.Get(ctx, entry.DN)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkUser, err = posixaccount.DecodeUser(decoded)
		if err != nil {
			b.Fatal(err)
		}
	}
}
