//go:build integration

package arden_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
)

func Test389DSBindAndRootDSESearch(t *testing.T) {
	address := os.Getenv("ARDEN_389DS_ADDR")
	password := os.Getenv("ARDEN_389DS_DM_PASSWORD")
	if address == "" || password == "" {
		t.Skip("389ds integration environment is not configured; run integration/389ds/test.sh")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := new(arden.Dialer).Dial(ctx, arden.Endpoint{
		ID:        "389ds-integration",
		Address:   address,
		Transport: arden.TransportPlaintext,
	})
	require.NoError(t, err)
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = conn.Close()
		}
	})

	bind, err := rfc4511.NewBindOperation(&rfc4511.BindRequest{
		Version:        3,
		Name:           rfc4511.LDAPDN("cn=Directory Manager"),
		Authentication: rfc4511.SimpleAuthentication(password),
	}, nil)
	require.NoError(t, err)

	bindStream, err := conn.Do(ctx, bind)
	require.NoError(t, err)
	bindMessage, err := bindStream.Next(ctx)
	require.NoError(t, err)
	require.Equal(t, rfc4511.BindResponseIdentifier(), bindMessage.ProtocolID)

	var bindResponse rfc4511.BindResponse
	require.NoError(t, bindMessage.UnmarshalProtocol(&bindResponse, ber.DefaultLimits()))
	require.Equal(t, rfc4511.ResultSuccess, bindResponse.Result.ResultCode,
		"bind diagnostic: %s", bindResponse.Result.DiagnosticMessage)
	_, err = bindStream.Next(ctx)
	require.ErrorIs(t, err, io.EOF)

	search, err := rfc4511.NewSearchOperation(&rfc4511.SearchRequest{
		BaseObject:   rfc4511.LDAPDN{},
		Scope:        rfc4511.ScopeBaseObject,
		DerefAliases: rfc4511.DerefNever,
		Filter: rfc4511.Present{
			Attribute: rfc4511.AttributeDescription("objectClass"),
		},
		Attributes: []rfc4511.AttributeSelector{
			rfc4511.AttributeSelector("supportedLDAPVersion"),
		},
	}, nil)
	require.NoError(t, err)

	searchStream, err := conn.Do(ctx, search)
	require.NoError(t, err)

	var entries []rfc4511.SearchResultEntry
	for {
		message, err := searchStream.Next(ctx)
		require.NoError(t, err)
		switch message.ProtocolID {
		case rfc4511.SearchResultEntryIdentifier():
			var entry rfc4511.SearchResultEntry
			require.NoError(t, message.UnmarshalProtocol(&entry, ber.DefaultLimits()))
			entries = append(entries, entry)
		case rfc4511.SearchResultReferenceIdentifier():
			t.Fatal("unexpected search reference from root DSE search")
		case rfc4511.SearchResultDoneIdentifier():
			var done rfc4511.SearchResultDone
			require.NoError(t, message.UnmarshalProtocol(&done, ber.DefaultLimits()))
			require.Equal(t, rfc4511.ResultSuccess, done.Result.ResultCode,
				"search diagnostic: %s", done.Result.DiagnosticMessage)
			goto searchComplete
		default:
			t.Fatalf("unexpected root DSE response identifier %s", message.ProtocolID)
		}
	}

searchComplete:
	_, err = searchStream.Next(ctx)
	require.ErrorIs(t, err, io.EOF)
	require.Len(t, entries, 1)
	assert.Empty(t, entries[0].ObjectName)
	require.True(t, attributeContains(entries[0], "supportedLDAPVersion", "3"),
		"root DSE did not advertise LDAPv3: %#v", entries[0].Attributes)
	require.NoError(t, conn.Close())
	closed = true
}

func attributeContains(entry rfc4511.SearchResultEntry, name, value string) bool {
	for _, attribute := range entry.Attributes {
		if !bytes.EqualFold(attribute.Type, []byte(name)) {
			continue
		}
		for _, candidate := range attribute.Values {
			if bytes.Equal(candidate, []byte(value)) {
				return true
			}
		}
	}
	return false
}
