//go:build integration

package integration

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/auth"
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/integration/ldap389ds"
	"github.com/wyattanderson/arden/rfc4511"
)

const default389DSImage = "quay.io/389ds/dirsrv@sha256:f2851654c5df545cd893d84bea8d08c28dc25f0930493fbfed1d8a6eacf657f7"

func Test389DSSimpleBindBootstrapAndRootDSESearch(t *testing.T) {
	image := os.Getenv("ARDEN_389DS_IMAGE")
	if image == "" {
		image = default389DSImage
	}

	server, err := ldap389ds.Run(context.Background(), image)
	testcontainers.CleanupContainer(t, server)
	require.NoError(t, err)

	simpleBind, err := auth.NewSimpleBind(
		"389ds-directory-manager",
		[]byte(server.DirectoryManagerDN()),
		[]byte(server.DirectoryManagerPassword()),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var l = new(slog.LevelVar)
	l.Set(slog.LevelDebug)
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})
	slog.SetDefault(slog.New(h))

	conn, err := (&arden.Dialer{
		TLSConfig:      server.TLSConfig(),
		Authentication: simpleBind,
		Logger:         slog.Default(),
	}).Dial(ctx, arden.Endpoint{
		ID:         "389ds-integration",
		Address:    server.Address(),
		ServerName: server.ServerName(),
	})
	require.NoError(t, err)
	require.Equal(t, "389ds-directory-manager", conn.Identity().StableID)
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = conn.Close()
		}
	})

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
