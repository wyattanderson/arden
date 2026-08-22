//go:build integration

package arden_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/auth"
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
)

func Test389DSSimpleBindBootstrapAndRootDSESearch(t *testing.T) {
	address := os.Getenv("ARDEN_389DS_ADDR")
	serverName := os.Getenv("ARDEN_389DS_SERVER_NAME")
	caCertificatePath := os.Getenv("ARDEN_389DS_CA_CERT")
	password := os.Getenv("ARDEN_389DS_DM_PASSWORD")
	if address == "" || serverName == "" || caCertificatePath == "" || password == "" {
		t.Skip("389ds integration environment is not configured; run integration/389ds/test.sh")
	}
	caCertificate, err := os.ReadFile(caCertificatePath)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(caCertificate), "389ds test CA certificate is not valid PEM")
	simpleBind, err := auth.NewSimpleBind(
		"389ds-directory-manager",
		[]byte("cn=Directory Manager"),
		[]byte(password),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := (&arden.Dialer{
		TLSConfig:      &tls.Config{RootCAs: roots},
		Authentication: simpleBind,
	}).Dial(ctx, arden.Endpoint{
		ID:         "389ds-integration",
		Address:    address,
		ServerName: serverName,
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
