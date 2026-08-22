//go:build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
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

func Test389DSDirectoryOperationsAndPagedSearch(t *testing.T) {
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

	var l = new(slog.LevelVar)
	l.Set(slog.LevelDebug)
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})
	slog.SetDefault(slog.New(h))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := (&arden.Dialer{
		TLSConfig:      server.TLSConfig(),
		Authentication: simpleBind,
		Logger:         slog.Default(),
	}).Dial(ctx, arden.Endpoint{
		ID:         "389ds-directory-operations",
		Address:    server.Address(),
		ServerName: server.ServerName(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	const baseDN = "dc=arden-integration,dc=test"
	create389DSBackend(t, ctx, server, baseDN)
	add389DSRecord(t, ctx, conn, &rfc4511.AddRequest{
		Entry: rfc4511.LDAPDN(baseDN),
		Attributes: []rfc4511.Attribute{
			attribute("objectClass", "top", "domain"),
			attribute("dc", "arden-integration"),
		},
	})

	const recordCount = 30
	peopleDN := fmt.Sprintf("ou=arden-integration-people,%s", baseDN)
	add389DSRecord(t, ctx, conn, &rfc4511.AddRequest{
		Entry: rfc4511.LDAPDN(peopleDN),
		Attributes: []rfc4511.Attribute{
			attribute("objectClass", "top", "organizationalUnit"),
			attribute("ou", "arden-integration-people"),
		},
	})

	for i := range recordCount {
		uid := fmt.Sprintf("arden-user-%02d", i)
		add389DSRecord(t, ctx, conn, &rfc4511.AddRequest{
			Entry: rfc4511.LDAPDN(fmt.Sprintf("uid=%s,%s", uid, peopleDN)),
			Attributes: []rfc4511.Attribute{
				attribute("objectClass", "top", "person", "organizationalPerson", "inetOrgPerson"),
				attribute("uid", uid),
				attribute("cn", fmt.Sprintf("Arden User %02d", i)),
				attribute("sn", fmt.Sprintf("User %02d", i)),
				attribute("departmentNumber", departmentFor(i)),
				attribute("description", "created"),
			},
		})
	}

	// Retrieve the entries in pages smaller than the data set and use every
	// returned cookie until the server signals the final page with an empty one.
	seen := make(map[string]struct{}, recordCount)
	var cookie []byte
	pages := 0
	for {
		control, err := pagedResultsControl(7, cookie)
		require.NoError(t, err)
		result := search389DS(t, ctx, conn, &rfc4511.SearchRequest{
			BaseObject:   rfc4511.LDAPDN(peopleDN),
			Scope:        rfc4511.ScopeWholeSubtree,
			DerefAliases: rfc4511.DerefNever,
			Filter:       rfc4511.Present{Attribute: rfc4511.AttributeDescription("uid")},
			Attributes:   []rfc4511.AttributeSelector{rfc4511.AttributeSelector("uid")},
		}, []ber.Marshaler{control})
		pages++
		require.LessOrEqual(t, len(result.entries), 7)
		for _, entry := range result.entries {
			uid := attributeValue(entry, "uid")
			require.NotEmpty(t, uid)
			_, duplicate := seen[uid]
			require.False(t, duplicate, "paged search returned %q twice", uid)
			seen[uid] = struct{}{}
		}
		cookie, err = pagedResultsCookie(result.done.Controls)
		require.NoError(t, err)
		if len(cookie) == 0 {
			break
		}
		require.Less(t, pages, recordCount, "paged search did not terminate")
	}
	require.Greater(t, pages, 1)
	require.Len(t, seen, recordCount)

	for i := range recordCount {
		uid := fmt.Sprintf("arden-user-%02d", i)
		modify389DSRecord(t, ctx, conn, &rfc4511.ModifyRequest{
			Object: rfc4511.LDAPDN(fmt.Sprintf("uid=%s,%s", uid, peopleDN)),
			Changes: []rfc4511.Change{{
				Operation: rfc4511.ModifyReplace,
				Modification: rfc4511.PartialAttribute{
					Type:   rfc4511.AttributeDescription("description"),
					Values: []rfc4511.AttributeValue{rfc4511.AttributeValue("updated-" + uid)},
				},
			}},
		})
	}

	// Re-retrieve all modified entries and check that every replacement stuck.
	updated := search389DS(t, ctx, conn, &rfc4511.SearchRequest{
		BaseObject:   rfc4511.LDAPDN(peopleDN),
		Scope:        rfc4511.ScopeWholeSubtree,
		DerefAliases: rfc4511.DerefNever,
		Filter:       rfc4511.Present{Attribute: rfc4511.AttributeDescription("uid")},
		Attributes: []rfc4511.AttributeSelector{
			rfc4511.AttributeSelector("uid"),
			rfc4511.AttributeSelector("description"),
		},
	}, nil).entries
	require.Len(t, updated, recordCount)
	for _, entry := range updated {
		uid := attributeValue(entry, "uid")
		require.Equal(t, "updated-"+uid, attributeValue(entry, "description"))
	}

	filtered := search389DS(t, ctx, conn, &rfc4511.SearchRequest{
		BaseObject:   rfc4511.LDAPDN(peopleDN),
		Scope:        rfc4511.ScopeWholeSubtree,
		DerefAliases: rfc4511.DerefNever,
		Filter: rfc4511.EqualityMatch{Assertion: rfc4511.AttributeValueAssertion{
			Type:  rfc4511.AttributeDescription("departmentNumber"),
			Value: rfc4511.AssertionValue("engineering"),
		}},
		Attributes: []rfc4511.AttributeSelector{
			rfc4511.AttributeSelector("uid"),
			rfc4511.AttributeSelector("departmentNumber"),
		},
	}, nil).entries
	require.Len(t, filtered, recordCount/2)
	for _, entry := range filtered {
		require.Equal(t, "engineering", attributeValue(entry, "departmentNumber"))
	}

	for i := range recordCount {
		delete389DSRecord(t, ctx, conn, rfc4511.LDAPDN(fmt.Sprintf("uid=arden-user-%02d,%s", i, peopleDN)))
	}
	remaining := search389DS(t, ctx, conn, &rfc4511.SearchRequest{
		BaseObject:   rfc4511.LDAPDN(peopleDN),
		Scope:        rfc4511.ScopeWholeSubtree,
		DerefAliases: rfc4511.DerefNever,
		Filter:       rfc4511.Present{Attribute: rfc4511.AttributeDescription("uid")},
		Attributes:   []rfc4511.AttributeSelector{rfc4511.AttributeSelector("uid")},
	}, nil).entries
	require.Empty(t, remaining)
}

type search389DSResult struct {
	entries []rfc4511.SearchResultEntry
	done    arden.Response
}

func search389DS(t *testing.T, ctx context.Context, conn *arden.Conn, request *rfc4511.SearchRequest, controls []ber.Marshaler) search389DSResult {
	t.Helper()
	op, err := rfc4511.NewSearchOperation(request, controls)
	require.NoError(t, err)
	stream, err := conn.Do(ctx, op)
	require.NoError(t, err)
	defer func() { require.NoError(t, stream.Close()) }()

	var result search389DSResult
	for {
		message, err := stream.Next(ctx)
		require.NoError(t, err)
		switch message.ProtocolID {
		case rfc4511.SearchResultEntryIdentifier():
			var entry rfc4511.SearchResultEntry
			require.NoError(t, message.UnmarshalProtocol(&entry, ber.DefaultLimits()))
			result.entries = append(result.entries, entry)
		case rfc4511.SearchResultDoneIdentifier():
			var done rfc4511.SearchResultDone
			require.NoError(t, message.UnmarshalProtocol(&done, ber.DefaultLimits()))
			require.Equal(t, rfc4511.ResultSuccess, done.Result.ResultCode,
				"search diagnostic: %s", done.Result.DiagnosticMessage)
			result.done = message
			_, err = stream.Next(ctx)
			require.ErrorIs(t, err, io.EOF)
			return result
		default:
			t.Fatalf("unexpected search response identifier %s", message.ProtocolID)
		}
	}
}

func add389DSRecord(t *testing.T, ctx context.Context, conn *arden.Conn, request *rfc4511.AddRequest) {
	t.Helper()
	op, err := rfc4511.NewAddOperation(request, nil)
	require.NoError(t, err)
	message := execute389DSOperation(t, ctx, conn, op)
	var response rfc4511.AddResponse
	require.NoError(t, message.UnmarshalProtocol(&response, ber.DefaultLimits()))
	require.Equal(t, rfc4511.ResultSuccess, response.Result.ResultCode,
		"add %s diagnostic: %s", request.Entry, response.Result.DiagnosticMessage)
}

func modify389DSRecord(t *testing.T, ctx context.Context, conn *arden.Conn, request *rfc4511.ModifyRequest) {
	t.Helper()
	op, err := rfc4511.NewModifyOperation(request, nil)
	require.NoError(t, err)
	message := execute389DSOperation(t, ctx, conn, op)
	var response rfc4511.ModifyResponse
	require.NoError(t, message.UnmarshalProtocol(&response, ber.DefaultLimits()))
	require.Equal(t, rfc4511.ResultSuccess, response.Result.ResultCode,
		"modify %s diagnostic: %s", request.Object, response.Result.DiagnosticMessage)
}

func delete389DSRecord(t *testing.T, ctx context.Context, conn *arden.Conn, entry rfc4511.LDAPDN) {
	t.Helper()
	op, err := rfc4511.NewDeleteOperation(&rfc4511.DeleteRequest{Entry: entry}, nil)
	require.NoError(t, err)
	message := execute389DSOperation(t, ctx, conn, op)
	var response rfc4511.DeleteResponse
	require.NoError(t, message.UnmarshalProtocol(&response, ber.DefaultLimits()))
	require.Equal(t, rfc4511.ResultSuccess, response.Result.ResultCode,
		"delete %s diagnostic: %s", entry, response.Result.DiagnosticMessage)
}

func execute389DSOperation(t *testing.T, ctx context.Context, conn *arden.Conn, operation arden.Operation) arden.Response {
	t.Helper()
	stream, err := conn.Do(ctx, operation)
	require.NoError(t, err)
	defer func() { require.NoError(t, stream.Close()) }()
	message, err := stream.Next(ctx)
	require.NoError(t, err)
	_, err = stream.Next(ctx)
	require.ErrorIs(t, err, io.EOF)
	return message
}

func create389DSBackend(t *testing.T, ctx context.Context, server *ldap389ds.Container, suffix string) {
	t.Helper()
	exitCode, output, err := server.Exec(ctx, []string{
		"dsconf", "localhost", "backend", "create",
		"--suffix", suffix,
		"--be-name", "arden-integration",
	})
	require.NoError(t, err)
	result, err := io.ReadAll(output)
	require.NoError(t, err)
	require.Zerof(t, exitCode, "create 389ds backend failed: %s", result)
}

func pagedResultsControl(pageSize int64, cookie []byte) (rfc4511.Control, error) {
	contents, err := ber.AppendInteger(nil, pageSize)
	if err != nil {
		return rfc4511.Control{}, err
	}
	contents, err = ber.AppendOctetString(contents, cookie)
	if err != nil {
		return rfc4511.Control{}, err
	}
	value, err := ber.AppendSequence(nil, contents)
	if err != nil {
		return rfc4511.Control{}, err
	}
	return rfc4511.Control{
		Type:     rfc4511.LDAPOID("1.2.840.113556.1.4.319"),
		Value:    value,
		HasValue: true,
	}, nil
}

func pagedResultsCookie(controls []ber.Element) ([]byte, error) {
	for _, element := range controls {
		reader, err := ber.NewReader(element.Raw, ber.DefaultLimits())
		if err != nil {
			return nil, err
		}
		var control rfc4511.Control
		if err := control.UnmarshalBER(reader); err != nil {
			return nil, err
		}
		if err := reader.RequireEmpty(); err != nil {
			return nil, err
		}
		if !bytes.Equal(control.Type, []byte("1.2.840.113556.1.4.319")) {
			continue
		}
		value, err := ber.NewReader(control.Value, ber.DefaultLimits())
		if err != nil {
			return nil, err
		}
		contents, err := value.Sequence()
		if err != nil {
			return nil, err
		}
		if _, err := contents.Integer(); err != nil {
			return nil, err
		}
		cookie, err := contents.OctetString()
		if err != nil {
			return nil, err
		}
		if err := contents.RequireEmpty(); err != nil {
			return nil, err
		}
		if err := value.RequireEmpty(); err != nil {
			return nil, err
		}
		return cookie, nil
	}
	return nil, fmt.Errorf("paged-results response control is missing")
}

func attribute(name string, values ...string) rfc4511.Attribute {
	attributeValues := make([]rfc4511.AttributeValue, len(values))
	for i, value := range values {
		attributeValues[i] = rfc4511.AttributeValue(value)
	}
	return rfc4511.Attribute{Type: rfc4511.AttributeDescription(name), Values: attributeValues}
}

func attributeValue(entry rfc4511.SearchResultEntry, name string) string {
	for _, attribute := range entry.Attributes {
		if !bytes.EqualFold(attribute.Type, []byte(name)) || len(attribute.Values) == 0 {
			continue
		}
		return string(attribute.Values[0])
	}
	return ""
}

func departmentFor(index int) string {
	if index%2 == 0 {
		return "engineering"
	}
	return "support"
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
