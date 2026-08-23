//go:build integration

package integration

import (
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
	"github.com/wyattanderson/arden/integration/ldap389ds"
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
		server.DirectoryManagerDN(),
		server.DirectoryManagerPassword(),
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
	client := arden.NewClient(conn)
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = conn.Close()
		}
	})

	rootDSE, err := client.RootDSE(ctx, "supportedLDAPVersion")
	require.NoError(t, err)
	assert.Empty(t, rootDSE.DN)
	require.True(t, rootDSE.Contains("supportedLDAPVersion", "3"),
		"root DSE did not advertise LDAPv3: %#v", rootDSE.Attributes)
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
		server.DirectoryManagerDN(),
		server.DirectoryManagerPassword(),
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
	client := arden.NewClient(conn)
	t.Cleanup(func() { _ = conn.Close() })

	const baseDN = "dc=arden-integration,dc=test"
	create389DSBackend(t, ctx, server, baseDN)
	base := arden.NewEntry(baseDN)
	base.Set("objectClass", "top", "domain")
	base.Set("dc", "arden-integration")
	require.NoError(t, client.Add(ctx, base))

	const recordCount = 30
	peopleDN := fmt.Sprintf("ou=arden-integration-people,%s", baseDN)
	people := arden.NewEntry(arden.LDAPDN(peopleDN))
	people.Set("objectClass", "top", "organizationalUnit")
	people.Set("ou", "arden-integration-people")
	require.NoError(t, client.Add(ctx, people))

	for i := range recordCount {
		uid := fmt.Sprintf("arden-user-%02d", i)
		user := arden.NewEntry(arden.LDAPDN(fmt.Sprintf("uid=%s,%s", uid, peopleDN)))
		user.Set("objectClass", "top", "person", "organizationalPerson", "inetOrgPerson")
		user.Set("uid", uid)
		user.Set("cn", fmt.Sprintf("Arden User %02d", i))
		user.Set("sn", fmt.Sprintf("User %02d", i))
		user.Set("departmentNumber", departmentFor(i))
		user.Set("description", "created")
		require.NoError(t, client.Add(ctx, user))
	}

	// Retrieve the entries in pages smaller than the data set and use every
	// returned cookie until the server signals the final page with an empty one.
	seen := make(map[string]struct{}, recordCount)
	rows, err := client.Search(ctx, arden.SearchRequest{
		BaseDN: arden.LDAPDN(peopleDN), Scope: arden.ScopeSubtree, Filter: arden.Has("uid"),
		Attributes: []string{"uid"}, PageSize: 7,
	})
	require.NoError(t, err)
	defer func() { require.NoError(t, rows.Close()) }()
	for rows.Next() {
		uid := rows.Entry().Value("uid")
		require.NotEmpty(t, uid)
		_, duplicate := seen[uid]
		require.False(t, duplicate, "paged search returned %q twice", uid)
		seen[uid] = struct{}{}
	}
	require.NoError(t, rows.Err())
	require.Len(t, seen, recordCount)

	for i := range recordCount {
		uid := fmt.Sprintf("arden-user-%02d", i)
		require.NoError(t, client.Modify(ctx, arden.LDAPDN(fmt.Sprintf("uid=%s,%s", uid, peopleDN)),
			arden.Replace("description", "updated-"+uid)))
	}

	// Re-retrieve all modified entries and check that every replacement stuck.
	updated := search389DS(t, ctx, client, &arden.SearchRequest{
		BaseDN:       arden.LDAPDN(peopleDN),
		Scope:        arden.ScopeSubtree,
		DerefAliases: arden.DerefNever,
		Filter:       arden.Has("uid"),
		PageSize:     7,
		Attributes: []string{
			"uid",
			"description",
		},
	})
	require.Len(t, updated, recordCount)
	for _, entry := range updated {
		uid := entry.Value("uid")
		require.Equal(t, "updated-"+uid, entry.Value("description"))
	}

	filtered := search389DS(t, ctx, client, &arden.SearchRequest{
		BaseDN:       arden.LDAPDN(peopleDN),
		Scope:        arden.ScopeSubtree,
		DerefAliases: arden.DerefNever,
		Filter:       arden.Equal("departmentNumber", "engineering"),
		PageSize:     7,
		Attributes: []string{
			"uid",
			"departmentNumber",
		},
	})
	require.Len(t, filtered, recordCount/2)
	for _, entry := range filtered {
		require.Equal(t, "engineering", entry.Value("departmentNumber"))
	}

	for i := range recordCount {
		require.NoError(t, client.Delete(ctx, arden.LDAPDN(fmt.Sprintf("uid=arden-user-%02d,%s", i, peopleDN))))
	}
	remaining := search389DS(t, ctx, client, &arden.SearchRequest{
		BaseDN:       arden.LDAPDN(peopleDN),
		Scope:        arden.ScopeSubtree,
		DerefAliases: arden.DerefNever,
		Filter:       arden.Has("uid"),
		Attributes:   []string{"uid"},
		PageSize:     7,
	})
	require.Empty(t, remaining)
}

func search389DS(t *testing.T, ctx context.Context, client *arden.Client, request *arden.SearchRequest) []arden.Entry {
	t.Helper()
	rows, err := client.Search(ctx, *request)
	require.NoError(t, err)
	defer func() { require.NoError(t, rows.Close()) }()
	var entries []arden.Entry
	for rows.Next() {
		entries = append(entries, rows.Entry())
	}
	require.NoError(t, rows.Err())
	return entries
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

func departmentFor(index int) string {
	if index%2 == 0 {
		return "engineering"
	}
	return "support"
}
