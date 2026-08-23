package arden

import "github.com/wyattanderson/arden/rfc4511"

// LDAPDN is the opaque textual distinguished-name type used by the generic
// client and the RFC 4511 wire layer.
type LDAPDN = rfc4511.LDAPDN

// RelativeLDAPDN is the opaque textual relative distinguished-name type.
type RelativeLDAPDN = rfc4511.RelativeLDAPDN

// Attribute is a schema-neutral LDAP attribute.
type Attribute = rfc4511.Attribute

// Change is one ordered LDAP Modify change.
type Change = rfc4511.Change

// Filter is an RFC 4511 search filter.
type Filter = rfc4511.Filter

// SearchScope selects the portion of the directory tree searched.
type SearchScope = rfc4511.SearchScope

// DerefAliases controls alias dereferencing during search.
type DerefAliases = rfc4511.DerefAliases

// Search scope and alias-dereferencing constants for the generic client.
const (
	ScopeBase     = rfc4511.ScopeBaseObject
	ScopeChildren = rfc4511.ScopeSingleLevel
	ScopeSubtree  = rfc4511.ScopeWholeSubtree

	DerefNever       = rfc4511.DerefNever
	DerefSearching   = rfc4511.DerefSearching
	DerefFindingBase = rfc4511.DerefFindingBase
	DerefAlways      = rfc4511.DerefAlways
)
