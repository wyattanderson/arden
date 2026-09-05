package rfc4511

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/protocol"
)

var (
	searchRequestIdentifier   = applicationConstructed(3)
	searchEntryIdentifier     = applicationConstructed(4)
	searchDoneIdentifier      = applicationConstructed(5)
	searchReferenceIdentifier = applicationConstructed(19)
	searchResponsePattern     = mustResponsePattern[SearchResult](protocol.ResponseSpec{
		Continue: []ber.Identifier{searchEntryIdentifier, searchReferenceIdentifier},
		Complete: []ber.Identifier{searchDoneIdentifier},
	})
)

// SearchRequestIdentifier returns the application identifier for SearchRequest.
func SearchRequestIdentifier() ber.Identifier { return searchRequestIdentifier }

// SearchResultEntryIdentifier returns the application identifier for a search
// entry response.
func SearchResultEntryIdentifier() ber.Identifier { return searchEntryIdentifier }

// SearchResultDoneIdentifier returns the terminal application identifier for
// a search response.
func SearchResultDoneIdentifier() ber.Identifier { return searchDoneIdentifier }

// SearchResultReferenceIdentifier returns the application identifier for a
// search continuation reference.
func SearchResultReferenceIdentifier() ber.Identifier { return searchReferenceIdentifier }

// SearchScope is the extensible SearchRequest scope ENUMERATED.
type SearchScope int64

// Search scopes defined by RFC 4511.
const (
	ScopeBaseObject   SearchScope = 0
	ScopeSingleLevel  SearchScope = 1
	ScopeWholeSubtree SearchScope = 2
	// ScopeBase, ScopeChildren, and ScopeSubtree are concise application-facing aliases.
	ScopeBase     = ScopeBaseObject
	ScopeChildren = ScopeSingleLevel
	ScopeSubtree  = ScopeWholeSubtree
)

// DerefAliases controls when aliases are dereferenced during Search. Unlike
// SearchScope, this RFC 4511 enumeration is not extensible.
type DerefAliases int64

// Alias dereferencing policies defined by RFC 4511.
const (
	DerefNever       DerefAliases = 0
	DerefSearching   DerefAliases = 1
	DerefFindingBase DerefAliases = 2
	DerefAlways      DerefAliases = 3
)

// SearchRequest is the RFC 4511 SearchRequest protocol operation.
// RFC 4511 section 4.5.1.
type SearchRequest struct {
	BaseObject   LDAPDN
	Scope        SearchScope
	DerefAliases DerefAliases
	SizeLimit    uint32
	TimeLimit    time.Duration
	TypesOnly    bool
	Filter       Filter
	Attributes   AttributeSelectors
	Extensions   []UnknownField
}

//revive:disable-next-line:exported
func (*SearchRequest) ProtocolIdentifier() ber.Identifier { return searchRequestIdentifier }

// BERPacket returns the search-request packet.
func (v *SearchRequest) BERPacket() ber.Packet {
	timeLimit := v.TimeLimit / time.Second
	return ber.Constructed(searchRequestIdentifier).
		Add(
			ber.OctetString(v.BaseObject),
			ber.Enumerated(v.Scope),
			ber.Enumerated(v.DerefAliases),
			ber.Integer(v.SizeLimit),
			ber.Integer(timeLimit),
			ber.Boolean(v.TypesOnly),
		).
		Add(v.Filter).
		Add(v.Attributes).
		Add(v.Extensions...).
		BERPacket()
}

//revive:disable-next-line:exported
func (v *SearchRequest) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r).Constructed(searchRequestIdentifier)
	decoded := SearchRequest{
		BaseObject:   d.Read[LDAPDN](),
		Scope:        d.Enumerated[SearchScope](),
		DerefAliases: d.Enumerated[DerefAliases](),
		SizeLimit:    d.Integer[uint32](),
		TimeLimit:    d.Using(decodeSearchTimeLimit),
		TypesOnly:    d.Boolean(),
		Filter:       d.Using(decodeFilter),
		Attributes:   d.Read[AttributeSelectors](),
		Extensions:   d.Extensions[UnknownField](),
	}
	if err := d.End(); err != nil {
		return err
	}
	if err := validateDerefAliases(decoded.DerefAliases); err != nil {
		return err
	}
	if decoded.SizeLimit > math.MaxInt32 {
		return errors.New("arden: search size limit is outside maxInt")
	}
	*v = decoded
	return nil
}

// Keep the existing signed, whole-second time-limit policy, but check both
// the LDAP upper bound and duration representability before multiplication.
func decodeSearchTimeLimit(r *ber.Reader) (time.Duration, error) {
	d := ber.NewDecoder(r)
	seconds := d.Integer[int64]()
	if err := d.Err(); err != nil {
		return 0, err
	}
	if seconds > math.MaxInt32 || seconds < math.MinInt64/int64(time.Second) {
		return 0, errors.New("arden: search time limit is outside representable bounds")
	}
	return time.Duration(seconds) * time.Second, nil
}

func validateDerefAliases(value DerefAliases) error {
	if value < DerefNever || value > DerefAlways {
		return fmt.Errorf("arden: invalid derefAliases value %d", value)
	}
	return nil
}

// SearchResultEntry is a nonterminal RFC 4511 search response.
type SearchResultEntry struct {
	ObjectName LDAPDN
	Attributes []PartialAttribute
	Extensions []UnknownField
}

func (SearchResultEntry) isSearchResultValue() {}

// BERPacket returns the search-result entry packet.
func (v SearchResultEntry) BERPacket() ber.Packet {
	return ber.Constructed(searchEntryIdentifier).
		Add(ber.OctetString(v.ObjectName)).
		Add(ber.Sequence().Add(v.Attributes...)).
		Add(v.Extensions...).
		BERPacket()
}

//revive:disable-next-line:exported
func (v *SearchResultEntry) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r).Constructed(searchEntryIdentifier)
	decoded := SearchResultEntry{
		ObjectName: d.Read[LDAPDN](),
		Attributes: d.Sequence().All[PartialAttribute](),
		Extensions: d.Extensions[UnknownField](),
	}
	if err := d.End(); err != nil {
		return err
	}
	*v = decoded
	return nil
}

// SearchResultReference is a nonterminal search continuation reference with
// one or more URIs.
type SearchResultReference struct {
	URIs       []URI
	Extensions []UnknownField
}

func (SearchResultReference) isSearchResultValue() {}

// BERPacket returns the search-result reference packet.
func (v SearchResultReference) BERPacket() ber.Packet {
	return ber.Constructed(searchReferenceIdentifier).
		Add(v.URIs...).
		Add(v.Extensions...).
		BERPacket()
}

//revive:disable-next-line:exported
func (v *SearchResultReference) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r).Constructed(searchReferenceIdentifier)
	var decoded SearchResultReference
	for d.NextIs(ber.OctetStringIdentifier) {
		decoded.URIs = append(decoded.URIs, d.Read[URI]())
	}
	decoded.Extensions = d.Extensions[UnknownField](ber.OctetStringIdentifier)
	if err := d.End(); err != nil {
		return err
	}
	if len(decoded.URIs) == 0 {
		return errors.New("arden: search result reference requires at least one URI")
	}
	*v = decoded
	return nil
}

// SearchResultDone is the terminal LDAPResult for a SearchRequest.
type SearchResultDone struct{ Result LDAPResult }

func (SearchResultDone) isSearchResultValue() {}

// LDAPResult returns the terminal search result carried by v.
func (v SearchResultDone) LDAPResult() LDAPResult { return v.Result }

// BERPacket returns the search-result done packet.
func (v SearchResultDone) BERPacket() ber.Packet {
	return resultResponsePacket(searchDoneIdentifier, v.Result)
}

//revive:disable-next-line:exported
func (v *SearchResultDone) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r)
	decoded := SearchResultDone{Result: d.ReadAs[LDAPResult](searchDoneIdentifier)}
	if err := d.Err(); err != nil {
		return err
	}
	*v = decoded
	return nil
}

// SearchResultValue is one of the RFC 4511 SearchResult protocol-operation
// alternatives. The interface is sealed because the SearchResult CHOICE is
// fixed by RFC 4511.
type SearchResultValue interface {
	isSearchResultValue()
}

// SearchResult is the typed SearchResult CHOICE returned by a Search
// operation. Its zero value has no selected alternative.
type SearchResult struct {
	value SearchResultValue
}

// UnmarshalBER decodes one SearchResult alternative based on its application
// identifier. The receiver is unchanged if decoding fails.
func (v *SearchResult) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r)
	id := d.PeekIdentifier()
	var decoded SearchResultValue
	switch id {
	case searchEntryIdentifier:
		decoded = d.Read[SearchResultEntry]()
	case searchReferenceIdentifier:
		decoded = d.Read[SearchResultReference]()
	case searchDoneIdentifier:
		decoded = d.Read[SearchResultDone]()
	default:
		d.Fail(fmt.Errorf("arden: unexpected SearchResult identifier %s", id))
	}
	if err := d.Err(); err != nil {
		return err
	}
	*v = SearchResult{value: decoded}
	return nil
}

// Value returns the selected SearchResult alternative, or nil for the zero
// value. Callers may use a type switch over SearchResultEntry,
// SearchResultReference, and SearchResultDone.
func (v SearchResult) Value() SearchResultValue { return v.value }

// SearchResponsePattern returns the immutable standard streaming response
// pattern for SearchRequest.
func SearchResponsePattern() protocol.ResponsePattern[SearchResult] { return searchResponsePattern }

// NewSearchOperation creates the complete request declaration for a Search.
// Search defaults to Abandon-style cancellation because it may stream for a
// long time; the connection runtime owns the tombstone lifecycle.
func NewSearchOperation(request *SearchRequest, controls []ber.Packeter) (protocol.Operation[SearchResult], error) {
	if request == nil {
		return protocol.Operation[SearchResult]{}, errors.New("arden: nil SearchRequest")
	}
	op := protocol.Operation[SearchResult]{
		Protocol:     request,
		Controls:     slices.Clone(controls),
		Responses:    SearchResponsePattern(),
		Cancellation: protocol.CancelAbandon,
		Metadata:     protocol.OperationMetadata{Label: "ldap.search"},
	}
	if err := op.Validate(); err != nil {
		return protocol.Operation[SearchResult]{}, err
	}
	return op, nil
}
