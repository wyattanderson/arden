package arden

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/protocol"
	"github.com/wyattanderson/arden/rfc4511"
)

const pagedResultsOID rfc4511.LDAPOID = "1.2.840.113556.1.4.319"

// ErrNotFound reports that a base-object lookup found no entry.
var ErrNotFound = errors.New("arden: LDAP entry not found")

// Client adds ordinary LDAP operations to an executor.
type Client struct {
	executor Executor
	limits   ber.Limits
}

// DecodedStream owns the response stream for one typed operation. Next
// decodes both the protocol response and its controls. Callers must close the
// stream when they finish reading.
type DecodedStream[T any] struct {
	stream    protocol.ResponseStream
	responses protocol.ResponsePattern[T]
	limits    ber.Limits
	closed    bool
}

// NewClient constructs an ordinary LDAP client over executor.
func NewClient(executor Executor) *Client {
	return &Client{executor: executor, limits: ber.DefaultLimits()}
}

// RequestOption adds an LDAP control to an ordinary operation.
type RequestOption interface{ applyRequest(*requestOptions) }

type requestOptions struct{ controls []ber.Marshaler }

type controlOption struct{ control rfc4511.Control }

func (o controlOption) applyRequest(options *requestOptions) {
	options.controls = append(options.controls, o.control)
}

// WithControl attaches control to an ordinary operation.
func WithControl(control rfc4511.Control) RequestOption { return controlOption{control: control} }

// ResultError reports a non-success terminal LDAP result.
type ResultError struct {
	Operation string
	Result    rfc4511.LDAPResult
	Controls  []rfc4511.Control
}

// ExecuteOption changes typed single-response result handling.
type ExecuteOption interface{ applyExecute(*executeOptions) }

type executeOptions struct {
	accepted map[rfc4511.ResultCode]struct{}
}

type acceptResultCodesOption []rfc4511.ResultCode

func (o acceptResultCodesOption) applyExecute(options *executeOptions) {
	options.accepted = make(map[rfc4511.ResultCode]struct{}, len(o))
	for _, code := range o {
		options.accepted[code] = struct{}{}
	}
}

// AcceptResultCodes replaces the default accepted result set, which contains
// only ResultSuccess.
func AcceptResultCodes(codes ...rfc4511.ResultCode) ExecuteOption {
	return acceptResultCodesOption(slices.Clone(codes))
}

func (e *ResultError) Error() string {
	return fmt.Sprintf("arden: %s failed with LDAP result code %d", e.Operation, e.Result.ResultCode)
}

// ResultCode returns the server's LDAP result code.
func (e *ResultError) ResultCode() rfc4511.ResultCode {
	return e.Result.ResultCode
}

// Is maps noSuchObject to ErrNotFound while retaining the complete LDAP result.
func (e *ResultError) Is(target error) bool {
	return target == ErrNotFound && e.Result.ResultCode == rfc4511.ResultNoSuchObject
}

// Add creates entry.
func (c *Client) Add(ctx context.Context, entry *Entry, options ...RequestOption) error {
	if entry == nil {
		return errors.New("arden: nil Add entry")
	}
	request := &rfc4511.AddRequest{Entry: entry.DN, Attributes: entry.Attributes}
	operation, err := rfc4511.NewAddOperation(request, requestControls(options))
	if err != nil {
		return err
	}
	_, _, err = c.ExecuteSingle(ctx, operation)
	return err
}

// Modify applies changes to dn in order.
func (c *Client) Modify(ctx context.Context, dn LDAPDN, changes ...Change) error {
	return c.ModifyWithOptions(ctx, dn, changes)
}

// ModifyWithOptions applies changes to dn in order and attaches request
// controls. Modify is the concise form for the usual control-free operation.
func (c *Client) ModifyWithOptions(ctx context.Context, dn LDAPDN, changes []Change, options ...RequestOption) error {
	operation, err := rfc4511.NewModifyOperation(
		&rfc4511.ModifyRequest{Object: dn, Changes: changes},
		requestControls(options),
	)
	if err != nil {
		return err
	}
	_, _, err = c.ExecuteSingle(ctx, operation)
	return err
}

// Delete removes dn.
func (c *Client) Delete(ctx context.Context, dn LDAPDN, options ...RequestOption) error {
	operation, err := rfc4511.NewDeleteOperation(&rfc4511.DeleteRequest{Entry: dn}, requestControls(options))
	if err != nil {
		return err
	}
	_, _, err = c.ExecuteSingle(ctx, operation)
	return err
}

// Compare tests a text assertion. Compare false is a successful false result.
func (c *Client) Compare(ctx context.Context, dn LDAPDN, attribute, value string, options ...RequestOption) (bool, error) {
	return c.compare(ctx, dn, attribute, []byte(value), options...)
}

// CompareBytes tests a binary assertion.
func (c *Client) CompareBytes(ctx context.Context, dn LDAPDN, attribute string, value []byte, options ...RequestOption) (bool, error) {
	return c.compare(ctx, dn, attribute, value, options...)
}

func (c *Client) compare(ctx context.Context, dn LDAPDN, attribute string, value []byte, options ...RequestOption) (bool, error) {
	request := &rfc4511.CompareRequest{Entry: dn, Assertion: rfc4511.AttributeValueAssertion{
		Type: rfc4511.AttributeDescription(attribute), Value: rfc4511.AssertionValue(value),
	}}
	operation, err := rfc4511.NewCompareOperation(request, requestControls(options))
	if err != nil {
		return false, err
	}
	response, _, err := c.ExecuteSingle(ctx, operation, AcceptResultCodes(rfc4511.ResultCompareFalse, rfc4511.ResultCompareTrue))
	if err != nil {
		return false, err
	}
	switch response.Result.ResultCode {
	case rfc4511.ResultCompareTrue:
		return true, nil
	case rfc4511.ResultCompareFalse:
		return false, nil
	default:
		return false, errors.New("arden: Compare returned an accepted non-Compare result code")
	}
}

// ModifyDN renames or moves an entry. An empty newSuperior keeps the current
// parent; deleteOldRDN controls whether the old naming values are removed.
func (c *Client) ModifyDN(ctx context.Context, dn LDAPDN, newRDN RelativeLDAPDN, deleteOldRDN bool, newSuperior LDAPDN, options ...RequestOption) error {
	request := &rfc4511.ModifyDNRequest{
		Entry: dn, NewRDN: newRDN, DeleteOldRDN: deleteOldRDN,
	}
	if newSuperior != "" {
		superior := newSuperior
		request.NewSuperior = &superior
	}
	operation, err := rfc4511.NewModifyDNOperation(request, requestControls(options))
	if err != nil {
		return err
	}
	_, _, err = c.ExecuteSingle(ctx, operation)
	return err
}

// SearchRequest describes a generic LDAP search. PageSize is client behavior,
// not part of the RFC 4511 SearchRequest wire value.
type SearchRequest struct {
	BaseDN       LDAPDN
	Scope        SearchScope
	DerefAliases DerefAliases
	SizeLimit    uint32
	TimeLimit    time.Duration
	TypesOnly    bool
	Filter       Filter
	Attributes   []string
	PageSize     uint32
}

func (r SearchRequest) protocolRequest() rfc4511.SearchRequest {
	attributes := make([]rfc4511.AttributeSelector, len(r.Attributes))
	for i, attribute := range r.Attributes {
		attributes[i] = rfc4511.AttributeSelector(attribute)
	}
	return rfc4511.SearchRequest{
		BaseObject:   r.BaseDN,
		Scope:        r.Scope,
		DerefAliases: r.DerefAliases,
		SizeLimit:    r.SizeLimit,
		TimeLimit:    r.TimeLimit,
		TypesOnly:    r.TypesOnly,
		Filter:       r.Filter,
		Attributes:   attributes,
	}
}

// Search starts a streaming search. PageSize transparently follows RFC 2696
// cookies until the server returns an empty cookie.
func (c *Client) Search(ctx context.Context, request SearchRequest, options ...RequestOption) (*Entries, error) {
	if ctx == nil {
		return nil, errors.New("arden: nil Search context")
	}
	rows := &Entries{
		ctx:     ctx,
		client:  c,
		request: request,
		options: requestOptions{controls: requestControls(options)},
	}
	if err := rows.startPage(nil); err != nil {
		return nil, err
	}
	return rows, nil
}

// Get performs a base-object lookup and requires exactly one entry.
func (c *Client) Get(ctx context.Context, dn LDAPDN, attributes ...string) (Entry, error) {
	rows, err := c.Search(ctx, SearchRequest{
		BaseDN: dn, Scope: ScopeBase, SizeLimit: 1,
		Filter: Has("objectClass"), Attributes: slices.Clone(attributes),
	})
	if err != nil {
		return Entry{}, err
	}
	// The lookup consumes the stream before returning, so Close cannot affect
	// the result being returned.
	//nolint:errcheck
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return Entry{}, err
		}
		return Entry{}, ErrNotFound
	}
	entry := rows.Entry()
	if rows.Next() {
		return Entry{}, errors.New("arden: base-object lookup returned more than one entry")
	}
	if err := rows.Err(); err != nil {
		return Entry{}, err
	}
	return entry, nil
}

// RootDSE reads the root DSE as a single entry.
func (c *Client) RootDSE(ctx context.Context, attributes ...string) (Entry, error) {
	return c.Get(ctx, "", attributes...)
}

// Entries is a streaming sequence of search entries.
type Entries struct {
	ctx       context.Context
	client    *Client
	request   SearchRequest
	options   requestOptions
	stream    *DecodedStream[rfc4511.SearchResult]
	entry     Entry
	err       error
	done      bool
	closed    bool
	controls  []rfc4511.Control
	referrals []string
}

// Next advances to the next entry, transparently crossing page boundaries.
func (r *Entries) Next() bool {
	if r.done || r.err != nil {
		return false
	}
	for {
		decoded, controls, err := r.stream.Next(r.ctx)
		if err != nil {
			r.err = err
			return false
		}
		switch value := decoded.Value().(type) {
		case rfc4511.SearchResultEntry:
			r.entry = entryFromSearchResult(value)
			return true
		case rfc4511.SearchResultReference:
			for _, uri := range value.URIs {
				r.referrals = append(r.referrals, string(uri))
			}
		case rfc4511.SearchResultDone:
			r.controls = controls
			if err := requireSuccess("search", value.Result, controls); err != nil {
				r.err = err
				return false
			}
			if err := r.stream.requireEnd(r.ctx, "arden: Search returned data after SearchResultDone"); err != nil {
				r.err = err
				return false
			}
			if err := r.closeStream(); err != nil {
				r.err = err
				return false
			}
			if r.request.PageSize == 0 {
				r.done = true
				return false
			}
			cookie, err := pagedResultsCookie(controls, r.client.limits)
			if err != nil {
				r.err = err
				return false
			}
			if len(cookie) == 0 {
				r.done = true
				return false
			}
			if err := r.startPage(cookie); err != nil {
				r.err = err
				return false
			}
		default:
			r.err = fmt.Errorf("arden: Search decoded unexpected response type %T", value)
			return false
		}
	}
}

// Entry returns the current owned entry.
func (r *Entries) Entry() Entry { return r.entry }

// Err returns the first search, decode, paging, or LDAP result error.
func (r *Entries) Err() error {
	return r.err
}

// Referrals returns referral URIs observed so far.
func (r *Entries) Referrals() []string { return slices.Clone(r.referrals) }

// Controls returns terminal controls from the latest page.
func (r *Entries) Controls() []rfc4511.Control { return slices.Clone(r.controls) }

// Close stops delivery and releases the underlying response stream.
func (r *Entries) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	r.done = true
	return r.closeStream()
}

func (r *Entries) startPage(cookie []byte) error {
	if r.stream != nil {
		return errors.New("arden: cannot start a search page before closing the previous response stream")
	}
	controls := slices.Clone(r.options.controls)
	if r.request.PageSize > 0 {
		control, err := newPagedResultsControl(r.request.PageSize, cookie)
		if err != nil {
			return err
		}
		controls = append(controls, control)
	}
	request := r.request.protocolRequest()
	operation, err := rfc4511.NewSearchOperation(&request, controls)
	if err != nil {
		return err
	}
	r.stream, err = r.client.ExecuteStream(r.ctx, operation)
	return err
}

func (r *Entries) closeStream() error {
	if r.stream == nil {
		return nil
	}
	stream := r.stream
	r.stream = nil
	return stream.Close()
}

func requestControls(options []RequestOption) []ber.Marshaler {
	var applied requestOptions
	for _, option := range options {
		if option != nil {
			option.applyRequest(&applied)
		}
	}
	return applied.controls
}

// ExecuteStream starts one typed operation and returns a stream which decodes
// each protocol response and its controls. The caller owns the returned stream
// and must close it when it finishes reading.
func (c *Client) ExecuteStream[T any](ctx context.Context, operation protocol.Operation[T]) (*DecodedStream[T], error) {
	stream, err := c.executor.Do(ctx, operation)
	if err != nil {
		return nil, err
	}
	return &DecodedStream[T]{stream: stream, responses: operation.Responses, limits: c.limits}, nil
}

// Next returns the next typed response and its decoded controls. At the end of
// the operation it returns io.EOF. Decode errors return a nil response and nil
// controls.
func (s *DecodedStream[T]) Next(ctx context.Context) (*T, []rfc4511.Control, error) {
	if s.closed {
		return nil, nil, errors.New("arden: decoded response stream is closed")
	}
	response, err := s.stream.Next(ctx)
	if err != nil {
		return nil, nil, err
	}
	decoded, err := s.responses.Decode(response, s.limits)
	if err != nil {
		return nil, nil, err
	}
	controls, err := decodeControls(response.Controls, s.limits)
	if err != nil {
		return nil, nil, err
	}
	return decoded, controls, nil
}

func (s *DecodedStream[T]) requireEnd(ctx context.Context, unexpected string) error {
	_, _, err := s.Next(ctx)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New(unexpected)
}

// Close releases the underlying response stream. It is safe to call more than
// once.
func (s *DecodedStream[T]) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	return s.stream.Close()
}

// ExecuteSingle runs one typed, terminal LDAP-result operation. It shares
// submission, decoding, control handling, and ownership with ExecuteStream,
// then additionally requires exactly one response and an accepted result code.
// Transport, stream, BER, and control-decoding errors return a nil response. A
// rejected LDAP result returns the decoded response and controls together with
// *ResultError.
func (c *Client) ExecuteSingle[T rfc4511.ResultResponse](ctx context.Context, operation protocol.Operation[T], options ...ExecuteOption) (*T, []rfc4511.Control, error) {
	stream, err := c.ExecuteStream(ctx, operation)
	if err != nil {
		return nil, nil, err
	}
	//nolint:errcheck // The terminal response determines the operation result.
	defer stream.Close()
	decoded, controls, err := stream.Next(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err := stream.requireEnd(ctx, "arden: single-response operation returned more than one response"); err != nil {
		return nil, nil, err
	}
	applied := executeOptions{accepted: map[rfc4511.ResultCode]struct{}{rfc4511.ResultSuccess: {}}}
	for _, option := range options {
		if option != nil {
			option.applyExecute(&applied)
		}
	}
	result := (*decoded).LDAPResult()
	if _, accepted := applied.accepted[result.ResultCode]; !accepted {
		operationName := operation.Metadata.Label
		if after, ok := strings.CutPrefix(operationName, "ldap."); ok {
			operationName = after
		}
		return decoded, controls, &ResultError{Operation: operationName, Result: result, Controls: controls}
	}
	return decoded, controls, nil
}

// Execute is retained as the concise form of ExecuteSingle.
func (c *Client) Execute[T rfc4511.ResultResponse](ctx context.Context, operation protocol.Operation[T], options ...ExecuteOption) (*T, []rfc4511.Control, error) {
	return c.ExecuteSingle(ctx, operation, options...)
}

func requireSuccess(operation string, result rfc4511.LDAPResult, controls []rfc4511.Control) error {
	if result.ResultCode == rfc4511.ResultSuccess {
		return nil
	}
	return &ResultError{Operation: operation, Result: result, Controls: controls}
}

func decodeControls(elements []ber.Element, limits ber.Limits) ([]rfc4511.Control, error) {
	controls := make([]rfc4511.Control, 0, len(elements))
	for _, element := range elements {
		reader, err := ber.NewReader(element.Raw, limits)
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
		controls = append(controls, control)
	}
	return controls, nil
}

func newPagedResultsControl(size uint32, cookie []byte) (rfc4511.Control, error) {
	value, err := ber.Sequence().
		Add(ber.Integer(size), ber.OctetString(cookie)).
		AppendBER(nil)
	if err != nil {
		return rfc4511.Control{}, err
	}
	return rfc4511.Control{Type: pagedResultsOID, Value: value, HasValue: true}, nil
}

func pagedResultsCookie(controls []rfc4511.Control, limits ber.Limits) ([]byte, error) {
	for _, control := range controls {
		if control.Type != pagedResultsOID {
			continue
		}
		reader, err := ber.NewReader(control.Value, limits)
		if err != nil {
			return nil, err
		}
		contents, err := reader.Sequence()
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
		if err := reader.RequireEmpty(); err != nil {
			return nil, err
		}
		return bytes.Clone(cookie), nil
	}
	return nil, errors.New("arden: paged-results response control is missing")
}
