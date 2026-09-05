package ldapmodel

import (
	"context"
	"errors"

	"github.com/wyattanderson/arden"
)

var (
	// ErrNotUnique reports that One observed more than one matching entry.
	ErrNotUnique = errors.New("ldapmodel: result is not unique")

	// ErrEmptyPatch reports an Update with no generated LDAP changes.
	ErrEmptyPatch = errors.New("ldapmodel: patch contains no changes")
)

// DAO is the generic entry point for one model. It borrows the Arden client
// and does not own the client's connection or pool.
type DAO[T any] struct {
	ctx    context.Context
	client *arden.Client
	model  Model[T]
}

// NewDAO binds a model to an Arden client. Use WithContext to attach an
// operation context; without it, operations use context.Background.
func NewDAO[T any](client *arden.Client, model Model[T]) DAO[T] {
	return DAO[T]{ctx: context.Background(), client: client, model: model}
}

// WithContext returns a copy whose terminal operations use ctx.
func (d DAO[T]) WithContext(ctx context.Context) DAO[T] {
	d.ctx = ctx
	return d
}

// Where starts a result set with one or more model-specific predicates.
// Predicates are combined with AND.
func (d DAO[T]) Where(first Criterion[T], rest ...Criterion[T]) ResultSet[T] {
	criteria := append([]Criterion[T]{first}, rest...)
	return ResultSet[T]{dao: d, criteria: criteria}
}

// ResultSet is an immutable fluent query. All, One, and First fully own and
// close their LDAP searches. Stream transfers that responsibility explicitly.
type ResultSet[T any] struct {
	dao      DAO[T]
	criteria []Criterion[T]
}

// Where adds predicates to the result set and returns a copy.
func (r ResultSet[T]) Where(first Criterion[T], rest ...Criterion[T]) ResultSet[T] {
	criteria := make([]Criterion[T], 0, len(r.criteria)+1+len(rest))
	criteria = append(criteria, r.criteria...)
	criteria = append(criteria, first)
	criteria = append(criteria, rest...)
	r.criteria = criteria
	return r
}

// All returns every matching value and closes the LDAP search before returning.
func (r ResultSet[T]) All() (values []T, err error) {
	stream, closeStream, err := r.Stream()
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, closeStream())
	}()

	for stream.Next() {
		values = append(values, stream.Value())
	}
	return values, stream.Err()
}

// One returns exactly one matching value. No match returns arden.ErrNotFound;
// multiple matches return ErrNotUnique. The LDAP search is always closed.
func (r ResultSet[T]) One() (value T, err error) {
	stream, closeStream, err := r.open(2, 0)
	if err != nil {
		return value, err
	}
	defer func() {
		err = errors.Join(err, closeStream())
	}()

	if !stream.Next() {
		if err := stream.Err(); err != nil {
			return value, err
		}
		return value, arden.ErrNotFound
	}
	value = stream.Value()
	if stream.Next() {
		var zero T
		return zero, ErrNotUnique
	}
	if err := stream.Err(); err != nil {
		var zero T
		return zero, err
	}
	return value, nil
}

// First returns the first matching value and closes the search. No match
// returns arden.ErrNotFound.
func (r ResultSet[T]) First() (value T, err error) {
	stream, closeStream, err := r.open(1, 0)
	if err != nil {
		return value, err
	}
	defer func() {
		err = errors.Join(err, closeStream())
	}()

	if !stream.Next() {
		if err := stream.Err(); err != nil {
			return value, err
		}
		return value, arden.ErrNotFound
	}
	return stream.Value(), nil
}

// Stream starts a paged LDAP search. The returned close function must be
// called, including when iteration stops early.
func (r ResultSet[T]) Stream() (Stream[T], func() error, error) {
	return r.open(0, defaultPageSize)
}

func (r ResultSet[T]) open(sizeLimit, pageSize uint32) (Stream[T], func() error, error) {
	filters := make([]arden.Filter, 1, len(r.criteria)+1)
	filters[0] = r.dao.model.filter
	for _, criterion := range r.criteria {
		filters = append(filters, criterion.filter)
	}
	entries, err := r.dao.client.Search(r.dao.ctx, arden.SearchRequest{
		BaseDN:       r.dao.model.baseDN,
		Scope:        r.dao.model.scope,
		DerefAliases: arden.DerefNever,
		SizeLimit:    sizeLimit,
		Filter:       arden.All(filters...),
		Attributes:   r.dao.model.attributes,
		PageSize:     pageSize,
	})
	if err != nil {
		return nil, nil, err
	}
	stream := &entryStream[T]{entries: entries, decode: r.dao.model.decode}
	return stream, entries.Close, nil
}

// Stream is the read side of a streaming result set. Lifecycle ownership is
// represented separately by the close function returned from ResultSet.Stream.
type Stream[T any] interface {
	Next() bool
	Value() T
	Err() error
}

type entryStream[T any] struct {
	entries *arden.Entries
	decode  func(arden.Entry) (T, error)
	value   T
	err     error
}

func (s *entryStream[T]) Next() bool {
	if s.err != nil || !s.entries.Next() {
		return false
	}
	value, err := s.decode(s.entries.Entry())
	if err != nil {
		s.err = err
		return false
	}
	s.value = value
	return true
}

func (s *entryStream[T]) Value() T { return s.value }

func (s *entryStream[T]) Err() error {
	if s.err != nil {
		return s.err
	}
	return s.entries.Err()
}
