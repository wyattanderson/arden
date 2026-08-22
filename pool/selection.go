package pool

import (
	"errors"

	"github.com/wyattanderson/arden"
)

// SelectionKind identifies a pool routing strategy.
type SelectionKind uint8

// Supported pool selection strategies.
const (
	SelectionAny SelectionKind = iota + 1
	SelectionExactEndpoint
)

// Selection is an immutable routing request. Exact endpoint selection never
// silently degrades to SelectionAny.
type Selection struct {
	kind     SelectionKind
	endpoint arden.EndpointID
}

// Any selects any available endpoint.
func Any() Selection { return Selection{kind: SelectionAny} }

// Endpoint selects one specific endpoint.
func Endpoint(id arden.EndpointID) (Selection, error) {
	if err := id.Validate(); err != nil {
		return Selection{}, err
	}
	return Selection{kind: SelectionExactEndpoint, endpoint: id}, nil
}

// Kind returns the selection strategy.
func (s Selection) Kind() SelectionKind { return s.kind }

// EndpointID returns the selected endpoint for an exact-endpoint selection.
func (s Selection) EndpointID() (arden.EndpointID, bool) {
	return s.endpoint, s.kind == SelectionExactEndpoint
}

// Validate reports whether the selection is usable.
func (s Selection) Validate() error {
	switch s.kind {
	case SelectionAny:
		return nil
	case SelectionExactEndpoint:
		return s.endpoint.Validate()
	default:
		return errors.New("pool: invalid endpoint selection")
	}
}
