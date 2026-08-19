package pool

import (
	"errors"

	"github.com/wyattanderson/arden"
)

type SelectionKind uint8

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

func Any() Selection { return Selection{kind: SelectionAny} }

func Endpoint(id arden.EndpointID) (Selection, error) {
	if err := id.Validate(); err != nil {
		return Selection{}, err
	}
	return Selection{kind: SelectionExactEndpoint, endpoint: id}, nil
}

func (s Selection) Kind() SelectionKind { return s.kind }

func (s Selection) EndpointID() (arden.EndpointID, bool) {
	return s.endpoint, s.kind == SelectionExactEndpoint
}

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
