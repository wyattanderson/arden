package arden_test

import (
	"context"
	"errors"
	"testing"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/pool"
)

var (
	searchRequest = ber.Identifier{Class: ber.ClassApplication, Constructed: true, Number: 3}
	searchEntry   = ber.Identifier{Class: ber.ClassApplication, Constructed: true, Number: 4}
	searchDone    = ber.Identifier{Class: ber.ClassApplication, Constructed: true, Number: 5}
	searchRef     = ber.Identifier{Class: ber.ClassApplication, Constructed: true, Number: 19}
	modifyDone    = ber.Identifier{Class: ber.ClassApplication, Constructed: true, Number: 7}
)

type rawOperation struct {
	id    ber.Identifier
	value []byte
}

func (o rawOperation) ProtocolIdentifier() ber.Identifier { return o.id }
func (o rawOperation) AppendBER(dst []byte) ([]byte, error) {
	return append(dst, o.value...), nil
}

func TestResponsePatternIsImmutableAndTagOnly(t *testing.T) {
	continuing := []ber.Identifier{searchEntry, searchRef}
	terminal := []ber.Identifier{searchDone}
	pattern, err := arden.NewResponsePattern(arden.ResponseSpec{
		Continue: continuing,
		Complete: terminal,
	})
	if err != nil {
		t.Fatal(err)
	}

	continuing[0] = modifyDone
	terminal[0] = modifyDone

	for _, test := range []struct {
		id   ber.Identifier
		want arden.Classification
	}{
		{searchEntry, arden.ClassificationContinue},
		{searchRef, arden.ClassificationContinue},
		{searchDone, arden.ClassificationComplete},
		{modifyDone, arden.ClassificationInvalid},
	} {
		if got := pattern.Classify(test.id); got != test.want {
			t.Errorf("Classify(%s) = %v, want %v", test.id, got, test.want)
		}
	}
}

func TestPatternRejectsOverlapAndNonApplicationIdentifiers(t *testing.T) {
	for _, spec := range []arden.ResponseSpec{
		{Continue: []ber.Identifier{searchDone}, Complete: []ber.Identifier{searchDone}},
		{Complete: []ber.Identifier{{Class: ber.ClassUniversal, Constructed: true, Number: 5}}},
		{NoResponse: true, Complete: []ber.Identifier{searchDone}},
	} {
		if _, err := arden.NewResponsePattern(spec); err == nil {
			t.Fatalf("NewResponsePattern(%+v) succeeded", spec)
		}
	}
}

func TestCompileOnlyContracts(t *testing.T) {
	pattern, err := arden.NewResponsePattern(arden.ResponseSpec{Complete: []ber.Identifier{searchDone}})
	if err != nil {
		t.Fatal(err)
	}
	op := arden.Operation{
		Protocol:     rawOperation{id: searchRequest, value: []byte{0x63, 0x00}},
		Responses:    pattern,
		Cancellation: arden.CancelDrain,
		Metadata:     arden.OperationMetadata{Label: "root-dse"},
	}
	if err := op.Validate(); err != nil {
		t.Fatal(err)
	}

	selection, err := pool.Endpoint(arden.EndpointID("ipa-west"))
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := selection.EndpointID(); !ok || got != "ipa-west" {
		t.Fatalf("EndpointID() = %q, %v", got, ok)
	}

	var _ arden.Authentication = authenticationContract{}
	var _ arden.Authenticator = authenticatorContract{}
	var _ arden.Initializer[profile] = initializerContract{}
	var _ arden.Tracer = tracerContract{}
}

func TestTransportErrorIdentity(t *testing.T) {
	unsent := &arden.TransportError{Stage: arden.StageDial, Outcome: arden.OutcomeDefinitelyUnsent, Err: context.DeadlineExceeded}
	if !errors.Is(unsent, arden.ErrTransport) || !errors.Is(unsent, arden.ErrDefinitelyUnsent) ||
		!errors.Is(unsent, context.DeadlineExceeded) || errors.Is(unsent, arden.ErrAmbiguousOutcome) {
		t.Fatalf("unexpected unsent error identity: %v", unsent)
	}

	ambiguous := &arden.TransportError{Stage: arden.StageWrite, Outcome: arden.OutcomeAmbiguous, Err: errors.New("short write")}
	if !errors.Is(ambiguous, arden.ErrAmbiguousOutcome) || errors.Is(ambiguous, arden.ErrDefinitelyUnsent) {
		t.Fatalf("unexpected ambiguous error identity: %v", ambiguous)
	}
}

type profile struct{ Vendor []byte }

type authenticationContract struct{}

func (authenticationContract) Begin(context.Context, arden.Endpoint) (arden.Authenticator, error) {
	return authenticatorContract{}, nil
}

type authenticatorContract struct{}

func (authenticatorContract) Authenticate(context.Context, arden.InitializationSession) (arden.Identity, error) {
	return arden.Identity{StableID: "principal-id"}, nil
}
func (authenticatorContract) Close() error { return nil }

type initializerContract struct{}

func (initializerContract) Initialize(context.Context, arden.InitializationSession) (profile, arden.ConnectionPolicy, error) {
	return profile{}, arden.ConnectionPolicy{Cancellation: arden.CancellationConservative}, nil
}

type tracerContract struct{}

func (tracerContract) Start(ctx context.Context, _ arden.TraceStart) (context.Context, arden.Trace) {
	return ctx, traceContract{}
}

type traceContract struct{}

func (traceContract) Event(arden.TraceEvent) {}
func (traceContract) End(arden.TraceEnd)     {}
