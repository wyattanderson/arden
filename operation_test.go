package arden_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	typedResponse = ber.Identifier{Class: ber.ClassApplication, Number: 30}
)

type rawOperation struct {
	id    ber.Identifier
	value []byte
}

type rawUnmarshaler struct {
	id    ber.Identifier
	value []byte
}

type typedRawResponse struct{ value []byte }

func (r *typedRawResponse) UnmarshalBER(reader *ber.Reader) error {
	value, err := reader.Primitive(typedResponse)
	if err != nil {
		return err
	}
	r.value = append([]byte(nil), value...)
	return nil
}

func (u *rawUnmarshaler) UnmarshalBER(r *ber.Reader) error {
	value, err := r.Primitive(u.id)
	if err != nil {
		return err
	}
	u.value = append(u.value[:0], value...)
	return nil
}

func (o rawOperation) ProtocolIdentifier() ber.Identifier { return o.id }
func (o rawOperation) BERPacket() ber.Packet              { return ber.Encoded(o.value) }
func (o rawOperation) AppendBER(dst []byte) ([]byte, error) {
	return append(dst, o.value...), nil
}

func TestResponsePatternIsImmutableAndTagOnly(t *testing.T) {
	continuing := []ber.Identifier{searchEntry, searchRef}
	terminal := []ber.Identifier{searchDone}
	pattern, err := arden.NewResponsePattern[rawUnmarshaler](arden.ResponseSpec{
		Continue: continuing,
		Complete: terminal,
	})
	require.NoError(t, err)

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
		assert.Equal(t, test.want, pattern.Classify(test.id))
	}
}

func TestPatternRejectsOverlapAndNonApplicationIdentifiers(t *testing.T) {
	for _, spec := range []arden.ResponseSpec{
		{Continue: []ber.Identifier{searchDone}, Complete: []ber.Identifier{searchDone}},
		{Complete: []ber.Identifier{{Class: ber.ClassUniversal, Constructed: true, Number: 5}}},
		{NoResponse: true, Complete: []ber.Identifier{searchDone}},
	} {
		_, err := arden.NewResponsePattern[rawUnmarshaler](spec)
		assert.Error(t, err)
	}
}

func TestResponsePatternDecodesToNewTypedPointer(t *testing.T) {
	pattern, err := arden.NewResponsePattern[typedRawResponse](arden.ResponseSpec{
		Complete: []ber.Identifier{typedResponse},
	})
	require.NoError(t, err)
	encoded, err := ber.Primitive(typedResponse, []byte("decoded")).AppendBER(nil)
	require.NoError(t, err)

	decoded, err := pattern.Decode(arden.Response{ProtocolID: typedResponse, Protocol: encoded}, ber.DefaultLimits())
	require.NoError(t, err)
	require.NotNil(t, decoded)
	assert.Equal(t, []byte("decoded"), decoded.value)

	decoded, err = pattern.Decode(arden.Response{ProtocolID: typedResponse, Protocol: []byte{0x01}}, ber.DefaultLimits())
	assert.Nil(t, decoded)
	require.Error(t, err)

	decoded, err = pattern.Decode(arden.Response{ProtocolID: modifyDone, Protocol: encoded}, ber.DefaultLimits())
	assert.Nil(t, decoded)
	require.Error(t, err)
}

func TestNoResponsePatternUsesDefaultNoResponseType(t *testing.T) {
	pattern := arden.NewNoResponsePattern()
	assert.True(t, pattern.Valid())
	assert.True(t, pattern.NoResponse())
	assert.Equal(t, arden.ClassificationInvalid, pattern.Classify(typedResponse))
	decoded, err := pattern.Decode(arden.Response{}, ber.DefaultLimits())
	assert.Nil(t, decoded)
	require.Error(t, err)

	op := arden.Operation[arden.NoResponse]{
		Protocol:     rawOperation{id: searchRequest, value: []byte{0x63, 0x00}},
		Responses:    pattern,
		Cancellation: arden.CancelNone,
	}
	require.NoError(t, op.Validate())
	assert.True(t, op.Untyped().Responses.NoResponse())
}

func TestCompileOnlyContracts(t *testing.T) {
	pattern, err := arden.NewResponsePattern[rawUnmarshaler](arden.ResponseSpec{Complete: []ber.Identifier{searchDone}})
	require.NoError(t, err)
	op := arden.Operation[rawUnmarshaler]{
		Protocol:     rawOperation{id: searchRequest, value: []byte{0x63, 0x00}},
		Responses:    pattern,
		Cancellation: arden.CancelDrain,
		Metadata:     arden.OperationMetadata{Label: "root-dse"},
	}
	require.NoError(t, op.Validate())

	selection, err := pool.Endpoint(arden.EndpointID("ipa-west"))
	require.NoError(t, err)
	if got, ok := selection.EndpointID(); !ok || got != "ipa-west" {
		assert.True(t, ok)
		assert.Equal(t, arden.EndpointID("ipa-west"), got)
	}

	var _ arden.Authentication = authenticationContract{}
	var _ arden.Authenticator = authenticatorContract{}
	var _ arden.Initializer[profile] = initializerContract{}
	var _ arden.Tracer = tracerContract{}
	var _ ber.Unmarshaler = (*rawUnmarshaler)(nil)
}

func TestResponseUnmarshalProtocol(t *testing.T) {
	id := ber.Identifier{Class: ber.ClassApplication, Number: 9}
	protocol, err := ber.Primitive(id, []byte("result")).AppendBER(nil)
	require.NoError(t, err)
	response := arden.Response{
		MessageID:  7,
		ProtocolID: id,
		Bytes:      protocol,
		Protocol:   protocol,
	}

	var decoded rawUnmarshaler
	decoded.id = id
	require.NoError(t, response.UnmarshalProtocol(&decoded, ber.DefaultLimits()))
	require.Equal(t, "result", string(decoded.value))

	withTrailing := response
	withTrailing.Protocol = append(append([]byte(nil), protocol...), 0x05, 0x00)
	require.ErrorIs(t, withTrailing.UnmarshalProtocol(&rawUnmarshaler{id: id}, ber.DefaultLimits()), ber.ErrTrailingData)
}

func TestTransportErrorIdentity(t *testing.T) {
	unsent := &arden.TransportError{Stage: arden.StageDial, Outcome: arden.OutcomeDefinitelyUnsent, Err: context.DeadlineExceeded}
	require.ErrorIs(t, unsent, arden.ErrTransport)
	require.ErrorIs(t, unsent, arden.ErrDefinitelyUnsent)
	require.ErrorIs(t, unsent, context.DeadlineExceeded)
	require.NotErrorIs(t, unsent, arden.ErrAmbiguousOutcome)

	ambiguous := &arden.TransportError{Stage: arden.StageWrite, Outcome: arden.OutcomeAmbiguous, Err: errors.New("short write")}
	require.ErrorIs(t, ambiguous, arden.ErrAmbiguousOutcome)
	require.NotErrorIs(t, ambiguous, arden.ErrDefinitelyUnsent)
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
