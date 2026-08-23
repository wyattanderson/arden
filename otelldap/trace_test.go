package otelldap

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ber"
)

func TestAdapterCreatesSafeOrderedClientSpan(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider()
	provider.RegisterSpanProcessor(recorder)
	adapter, err := New(Config{TracerProvider: provider})
	require.NoError(t, err)
	started := time.Now()
	_, operation := adapter.Start(context.Background(), arden.TraceStart{
		Endpoint:        "ipa-west",
		EndpointAddress: "ipa-west.example:636",
		Connection:      42,
		Label:           "ldap.search",
		ApplicationTag:  ber.Identifier{Class: ber.ClassApplication, Constructed: true, Number: 3},
	})
	operation.Event(arden.TraceEvent{Kind: arden.TraceQueued, At: started})
	operation.Event(arden.TraceEvent{Kind: arden.TraceWritten, At: started.Add(time.Millisecond), Bytes: 100})
	operation.End(arden.TraceEnd{
		At:            started.Add(2 * time.Millisecond),
		RequestBytes:  100,
		ResponseBytes: 200,
		Responses:     2,
		ErrorClass:    "transport",
	})

	ended := recorder.Ended()
	require.Len(t, ended, 1)
	span := ended[0]
	require.Equal(t, "ldap.search", span.Name())
	require.Equal(t, oteltrace.SpanKindClient, span.SpanKind())
	require.Equal(t, codes.Error, span.Status().Code)
	require.Equal(t, "transport", span.Status().Description)
	events := span.Events()
	require.Len(t, events, 2)
	require.Equal(t, "queued", events[0].Name)
	require.Equal(t, "written", events[1].Name)
	attrs := make(map[string]string)
	for _, attr := range span.Attributes() {
		attrs[string(attr.Key)] = fmt.Sprint(attr.Value.AsInterface())
	}
	assert.Equal(t, "ipa-west", attrs["arden.endpoint.id"])
	assert.Equal(t, "ipa-west.example:636", attrs["arden.endpoint.address"])
	assert.Equal(t, "42", attrs["arden.connection.id"])
	assert.NotContains(t, attrs, "arden.ldap.message_id")
}
