package otelldap

import (
	"context"
	"fmt"
	"testing"
	"time"

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
	if err != nil {
		t.Fatal(err)
	}
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
	if len(ended) != 1 {
		t.Fatalf("ended spans = %d, want 1", len(ended))
	}
	span := ended[0]
	if span.Name() != "ldap.search" || span.SpanKind() != oteltrace.SpanKindClient {
		t.Fatalf("span identity = %q, %v", span.Name(), span.SpanKind())
	}
	if span.Status().Code != codes.Error || span.Status().Description != "transport" {
		t.Fatalf("span status = %#v", span.Status())
	}
	if events := span.Events(); len(events) != 2 || events[0].Name != "queued" || events[1].Name != "written" {
		t.Fatalf("span events = %#v", events)
	}
	attrs := make(map[string]string)
	for _, attr := range span.Attributes() {
		attrs[string(attr.Key)] = fmt.Sprint(attr.Value.AsInterface())
	}
	if attrs["arden.endpoint.id"] != "ipa-west" || attrs["arden.endpoint.address"] != "ipa-west.example:636" || attrs["arden.connection.id"] != "42" {
		t.Fatalf("safe span attributes = %#v", attrs)
	}
	if _, exists := attrs["arden.ldap.message_id"]; exists {
		t.Fatal("zero/default message ID was attached")
	}
}
