package otelldap

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/wyattanderson/arden"
)

const defaultInstrumentationName = "github.com/wyattanderson/arden/otelldap"

// Config selects providers and the instrumentation-scope name. Nil providers
// use OpenTelemetry's process-wide providers.
type Config struct {
	TracerProvider      trace.TracerProvider
	MeterProvider       metric.MeterProvider
	InstrumentationName string
}

// Tracer implements arden.Tracer with client spans and operation metrics.
type Tracer struct {
	tracer trace.Tracer

	duration      metric.Float64Histogram
	requestBytes  metric.Int64Histogram
	responseBytes metric.Int64Histogram
	responses     metric.Int64Histogram
	operations    metric.Int64Counter
}

// New constructs an OpenTelemetry adapter and returns instrument construction
// errors to the caller.
func New(config Config) (*Tracer, error) {
	name := config.InstrumentationName
	if name == "" {
		name = defaultInstrumentationName
	}
	tracerProvider := config.TracerProvider
	if tracerProvider == nil {
		tracerProvider = otel.GetTracerProvider()
	}
	meterProvider := config.MeterProvider
	if meterProvider == nil {
		meterProvider = otel.GetMeterProvider()
	}
	meter := meterProvider.Meter(name)
	adapter := &Tracer{tracer: tracerProvider.Tracer(name)}
	var errs []error
	adapter.duration, errs = float64Histogram(meter, "arden.client.operation.duration", "LDAP operation duration", "s", errs)
	adapter.requestBytes, errs = int64Histogram(meter, "arden.client.operation.request.size", "LDAP request size", "By", errs)
	adapter.responseBytes, errs = int64Histogram(meter, "arden.client.operation.response.size", "LDAP response bytes per operation", "By", errs)
	adapter.responses, errs = int64Histogram(meter, "arden.client.operation.responses", "LDAP responses per operation", "{response}", errs)
	var err error
	adapter.operations, err = meter.Int64Counter("arden.client.operations", metric.WithDescription("Completed LDAP operations"), metric.WithUnit("{operation}"))
	if err != nil {
		errs = append(errs, err)
	}
	return adapter, errors.Join(errs...)
}

func float64Histogram(meter metric.Meter, name, description, unit string, errs []error) (metric.Float64Histogram, []error) {
	instrument, err := meter.Float64Histogram(name, metric.WithDescription(description), metric.WithUnit(unit))
	if err != nil {
		errs = append(errs, err)
	}
	return instrument, errs
}

func int64Histogram(meter metric.Meter, name, description, unit string, errs []error) (metric.Int64Histogram, []error) {
	instrument, err := meter.Int64Histogram(name, metric.WithDescription(description), metric.WithUnit(unit))
	if err != nil {
		errs = append(errs, err)
	}
	return instrument, errs
}

// Start begins one client span using safe endpoint and operation metadata.
func (t *Tracer) Start(ctx context.Context, start arden.TraceStart) (context.Context, arden.Trace) {
	attrs := []attribute.KeyValue{
		attribute.String("arden.endpoint.id", string(start.Endpoint)),
		attribute.String("arden.endpoint.address", start.EndpointAddress),
		attribute.Int64("arden.connection.id", int64(start.Connection)),
		attribute.String("arden.operation.name", start.Label),
		attribute.String("arden.ldap.application_tag", start.ApplicationTag.String()),
	}
	metricAttrs := []attribute.KeyValue{
		attribute.String("arden.endpoint.id", string(start.Endpoint)),
		attribute.String("arden.operation.name", start.Label),
		attribute.String("arden.ldap.application_tag", start.ApplicationTag.String()),
	}
	if start.MessageID != 0 {
		attrs = append(attrs, attribute.Int64("arden.ldap.message_id", int64(start.MessageID)))
	}
	name := start.Label
	if name == "" {
		name = "ldap.operation"
	}
	spanCtx, span := t.tracer.Start(ctx, name, trace.WithSpanKind(trace.SpanKindClient), trace.WithAttributes(attrs...))
	return spanCtx, &operationTrace{adapter: t, span: span, began: time.Now(), metricAttrs: metricAttrs, ctx: spanCtx}
}

type operationTrace struct {
	adapter     *Tracer
	span        trace.Span
	began       time.Time
	metricAttrs []attribute.KeyValue
	ctx         context.Context
}

func (t *operationTrace) Event(event arden.TraceEvent) {
	byteAttribute := attribute.Int64("arden.response.bytes", int64(event.Bytes))
	if event.Kind == arden.TraceWritten {
		byteAttribute = attribute.Int64("arden.request.bytes", int64(event.Bytes))
	}
	t.span.AddEvent(event.Kind.String(),
		trace.WithTimestamp(event.At),
		trace.WithAttributes(
			byteAttribute,
			attribute.Int64("arden.responses", int64(event.Responses)),
		),
	)
}

func (t *operationTrace) End(end arden.TraceEnd) {
	attrs := append(append([]attribute.KeyValue(nil), t.metricAttrs...), attribute.String("arden.error.type", end.ErrorClass))
	metricOptions := metric.WithAttributes(attrs...)
	duration := end.At.Sub(t.began).Seconds()
	t.adapter.duration.Record(t.ctx, duration, metricOptions)
	t.adapter.requestBytes.Record(t.ctx, int64(end.RequestBytes), metricOptions)
	t.adapter.responseBytes.Record(t.ctx, int64(end.ResponseBytes), metricOptions)
	t.adapter.responses.Record(t.ctx, int64(end.Responses), metricOptions)
	t.adapter.operations.Add(t.ctx, 1, metricOptions)
	t.span.SetAttributes(
		attribute.Int64("arden.request.bytes", int64(end.RequestBytes)),
		attribute.Int64("arden.response.bytes", int64(end.ResponseBytes)),
		attribute.Int64("arden.responses", int64(end.Responses)),
		attribute.String("arden.error.type", end.ErrorClass),
	)
	if end.ErrorClass != "none" && end.ErrorClass != "closed" {
		// Use only the safe classification. RecordError is deliberately avoided
		// because it would attach an underlying error message to the span.
		t.span.SetStatus(codes.Error, end.ErrorClass)
	}
	t.span.End(trace.WithTimestamp(end.At))
}

var _ arden.Tracer = (*Tracer)(nil)
