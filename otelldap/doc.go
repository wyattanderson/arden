// Package otelldap adapts Arden's dependency-free lifecycle hooks to
// OpenTelemetry spans and metrics. It records only the safe metadata supplied
// by arden.Tracer; BER payloads and directory values never cross the adapter.
package otelldap
