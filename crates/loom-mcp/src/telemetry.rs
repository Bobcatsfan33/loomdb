//! Opt-in OpenTelemetry instrumentation.
//!
//! The entire module and dependency graph are absent unless the `observability` feature is selected.
//! Labels are deliberately low-cardinality and exclude tenant IDs, request IDs, arguments, tokens,
//! keys, source text, and response bodies.

use std::error::Error;
use std::time::{Duration, SystemTime};

use opentelemetry::metrics::{Counter, Histogram, MeterProvider as _};
use opentelemetry::trace::{Span as _, Status, Tracer as _, TracerProvider as _};
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::{SdkTracer, SdkTracerProvider};
use opentelemetry_sdk::Resource;

use crate::Response;

/// One completed request, containing only approved, bounded-cardinality dimensions.
pub struct RequestObservation<'a> {
    /// JSON-RPC method.
    pub method: &'a str,
    /// MCP tool name, or `"none"` for non-tool methods.
    pub tool: &'a str,
    /// End-to-end request duration.
    pub duration: Duration,
    /// Final JSON-RPC response.
    pub response: &'a Response,
}

/// Instrumentation seam used by `LoomServer`; custom enterprise exporters can implement it without
/// changing the database surface.
pub trait RequestObserver: Send + Sync {
    /// Record one completed request.
    fn record(&self, observation: RequestObservation<'_>);
}

/// OTLP/HTTP exporter for traces and metrics. Endpoint, headers, timeout, compression, and signal-
/// specific overrides use the standard `OTEL_EXPORTER_OTLP_*` environment variables.
pub struct OtlpTelemetry {
    tracer_provider: SdkTracerProvider,
    meter_provider: SdkMeterProvider,
    tracer: SdkTracer,
    requests: Counter<u64>,
    failures: Counter<u64>,
    denied: Counter<u64>,
    duration: Histogram<f64>,
}

impl OtlpTelemetry {
    /// Build both exporters. Construction errors are returned so an explicitly enabled deployment
    /// fails closed instead of silently running without telemetry.
    pub fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        let resource = Resource::builder()
            .with_service_name("loomd")
            .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
            .build();

        let span_exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .build()?;
        let tracer_provider = SdkTracerProvider::builder()
            .with_resource(resource.clone())
            .with_batch_exporter(span_exporter)
            .build();
        let tracer = tracer_provider.tracer("loomd.request");

        let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .build()?;
        let meter_provider = SdkMeterProvider::builder()
            .with_resource(resource)
            .with_periodic_exporter(metric_exporter)
            .build();
        let meter = meter_provider.meter("loomd.request");

        Ok(Self {
            tracer_provider,
            meter_provider,
            tracer,
            requests: meter
                .u64_counter("loomd.rpc.requests")
                .with_description("Completed JSON-RPC requests")
                .build(),
            failures: meter
                .u64_counter("loomd.rpc.failures")
                .with_description("JSON-RPC error responses")
                .build(),
            denied: meter
                .u64_counter("loomd.rpc.denied")
                .with_description("Policy or capability denials")
                .build(),
            duration: meter
                .f64_histogram("loomd.rpc.duration")
                .with_unit("s")
                .with_description("End-to-end JSON-RPC request duration")
                .build(),
        })
    }

    /// Flush and stop both providers. This is idempotence-protected by the SDK and should be called
    /// after stdin closes so the last telemetry batch is not lost.
    pub fn shutdown(&self) -> Result<(), String> {
        let trace = self.tracer_provider.shutdown().map_err(|e| e.to_string());
        let metrics = self.meter_provider.shutdown().map_err(|e| e.to_string());
        trace.and(metrics)
    }
}

impl RequestObserver for OtlpTelemetry {
    fn record(&self, observation: RequestObservation<'_>) {
        let outcome = if observation.response.error.is_none() {
            "ok"
        } else if observation.response.error.as_ref().map(|error| error.code)
            == Some(crate::codes::DENIED)
        {
            "denied"
        } else {
            "error"
        };
        let method = known_method(observation.method);
        let tool = known_tool(observation.tool);
        let attributes = [
            KeyValue::new("rpc.system", "jsonrpc"),
            KeyValue::new("rpc.method", method),
            KeyValue::new("loom.tool", tool),
            KeyValue::new("loom.outcome", outcome),
        ];

        self.requests.add(1, &attributes);
        self.duration
            .record(observation.duration.as_secs_f64(), &attributes);
        if outcome == "denied" {
            self.denied.add(1, &attributes);
        } else if outcome == "error" {
            self.failures.add(1, &attributes);
        }

        let start = SystemTime::now()
            .checked_sub(observation.duration)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let mut span = self
            .tracer
            .span_builder("loomd.rpc")
            .with_start_time(start)
            .with_attributes(attributes)
            .start(&self.tracer);
        if outcome != "ok" {
            span.set_status(Status::error(outcome));
        }
        span.end();
    }
}

fn known_method(method: &str) -> &'static str {
    match method {
        "initialize" => "initialize",
        "tools/list" => "tools/list",
        "tools/call" => "tools/call",
        _ => "unknown",
    }
}

fn known_tool(tool: &str) -> &'static str {
    match tool {
        "session.open" => "session.open",
        "observe" => "observe",
        "branch.create" => "branch.create",
        "claim.assert" => "claim.assert",
        "read" => "read",
        "retrieve" => "retrieve",
        "branch.merge" => "branch.merge",
        "branch.rewind" => "branch.rewind",
        "action.propose" => "action.propose",
        "audit.taint" => "audit.taint",
        "none" => "none",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::{known_method, known_tool};

    #[test]
    fn telemetry_dimensions_are_allow_listed_against_cardinality_and_secret_leaks() {
        assert_eq!(known_method("tools/call"), "tools/call");
        assert_eq!(known_tool("read"), "read");
        assert_eq!(known_method("secret/customer/123"), "unknown");
        assert_eq!(known_tool("token=super-secret"), "unknown");
    }
}
