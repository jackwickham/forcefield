use std::{sync::OnceLock, time::Duration};

use anyhow::Result;
use opentelemetry::{
    KeyValue, global,
    metrics::{Counter, Histogram},
};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{Resource, metrics::SdkMeterProvider};

pub fn init_metrics(otlp_endpoint: &str) -> Result<SdkMeterProvider> {
    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_endpoint(otlp_endpoint)
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build OTLP metrics exporter: {e}"))?;

    let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter)
        .with_interval(Duration::from_secs(60))
        .build();

    let resource = Resource::builder()
        .with_service_name("forcefield")
        .build();

    let provider = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(reader)
        .build();

    global::set_meter_provider(provider.clone());
    Ok(provider)
}

fn meter() -> opentelemetry::metrics::Meter {
    global::meter("forcefield")
}

static HTTP_REQUEST_DURATION: OnceLock<Histogram<f64>> = OnceLock::new();

pub fn http_request_duration() -> &'static Histogram<f64> {
    HTTP_REQUEST_DURATION.get_or_init(|| {
        meter()
            .f64_histogram("http.server.request.duration")
            .with_unit("s")
            .with_description("Duration of HTTP server requests in seconds")
            .build()
    })
}

static LOGIN_RESULTS: OnceLock<Counter<u64>> = OnceLock::new();

pub fn record_login(success: bool) {
    let counter = LOGIN_RESULTS.get_or_init(|| {
        meter()
            .u64_counter("forcefield.login.attempts.total")
            .with_description("Number of login attempts")
            .build()
    });
    let result = if success { "success" } else { "failure" };
    counter.add(1, &[KeyValue::new("result", result)]);
}

static CHECK_AUTH_RESULTS: OnceLock<Counter<u64>> = OnceLock::new();

pub fn record_check_auth(authenticated: bool) {
    let counter = CHECK_AUTH_RESULTS.get_or_init(|| {
        meter()
            .u64_counter("forcefield.check_auth.requests.total")
            .with_description("Number of check-auth requests")
            .build()
    });
    let result = if authenticated {
        "authenticated"
    } else {
        "unauthenticated"
    };
    counter.add(1, &[KeyValue::new("result", result)]);
}
