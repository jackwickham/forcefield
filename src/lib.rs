use std::{str::FromStr, sync::Arc, time::Instant};

use anyhow::Result;
use axum::{
    Router,
    body::Body,
    extract::Request,
    handler::Handler,
    http::{
        HeaderName, HeaderValue, Response,
        header::{
            CONTENT_SECURITY_POLICY, REFERRER_POLICY, STRICT_TRANSPORT_SECURITY,
            X_CONTENT_TYPE_OPTIONS, X_XSS_PROTECTION,
        },
    },
    middleware::{self, Next},
    routing::{get, post},
};
use opentelemetry::KeyValue;
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tower_http::services::ServeDir;

use crate::{
    check_auth::check_auth,
    config::ForcefieldConfig,
    cookies::auto_cookie_middleware,
    index::index_handler,
    login::{hash_password, login, logout, show_login},
    rate_limit::ClientIpKeyExtractor,
    same_origin::same_origin,
    state::ForcefieldState,
};

pub mod config;
pub mod metrics;

mod authenticated_user;
mod check_auth;
mod cookies;
mod index;
mod login;
mod rate_limit;
mod same_origin;
mod state;

pub async fn start_server() -> Result<()> {
    let config = ForcefieldConfig::load()?;
    let _metrics_provider = config
        .otlp_endpoint
        .as_deref()
        .map(metrics::init_metrics)
        .transpose()?;
    let app = create_app(config);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000")
        .await
        .expect("Failed to start listening on 0.0.0.0:8000");
    println!("Listening on 0.0.0.0:8000");
    Ok(axum::serve(listener, app).await?)
}

pub fn create_app(config: ForcefieldConfig) -> Router<()> {
    let client_ip_header = config
        .client_ip_header
        .as_ref()
        .map(|name| HeaderName::from_str(name).expect("Failed to parse IP extractor header"));
    let enable_hash_password = config.enable_hash_password;

    let state: ForcefieldState = config
        .try_into()
        .expect("Failed to convert config to state");

    let login_rate_limiter = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(1)
            .burst_size(2)
            .key_extractor(ClientIpKeyExtractor::new(client_ip_header))
            .finish()
            .expect("Failed to build rate limiter config"),
    );

    let login_handler = login
        .layer(GovernorLayer::new(login_rate_limiter))
        .layer(middleware::from_fn_with_state(state.clone(), same_origin));
    let mut app_builder = Router::<ForcefieldState>::new()
        .route("/", get(index_handler))
        .route("/check-auth", get(check_auth))
        .route("/login", get(show_login).post(login_handler))
        .route("/logout", get(logout))
        .nest_service("/static", ServeDir::new("static"));

    if enable_hash_password {
        app_builder = app_builder.route("/hash-password", post(hash_password));
    }

    app_builder
        .layer(middleware::from_fn(auto_cookie_middleware))
        .layer(middleware::from_fn(response_headers_middleware))
        .layer(middleware::from_fn(request_metrics_middleware))
        .with_state(state)
}

async fn request_metrics_middleware(req: Request, next: Next) -> Response<Body> {
    let method = req.method().to_string();
    let path = req.uri().path().to_owned();
    let start = Instant::now();

    let response = next.run(req).await;

    let duration = start.elapsed().as_secs_f64();
    let status = response.status().as_u16() as i64;
    metrics::http_request_duration().record(
        duration,
        &[
            KeyValue::new("http.request.method", method),
            KeyValue::new("url.path", path),
            KeyValue::new("http.response.status_code", status),
        ],
    );

    response
}

async fn response_headers_middleware(req: Request, next: Next) -> Response<Body> {
    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(concat!(
            "default-src 'self'; ",
            "script-src 'none'; ",
            "object-src 'none'; ",
            "base-uri 'none'; ",
            "frame-ancestors 'none'; ",
        )),
    );
    headers.insert(X_XSS_PROTECTION, HeaderValue::from_static("0"));
    headers.insert(
        STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31104000; includeSubDomains"), // 1y
    );
    headers.insert(
        REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));

    res
}
