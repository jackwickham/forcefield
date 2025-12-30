use anyhow::Result;
use axum::{
    Router,
    body::Body,
    extract::Request,
    http::{
        HeaderValue, Response,
        header::{
            CONTENT_SECURITY_POLICY, REFERRER_POLICY, STRICT_TRANSPORT_SECURITY, X_XSS_PROTECTION,
        },
    },
    middleware::{self, Next},
    routing::{get, post},
};
use tower_http::services::ServeDir;

use crate::{
    check_auth::check_auth,
    config::ForcefieldConfig,
    cookies::auto_cookie_middleware,
    index::index_handler,
    login::{hash_password, login, logout, show_login},
    state::ForcefieldState,
};

pub mod config;

mod authenticated_user;
mod check_auth;
mod cookies;
mod index;
mod login;
mod state;

pub async fn start_server() -> Result<()> {
    let config = ForcefieldConfig::load()?;
    let app = create_app(config);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000")
        .await
        .expect("Failed to start listening on 0.0.0.0:8000");
    println!("Listening on 0.0.0.0:8000");
    Ok(axum::serve(listener, app).await?)
}

pub fn create_app(config: ForcefieldConfig) -> Router<()> {
    let mut app_builder = Router::<ForcefieldState>::new()
        .route("/", get(index_handler))
        .route("/check-auth", get(check_auth))
        .route("/login", get(show_login).post(login))
        .route("/logout", get(logout))
        .nest_service("/static", ServeDir::new("static"));
    if config.enable_hash_password {
        app_builder = app_builder.route("/hash-password", post(hash_password));
    }

    app_builder
        .layer(middleware::from_fn(auto_cookie_middleware))
        .layer(middleware::from_fn(response_headers_middleware))
        .with_state(
            config
                .try_into()
                .expect("Failed to convert config to state"),
        )
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

    res
}
