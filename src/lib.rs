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
use axum_extra::extract::cookie::Key;
use base64::Engine;
use time::Duration;
use tower_http::services::ServeDir;
use url::Url;

use crate::{
    check_auth::check_auth,
    config::Config,
    cookies::auto_cookie_middleware,
    index::index_handler,
    login::{hash_password, login, logout, show_login},
    state::{ForcefieldState, InnerForcefieldState},
};

mod authenticated_user;
mod check_auth;
mod config;
mod cookies;
mod index;
mod login;
mod state;

pub async fn start_server_with_default_config() -> Result<(), std::io::Error> {
    start_server(Config {
        public_root: Url::parse("http://localhost:8000").expect("Failed to parse root URL"),
        root_domain: "localhost".to_owned(),
        secret_key: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_owned(),
        login_cookie_expiration: Duration::hours(1),
        enable_hash_password: true,
        users: vec![],
    })
    .await
}

pub async fn start_server(config: Config) -> Result<(), std::io::Error> {
    let mut app_builder = Router::<ForcefieldState>::new()
        .route("/", get(index_handler))
        .route("/check-auth", get(check_auth))
        .route("/login", get(show_login).post(login))
        .route("/logout", get(logout))
        .nest_service("/static", ServeDir::new("static"));
    if config.enable_hash_password {
        app_builder = app_builder.route("/hash-password", post(hash_password));
    }

    let app = app_builder
        .layer(middleware::from_fn(auto_cookie_middleware))
        .layer(middleware::from_fn(response_headers_middleware))
        .with_state(initial_state(config));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000")
        .await
        .expect("Failed to start listening on 0.0.0.0:8000");
    println!("Listening on 0.0.0.0:8000");
    axum::serve(listener, app).await
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

fn initial_state(config: Config) -> ForcefieldState {
    ForcefieldState::new(InnerForcefieldState {
        public_root: config.public_root,
        root_domain: config.root_domain,
        login_cookie_expiration: config.login_cookie_expiration,
        cookie_encryption_key: Key::from(
            &base64::prelude::BASE64_STANDARD
                .decode(&config.secret_key)
                .expect("Failed to deserialize encryption key"),
        ),
        users: config
            .users
            .into_iter()
            .map(|user| (user.username.clone(), user))
            .collect(),
    })
}
