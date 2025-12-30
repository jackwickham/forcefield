use axum::{Router, middleware, routing::get};
use axum_extra::extract::cookie::Key;
use base64::Engine;
use time::Duration;
use url::Url;

use crate::{
    check_auth::check_auth,
    config::Config,
    cookies::auto_cookie_middleware,
    index::index_handler,
    state::{ForcefieldState, InnerForcefieldState},
};

mod authenticated_user;
mod check_auth;
mod config;
mod cookies;
mod index;
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
    let app = Router::<ForcefieldState>::new()
        .route("/", get(index_handler))
        .route("/check-auth", get(check_auth))
        .layer(middleware::from_fn(auto_cookie_middleware))
        .with_state(initial_state(config));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000")
        .await
        .expect("Failed to start listening on 0.0.0.0:8000");
    println!("Listening on 0.0.0.0:8000");
    axum::serve(listener, app).await
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
        users: vec![],
    })
}
