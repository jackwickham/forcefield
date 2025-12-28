use axum::{Router, middleware, routing::get};
use axum_extra::extract::cookie::Key;
use base64::Engine;
use rocket::http::uri::Absolute;
use time::Duration;

use crate::{
    config::Config,
    cookies::auto_cookie_middleware,
    index::index_handler,
    state::{ForcefieldState, InnerForcefieldState},
};

mod authenticated_user;
mod config;
mod cookies;
mod index;
mod state;

pub async fn start_server_with_default_config() -> Result<(), std::io::Error> {
    start_server(Config {
        public_root: Absolute::parse("http://localhost:8000").unwrap(),
        root_domain: "localhost".to_owned(),
        secret_key: "00000000000000000000000000000000000000000000".to_owned(),
        login_cookie_expiration: Duration::hours(1),
        enable_hash_password: true,
        users: vec![],
    })
    .await
}

pub async fn start_server(config: Config<'_>) -> Result<(), std::io::Error> {
    let app = Router::<ForcefieldState>::new()
        .route("/", get(index_handler))
        .layer(middleware::from_fn(auto_cookie_middleware))
        .with_state(initial_state(config));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000")
        .await
        .expect("Failed to start listening on 0.0.0.0:8000");
    println!("Listening on 0.0.0.0:8000");
    axum::serve(listener, app).await
}

fn initial_state(config: Config<'_>) -> ForcefieldState {
    ForcefieldState::new(InnerForcefieldState {
        public_root: (),
        root_domain: config.root_domain,
        login_cookie_expiration: config.login_cookie_expiration,
        cookie_encryption_key: Key::derive_from(
            &base64::prelude::BASE64_STANDARD
                .decode(&config.secret_key)
                .expect("Failed to deserialize encryption key"),
        ),
        users: vec![],
    })
}
