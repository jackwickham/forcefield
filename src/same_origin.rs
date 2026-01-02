use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header::ORIGIN},
    middleware::Next,
    response::{IntoResponse, Response},
};
use url::Url;

use crate::state::ForcefieldState;

pub async fn same_origin(
    State(state): State<ForcefieldState>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Response {
    if !headers
        .get(ORIGIN)
        .and_then(|origin| Url::parse(origin.to_str().ok()?).ok())
        .is_some_and(|origin| origin.origin() == state.public_root.origin())
    {
        return (StatusCode::BAD_REQUEST, "Cross-origin request blocked").into_response();
    }

    next.run(req).await
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use axum::http::Request;
    use axum::routing::get;
    use axum::{Router, body};
    use axum::{body::Body, middleware};
    use cookie::Key;
    use time::Duration;
    use tower::ServiceExt;

    use crate::state::InnerForcefieldState;

    use super::*;

    fn app() -> Router {
        let state = ForcefieldState::new(InnerForcefieldState {
            public_root: Url::parse("https://forcefield.example.com/").unwrap(),
            root_domain: "example.com".into(),
            login_cookie_expiration: Duration::days(7),
            cookie_encryption_key: Key::generate(),
            users: HashMap::new(),
        });
        Router::new()
            .route("/", get(|| async { "Hello!" }))
            .layer(middleware::from_fn_with_state(state, same_origin))
    }

    #[tokio::test]
    async fn forwards_valid_request() {
        let app = app();

        let response = app
            .oneshot(
                Request::builder()
                    .header(ORIGIN, "https://forcefield.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            str::from_utf8(&body::to_bytes(response.into_body(), 1000).await.unwrap())
                .expect("Invalid response body"),
            "Hello!"
        );
    }

    #[tokio::test]
    async fn rejects_mismatched_origin() {
        let app = app();

        let response = app
            .oneshot(
                Request::builder()
                    .header(ORIGIN, "https://dashboard.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            str::from_utf8(&body::to_bytes(response.into_body(), 1000).await.unwrap())
                .expect("Invalid response body"),
            "Cross-origin request blocked"
        );
    }

    #[tokio::test]
    async fn rejects_missing_origin() {
        let app = app();

        let response = app
            .oneshot(Request::builder().body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            str::from_utf8(&body::to_bytes(response.into_body(), 1000).await.unwrap())
                .expect("Invalid response body"),
            "Cross-origin request blocked"
        );
    }

    #[tokio::test]
    async fn rejects_malformed_origin() {
        let app = app();

        let response = app
            .oneshot(
                Request::builder()
                    .header(ORIGIN, "NOT VALID ORIGIN")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            str::from_utf8(&body::to_bytes(response.into_body(), 1000).await.unwrap())
                .expect("Invalid response body"),
            "Cross-origin request blocked"
        );
    }
}
