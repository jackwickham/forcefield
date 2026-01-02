use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderName, StatusCode},
    response::{IntoResponse, Redirect},
};

use crate::{authenticated_user::AuthenticatedUser, state::ForcefieldState};

const AUTHENTICATED_USERNAME_HEADER: HeaderName = HeaderName::from_static("x-forcefield-username");
const FORWARDED_HOST_HEADER: HeaderName = HeaderName::from_static("x-forwarded-host");
const FORWARDED_URI_HEADER: HeaderName = HeaderName::from_static("x-forwarded-uri");

pub async fn check_auth(
    maybe_user: Option<AuthenticatedUser>,
    headers: HeaderMap,
    State(state): State<ForcefieldState>,
) -> Result<impl IntoResponse, Redirect> {
    maybe_user
        .map(|user| {
            (
                StatusCode::NO_CONTENT,
                [(AUTHENTICATED_USERNAME_HEADER, user.username)],
                Body::empty(),
            )
        })
        .ok_or_else(|| {
            let mut redirect = state
                .public_root
                .join("/login")
                .expect("Failed to generate login URI");
            if let (Some(return_host), Some(return_uri)) = (
                headers
                    .get(FORWARDED_HOST_HEADER)
                    .and_then(|uri| uri.to_str().ok()),
                headers
                    .get(FORWARDED_URI_HEADER)
                    .and_then(|uri| uri.to_str().ok()),
            ) {
                redirect
                    .query_pairs_mut()
                    .append_pair("next", &format!("https://{return_host}{return_uri}"));
            }
            Redirect::to(redirect.as_str())
        })
}

#[cfg(test)]
mod test {
    use axum::http::{HeaderValue, header::LOCATION};

    use super::*;

    #[tokio::test]
    async fn returns_authenticated_user_when_authenticated() {
        let response = check_auth(
            Some(AuthenticatedUser {
                username: "test-user".into(),
            }),
            HeaderMap::new(),
            State(ForcefieldState::default()),
        )
        .await
        .expect("Did not receive a successful response")
        .into_response();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            response.headers().get(AUTHENTICATED_USERNAME_HEADER),
            Some(&HeaderValue::from_static("test-user"))
        );
    }

    #[tokio::test]
    async fn redirects_when_not_authenticated() {
        let response = check_auth(None, HeaderMap::new(), State(ForcefieldState::default()))
            .await
            .map(IntoResponse::into_response) // impl IntoResponse doesn't implement Debug, but Response does, and expect_err requires Debug
            .expect_err("Unexpectedly received a successful response")
            .into_response();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers().get(AUTHENTICATED_USERNAME_HEADER), None);
        assert_eq!(
            response.headers().get(LOCATION),
            HeaderValue::from_str("http://localhost/login")
                .ok()
                .as_ref()
        );
    }

    #[tokio::test]
    async fn redirects_with_from_when_not_authenticated() {
        let mut request_headers = HeaderMap::new();
        request_headers.append(
            FORWARDED_HOST_HEADER,
            HeaderValue::from_static("example.org"),
        );
        request_headers.append(
            FORWARDED_URI_HEADER,
            HeaderValue::from_static("/foo?bar=baz"),
        );
        let response = check_auth(None, request_headers, State(ForcefieldState::default()))
            .await
            .map(IntoResponse::into_response)
            .expect_err("Unexpectedly received a successful response")
            .into_response();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers().get(AUTHENTICATED_USERNAME_HEADER), None);
        assert_eq!(
            response.headers().get(LOCATION),
            HeaderValue::from_str(
                "http://localhost/login?next=https%3A%2F%2Fexample.org%2Ffoo%3Fbar%3Dbaz"
            )
            .ok()
            .as_ref()
        );
    }
}
