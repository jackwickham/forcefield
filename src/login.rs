use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{PasswordHashString, SaltString, rand_core::OsRng},
};
use askama::Template;
use axum::{
    Form,
    extract::{Query, State},
    response::{Html, Redirect},
};
use serde::Deserialize;
use url::Url;

use crate::{
    authenticated_user::{AuthenticatedUser, AuthenticatedUserManager},
    state::ForcefieldState,
};

const DUMMY_HASH: &'static str = "$argon2id$v=19$m=19456,t=2,p=1$fKZfiZ9ioXzAPxb6I/IMLQ$EY+FN6zRB5YlFtHumtVWe/eGZUl1pmofDThztZHtL+U";

#[derive(Debug, Clone, Copy, Deserialize)]
pub enum LoginError {
    InvalidCredentials,
}

impl LoginError {
    pub fn message(&self) -> &'static str {
        match self {
            LoginError::InvalidCredentials => "Username or password was incorrect",
        }
    }
}

pub async fn show_login(
    Query(query): Query<LoginQueryParams>,
    authenticated_user: Option<AuthenticatedUser>,
    State(state): State<ForcefieldState>,
) -> Result<Html<String>, Redirect> {
    match authenticated_user {
        Some(_) => Err(Redirect::to(get_redirect_uri(query.next, &state).as_str())),
        None => {
            let mut submit_url = state
                .public_root
                .join("/login")
                .expect("Failed to construct login URI");
            if let Some(uri) = query.next {
                submit_url.query_pairs_mut().append_pair("next", &uri);
            }
            Ok(Html(
                LoginTemplate {
                    submit_url,
                    error: query.error,
                }
                .render()
                .expect("Failed to render login template"),
            ))
        }
    }
}

pub async fn login(
    mut authenticated_user_manager: AuthenticatedUserManager,
    Query(query): Query<LoginQueryParams>,
    State(state): State<ForcefieldState>,
    Form(request): Form<LoginRequest>,
) -> Redirect {
    let matching_user = state.users.get(&request.username);

    if verify_password(
        &request.password,
        matching_user.map(|user| &user.password_hash),
    ) && let Some(user) = matching_user
    {
        authenticated_user_manager
            .set_authenticated_user(&user.username)
            .await;
        Redirect::to(get_redirect_uri(query.next, &state).as_str())
    } else {
        let mut redirect_uri = state
            .public_root
            .join("/login")
            .expect("Failed to construct login URI");
        if let Some(uri) = query.next {
            redirect_uri.query_pairs_mut().append_pair("next", &uri);
        }
        redirect_uri
            .query_pairs_mut()
            .append_pair("error", "InvalidCredentials");
        Redirect::to(redirect_uri.as_str())
    }
}

pub async fn logout(
    mut authenticated_user_manager: AuthenticatedUserManager,
    Query(query): Query<LoginQueryParams>,
    State(state): State<ForcefieldState>,
) -> Redirect {
    authenticated_user_manager.clear_authenticated_user().await;
    Redirect::to(get_redirect_uri(query.next, &state).as_str())
}

pub async fn hash_password(password: String) -> String {
    let a2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);
    a2.hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string()
}

fn verify_password(password: &str, password_hash: Option<&PasswordHashString>) -> bool {
    Argon2::default()
        .verify_password(
            password.as_bytes(),
            &password_hash.map_or_else(
                || PasswordHash::new(DUMMY_HASH).expect("Failed to parse dummy hash"),
                |hash_str| hash_str.password_hash(),
            ),
        )
        .ok()
        // Only ok if there was a password hash provided
        .and(password_hash)
        .is_some()
}

/// Only allow redirecting to the root domain and its subdomains. Defaults to the forcefield public root otherwise.
fn get_redirect_uri(uri_param: Option<String>, state: &ForcefieldState) -> Url {
    uri_param
        .and_then(|uri| Url::parse(&uri).ok())
        .filter(|url| url.scheme().eq("http") || url.scheme().eq("https"))
        .filter(|url| {
            url.host()
                .and_then(|host| match host {
                    url::Host::Domain(val) => Some(val),
                    _ => None,
                })
                .is_some_and(|host| {
                    host.eq(&state.root_domain)
                        || host.ends_with(&format!(".{}", state.root_domain))
                })
        })
        .unwrap_or_else(|| state.public_root.clone())
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    submit_url: Url,
    error: Option<LoginError>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct LoginQueryParams {
    next: Option<String>,
    error: Option<LoginError>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoginRequest {
    username: String,
    password: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use argon2::{
        Argon2,
        password_hash::{PasswordHashString, SaltString, rand_core::OsRng},
    };
    use axum::{extract::State, http::header::LOCATION, response::IntoResponse};
    use cookie::Key;

    use crate::{
        authenticated_user::AuthenticatedUserManager,
        cookies::PrivateCookieJar,
        state::{ForcefieldState, InnerForcefieldState, User},
    };

    fn test_state() -> ForcefieldState {
        ForcefieldState::default()
    }

    fn test_state_with_domain(public_root: &str, root_domain: &str) -> ForcefieldState {
        ForcefieldState::new(InnerForcefieldState {
            public_root: Url::parse(public_root).expect("Failed to parse public root"),
            root_domain: root_domain.to_owned(),
            login_cookie_expiration: time::Duration::hours(24),
            cookie_encryption_key: Key::generate(),
            users: HashMap::new(),
        })
    }

    fn test_state_with_user(username: &str, password: &str) -> ForcefieldState {
        let password_hash = Argon2::default()
            .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
            .expect("Failed to hash password")
            .to_string();
        let password_hash = PasswordHashString::new(&password_hash).expect("Invalid hash");

        let mut users = HashMap::new();
        users.insert(
            username.to_owned(),
            User {
                username: username.to_owned(),
                password_hash,
            },
        );

        ForcefieldState::new(InnerForcefieldState {
            public_root: Url::parse("https://example.com").expect("Failed to parse public root"),
            root_domain: "example.com".to_owned(),
            login_cookie_expiration: time::Duration::days(90),
            cookie_encryption_key: Key::generate(),
            users,
        })
    }

    #[tokio::test]
    async fn test_hash_password_produces_valid_hash() {
        let password = "test_password_123";
        let hash = hash_password(password.to_owned()).await;
        let hash_string = PasswordHashString::new(&hash).expect("Invalid hash");

        assert!(verify_password(password, Some(&hash_string)));
    }

    #[tokio::test]
    async fn test_verify_password_with_correct_password() {
        let password = "test_password_123";
        let hash = hash_password(password.to_owned()).await;
        let hash_string = PasswordHashString::new(&hash).expect("Invalid hash");

        assert!(verify_password(password, Some(&hash_string)));
    }

    #[tokio::test]
    async fn test_verify_password_with_incorrect_password() {
        let password = "test_password_123";
        let hash = hash_password(password.to_owned()).await;
        let hash_string = PasswordHashString::new(&hash).expect("Invalid hash");

        assert!(!verify_password("wrong_password", Some(&hash_string)));
    }

    #[test]
    fn test_verify_password_with_none_hash_returns_false() {
        assert!(!verify_password("password", None));
    }

    #[test]
    fn test_get_redirect_uri_with_none() {
        let state = test_state_with_domain("https://example.com", "example.com");
        let uri = get_redirect_uri(None, &state);
        assert_eq!(uri.as_str(), "https://example.com/");
    }

    #[test]
    fn test_get_redirect_uri_with_valid_same_domain() {
        let state = test_state_with_domain("https://example.com", "example.com");
        let uri = get_redirect_uri(Some("https://example.com/dashboard".to_owned()), &state);
        assert_eq!(uri.as_str(), "https://example.com/dashboard");
    }

    #[test]
    fn test_get_redirect_uri_with_subdomain() {
        let state = test_state_with_domain("https://example.com", "example.com");
        let uri = get_redirect_uri(Some("https://app.example.com/dashboard".to_owned()), &state);
        assert_eq!(uri.as_str(), "https://app.example.com/dashboard");
    }

    #[test]
    fn test_get_redirect_uri_with_different_domain_rejects() {
        let state = test_state_with_domain("https://example.com", "example.com");
        let uri = get_redirect_uri(Some("https://evil.com/phishing".to_owned()), &state);
        assert_eq!(uri.as_str(), "https://example.com/");
    }

    #[test]
    fn test_get_redirect_uri_with_invalid_uri() {
        let state = test_state_with_domain("https://example.com", "example.com");
        let uri = get_redirect_uri(Some("not a valid uri!!!".to_owned()), &state);
        assert_eq!(uri.as_str(), "https://example.com/");
    }

    #[test]
    fn test_get_redirect_uri_with_path_only_rejects() {
        let state = test_state_with_domain("https://example.com", "example.com");
        let uri = get_redirect_uri(Some("/dashboard".to_owned()), &state);
        assert_eq!(uri.as_str(), "https://example.com/");
    }

    #[test]
    fn test_get_redirect_uri_without_scheme_rejects() {
        let state = test_state_with_domain("https://example.com", "example.com");
        let uri = get_redirect_uri(Some("//example.com/dashboard".to_owned()), &state);
        assert_eq!(uri.as_str(), "https://example.com/");
    }

    #[test]
    fn test_get_redirect_uri_with_query_params() {
        let state = test_state_with_domain("https://example.com", "example.com");
        let uri = get_redirect_uri(
            Some("https://example.com/page?foo=bar&baz=qux".to_owned()),
            &state,
        );
        assert_eq!(uri.as_str(), "https://example.com/page?foo=bar&baz=qux");
    }

    #[test]
    fn test_get_redirect_uri_rejects_non_http_schemes() {
        let state = test_state_with_domain("https://example.com", "example.com");

        let uri = get_redirect_uri(Some("javascript:alert(1)".to_owned()), &state);
        assert_eq!(uri.as_str(), "https://example.com/");

        let uri = get_redirect_uri(
            Some("data:text/html,<script>alert(1)</script>".to_owned()),
            &state,
        );
        assert_eq!(uri.as_str(), "https://example.com/");
    }

    #[tokio::test]
    async fn test_show_login_renders_when_not_authenticated() {
        let state = test_state_with_domain("https://example.com", "example.com");
        let result = show_login(Query(LoginQueryParams::default()), None, State(state)).await;

        let html = result.expect("Should return Ok with HTML");
        assert!(
            html.0.contains("type=\"password\""),
            "Should render login template"
        );
    }

    #[tokio::test]
    async fn test_show_login_redirects_when_authenticated() {
        let state = test_state_with_domain("https://example.com", "example.com");
        let user = AuthenticatedUser {
            username: "testuser".to_owned(),
        };
        let result = show_login(Query(LoginQueryParams::default()), Some(user), State(state)).await;

        let redirect = result.expect_err("Should return Err with Redirect");
        let response = redirect.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::SEE_OTHER);
        assert_eq!(
            response
                .headers()
                .get(LOCATION)
                .expect("Location header not present")
                .to_str()
                .expect("Failed to convert location header to string"),
            "https://example.com/"
        );
    }

    #[tokio::test]
    async fn test_show_login_redirects_to_next_when_authenticated() {
        let state = test_state_with_domain("https://example.com", "example.com");
        let user = AuthenticatedUser {
            username: "testuser".to_owned(),
        };
        let result = show_login(
            Query(LoginQueryParams {
                next: Some("https://dashboard.example.com/dashboard".to_owned()),
                error: None,
            }),
            Some(user),
            State(state),
        )
        .await;

        let redirect = result.expect_err("Should return Err with Redirect");
        let response = redirect.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::SEE_OTHER);
        assert_eq!(
            response
                .headers()
                .get(LOCATION)
                .expect("Location header not present")
                .to_str()
                .expect("Failed to convert location header to string"),
            "https://dashboard.example.com/dashboard"
        );
    }

    #[tokio::test]
    async fn test_login_with_valid_credentials() {
        let state = test_state_with_user("testuser", "testpassword");
        let cookies =
            PrivateCookieJar::create_with_cookies(state.cookie_encryption_key.clone(), vec![]);
        let manager = AuthenticatedUserManager::new_for_test(cookies.clone(), state.clone());

        let redirect = login(
            manager,
            Query(LoginQueryParams::default()),
            State(state),
            Form(LoginRequest {
                username: "testuser".to_owned(),
                password: "testpassword".to_owned(),
            }),
        )
        .await;

        let response = redirect.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get("location").map(|h| h.to_str().ok()),
            Some(Some("https://example.com/"))
        );

        let delta = cookies.get_delta().await;
        assert_eq!(delta.len(), 1, "Should set authentication cookie");
    }

    #[tokio::test]
    async fn test_login_with_invalid_password() {
        let state = test_state_with_user("testuser", "testpassword");
        let cookies =
            PrivateCookieJar::create_with_cookies(state.cookie_encryption_key.clone(), vec![]);
        let manager = AuthenticatedUserManager::new_for_test(cookies.clone(), state.clone());

        let redirect = login(
            manager,
            Query(LoginQueryParams::default()),
            State(state),
            Form(LoginRequest {
                username: "testuser".to_owned(),
                password: "wrongpassword".to_owned(),
            }),
        )
        .await;

        let response = redirect.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get("location")
            .and_then(|h| h.to_str().ok())
            .expect("Should have location header");
        assert!(location.contains("/login"), "Should redirect to login page");
        assert!(
            location.contains("error=InvalidCredentials"),
            "Should include error param"
        );

        let delta = cookies.get_delta().await;
        assert!(delta.is_empty(), "Should not set authentication cookie");
    }

    #[tokio::test]
    async fn test_login_with_nonexistent_user() {
        let state = test_state_with_user("testuser", "testpassword");
        let cookies =
            PrivateCookieJar::create_with_cookies(state.cookie_encryption_key.clone(), vec![]);
        let manager = AuthenticatedUserManager::new_for_test(cookies.clone(), state.clone());

        let redirect = login(
            manager,
            Query(LoginQueryParams::default()),
            State(state),
            Form(LoginRequest {
                username: "nonexistent".to_owned(),
                password: "anypassword".to_owned(),
            }),
        )
        .await;

        let response = redirect.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get("location")
            .and_then(|h| h.to_str().ok())
            .expect("Should have location header");
        assert!(location.contains("/login"));
        assert!(location.contains("error=InvalidCredentials"));

        let delta = cookies.get_delta().await;
        assert!(delta.is_empty(), "Should not set authentication cookie");
    }

    #[tokio::test]
    async fn test_login_redirects_to_next_parameter() {
        let state = test_state_with_user("testuser", "testpassword");
        let cookies =
            PrivateCookieJar::create_with_cookies(state.cookie_encryption_key.clone(), vec![]);
        let manager = AuthenticatedUserManager::new_for_test(cookies.clone(), state.clone());

        let redirect = login(
            manager,
            Query(LoginQueryParams {
                next: Some("https://example.com/dashboard".to_owned()),
                error: None,
            }),
            State(state),
            Form(LoginRequest {
                username: "testuser".to_owned(),
                password: "testpassword".to_owned(),
            }),
        )
        .await;

        let response = redirect.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get("location").map(|h| h.to_str().ok()),
            Some(Some("https://example.com/dashboard"))
        );
    }

    #[tokio::test]
    async fn test_login_rejects_malicious_next_parameter() {
        let state = test_state_with_user("testuser", "testpassword");
        let cookies =
            PrivateCookieJar::create_with_cookies(state.cookie_encryption_key.clone(), vec![]);
        let manager = AuthenticatedUserManager::new_for_test(cookies.clone(), state.clone());

        let redirect = login(
            manager,
            Query(LoginQueryParams {
                next: Some("https://evil.com/phishing".to_owned()),
                error: None,
            }),
            State(state),
            Form(LoginRequest {
                username: "testuser".to_owned(),
                password: "testpassword".to_owned(),
            }),
        )
        .await;

        let response = redirect.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get("location").map(|h| h.to_str().ok()),
            Some(Some("https://example.com/"))
        );
    }

    #[tokio::test]
    async fn test_login_failure_preserves_next_parameter() {
        let state = test_state_with_user("testuser", "testpassword");
        let cookies =
            PrivateCookieJar::create_with_cookies(state.cookie_encryption_key.clone(), vec![]);
        let manager = AuthenticatedUserManager::new_for_test(cookies.clone(), state.clone());

        let redirect = login(
            manager,
            Query(LoginQueryParams {
                next: Some("https://example.com/dashboard".to_owned()),
                error: None,
            }),
            State(state),
            Form(LoginRequest {
                username: "testuser".to_owned(),
                password: "wrongpassword".to_owned(),
            }),
        )
        .await;

        let response = redirect.into_response();
        let location = response
            .headers()
            .get("location")
            .and_then(|h| h.to_str().ok())
            .expect("Should have location header");
        assert!(location.contains("/login"));
        assert!(location.contains("error=InvalidCredentials"));
        assert!(location.contains("next="));
    }

    #[tokio::test]
    async fn test_logout_clears_authentication() {
        let state = test_state();
        // Start with an existing auth cookie
        let cookies = PrivateCookieJar::create_with_cookies(
            state.cookie_encryption_key.clone(),
            vec![(
                "forcefield_user".to_owned(),
                r#"{"username":"testuser","issued":"2024-06-20T15:30:45Z"}"#.to_owned(),
            )],
        );
        let manager = AuthenticatedUserManager::new_for_test(cookies.clone(), state.clone());

        let redirect = logout(manager, Query(LoginQueryParams::default()), State(state)).await;

        let response = redirect.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::SEE_OTHER);

        // Verify cookie removal was attempted
        let delta = cookies.get_delta().await;
        assert_eq!(delta.len(), 1, "Should clear authentication cookie");
        assert_eq!(delta[0].value(), "", "Cookie value should be empty");
    }

    #[tokio::test]
    async fn test_logout_respects_next_parameter() {
        let state = test_state_with_domain("https://example.com", "example.com");
        let cookies =
            PrivateCookieJar::create_with_cookies(state.cookie_encryption_key.clone(), vec![]);
        let manager = AuthenticatedUserManager::new_for_test(cookies.clone(), state.clone());

        let redirect = logout(
            manager,
            Query(LoginQueryParams {
                next: Some("https://example.com/goodbye".to_owned()),
                error: None,
            }),
            State(state),
        )
        .await;

        let response = redirect.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get("location").map(|h| h.to_str().ok()),
            Some(Some("https://example.com/goodbye"))
        );
    }
}
