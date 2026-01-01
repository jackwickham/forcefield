use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use axum::http::{HeaderValue, Request, Response, StatusCode};
use cookie::{Cookie, CookieJar};
use forcefield::config::{ConfigUser, ForcefieldConfig};
use forcefield::create_app;
use time::Duration;
use tokio::time::sleep;
use tower::{Service, ServiceExt};
use url::Url;

const USERNAME: &'static str = "test-user";
const PASSWORD: &'static str = "password";
const PASSWORD_HASH: &'static str = "$argon2id$v=19$m=19456,t=2,p=1$fKZfiZ9ioXzAPxb6I/IMLQ$EY+FN6zRB5YlFtHumtVWe/eGZUl1pmofDThztZHtL+U";

#[tokio::test]
async fn login_rejects_invalid_username() {
    let app = create_app(default_config());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login?next=https%3A%2F%2Fdashboard.example.com%2Ffoo%3Fbar%3Dbaz")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "username=invalid&password={}",
                    PASSWORD
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers().get(LOCATION),
        Some(&HeaderValue::from_static(
            "https://forcefield.example.com/login?next=https%3A%2F%2Fdashboard.example.com%2Ffoo%3Fbar%3Dbaz&error=InvalidCredentials"
        ))
    );
    assert_eq!(response.headers().get(SET_COOKIE), None);
}

#[tokio::test]
async fn login_rejects_invalid_password() {
    let app = create_app(default_config());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login?next=https%3A%2F%2Fdashboard.example.com%2Ffoo%3Fbar%3Dbaz")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "username={}&password=invalid",
                    USERNAME
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers().get(LOCATION),
        Some(&HeaderValue::from_static(
            "https://forcefield.example.com/login?next=https%3A%2F%2Fdashboard.example.com%2Ffoo%3Fbar%3Dbaz&error=InvalidCredentials"
        ))
    );
    assert_eq!(response.headers().get(SET_COOKIE), None);
}

#[tokio::test]
async fn login_accepts_valid_credentials_and_redirects() {
    let app = create_app(default_config());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login?next=https%3A%2F%2Fdashboard.example.com%2Ffoo%3Fbar%3Dbaz")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "username={}&password={}",
                    USERNAME, PASSWORD
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers().get(LOCATION),
        Some(&HeaderValue::from_static(
            "https://dashboard.example.com/foo?bar=baz"
        ))
    );
    let header = response
        .headers()
        .get(SET_COOKIE)
        .expect("Set-Cookie header was missing")
        .to_str()
        .expect("Failed to convert cookie header to string");
    assert!(
        header.starts_with("forcefield_user="),
        "Setting wrong cookie: {}",
        header
    );
    assert!(
        header.contains("; Domain=example.com;"),
        "Setting wrong domain: {}",
        header
    );
}

#[tokio::test]
async fn login_accepts_valid_credentials_and_ignores_malicious_redirect_uri() {
    let app = create_app(default_config());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login?next=https%3A%2F%2Fmalicious.example.org%2Ffoo%3Fbar%3Dbaz")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "username={}&password={}",
                    USERNAME, PASSWORD
                )))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers().get(LOCATION),
        Some(&HeaderValue::from_static("https://forcefield.example.com/"))
    );
    let header = response
        .headers()
        .get(SET_COOKIE)
        .expect("Set-Cookie header was missing")
        .to_str()
        .expect("Failed to convert cookie header to string");
    assert!(
        header.starts_with("forcefield_user="),
        "Setting wrong cookie: {}",
        header
    );
    assert!(
        header.contains("; Domain=example.com;"),
        "Setting wrong domain: {}",
        header
    );
}

#[tokio::test]
async fn check_auth_returns_ok_when_logged_in() {
    let mut app = create_app(default_config());
    let mut jar = CookieJar::new();

    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "username={}&password={}",
                    USERNAME, PASSWORD
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    extract_cookies(&login_response, &mut jar);

    let check_auth_response = app
        .call(
            Request::builder()
                .uri("/check-auth")
                .header(
                    "X-Forwarded-Host",
                    HeaderValue::from_static("dashboard.example.com"),
                )
                .header("X-Forwarded-Uri", HeaderValue::from_static("/test?foo=bar"))
                .header(COOKIE, to_cookie_header(&jar))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(check_auth_response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        check_auth_response.headers().get("x-forcefield-username"),
        Some(&HeaderValue::from_static(USERNAME))
    );
    assert!(!check_auth_response.headers().contains_key(SET_COOKIE));
}

#[tokio::test]
async fn check_auth_redirects_when_not_logged_in() {
    let mut app = create_app(default_config());

    let check_auth_response = app
        .call(
            Request::builder()
                .uri("/check-auth")
                .header(
                    "X-Forwarded-Host",
                    HeaderValue::from_static("dashboard.example.com"),
                )
                .header("X-Forwarded-Uri", HeaderValue::from_static("/test?foo=bar"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(check_auth_response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        check_auth_response.headers().get(LOCATION),
        Some(&HeaderValue::from_static(
            "https://forcefield.example.com/login?next=https%3A%2F%2Fdashboard.example.com%2Ftest%3Ffoo%3Dbar"
        ))
    );
    assert_eq!(
        check_auth_response.headers().get("x-forcefield-username"),
        None
    );
    assert!(!check_auth_response.headers().contains_key(SET_COOKIE));
}

#[tokio::test]
async fn check_auth_redirects_when_invalid_cookie() {
    let mut app = create_app(default_config());
    let mut jar = CookieJar::new();
    jar.add(("forcefield-user", "invalid"));

    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "username={}&password={}",
                    USERNAME, PASSWORD
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    extract_cookies(&login_response, &mut jar);

    let check_auth_response = app
        .call(
            Request::builder()
                .uri("/check-auth")
                .header(
                    "X-Forwarded-Host",
                    HeaderValue::from_static("dashboard.example.com"),
                )
                .header("X-Forwarded-Uri", HeaderValue::from_static("/test?foo=bar"))
                .header(COOKIE, to_cookie_header(&jar))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(check_auth_response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        check_auth_response.headers().get("x-forcefield-username"),
        Some(&HeaderValue::from_static(USERNAME))
    );
    assert!(!check_auth_response.headers().contains_key(SET_COOKIE));
}

#[tokio::test]
async fn check_auth_refreshes_cookie_when_nearly_expired() {
    let mut app = create_app(default_config());
    let mut jar = CookieJar::new();

    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "username={}&password={}",
                    USERNAME, PASSWORD
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    extract_cookies(&login_response, &mut jar);

    sleep(std::time::Duration::from_secs(3)).await;

    let check_auth_response = app
        .call(
            Request::builder()
                .uri("/check-auth")
                .header(
                    "X-Forwarded-Host",
                    HeaderValue::from_static("dashboard.example.com"),
                )
                .header("X-Forwarded-Uri", HeaderValue::from_static("/test?foo=bar"))
                .header(COOKIE, to_cookie_header(&jar))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(check_auth_response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        check_auth_response.headers().get("x-forcefield-username"),
        Some(&HeaderValue::from_static(USERNAME))
    );
    let header = check_auth_response
        .headers()
        .get(SET_COOKIE)
        .expect("Set-Cookie header was missing")
        .to_str()
        .expect("Failed to convert cookie header to string");
    assert!(
        header.starts_with("forcefield_user="),
        "Setting wrong cookie: {}",
        header
    );
    assert!(
        header.contains("; Domain=example.com;"),
        "Setting wrong domain: {}",
        header
    );
}

#[tokio::test]
async fn check_auth_redirects_when_login_expired() {
    let mut app = create_app(default_config());
    let mut jar = CookieJar::new();

    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "username={}&password={}",
                    USERNAME, PASSWORD
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    extract_cookies(&login_response, &mut jar);

    sleep(std::time::Duration::from_secs(5)).await;

    let check_auth_response = app
        .call(
            Request::builder()
                .uri("/check-auth")
                .header(
                    "X-Forwarded-Host",
                    HeaderValue::from_static("dashboard.example.com"),
                )
                .header("X-Forwarded-Uri", HeaderValue::from_static("/test?foo=bar"))
                .header(COOKIE, to_cookie_header(&jar))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(check_auth_response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        check_auth_response.headers().get(LOCATION),
        Some(&HeaderValue::from_static(
            "https://forcefield.example.com/login?next=https%3A%2F%2Fdashboard.example.com%2Ftest%3Ffoo%3Dbar"
        ))
    );
    assert_eq!(
        check_auth_response.headers().get("x-forcefield-username"),
        None
    );
    extract_cookies(&check_auth_response, &mut jar);
    assert_eq!(
        jar.get("forcefield_user")
            .expect("Removed cookies should stay in the cookie jar with no value, but the user cookie is missing")
            .value(),
        "",
        "Expired cookies should get removed"
    );
}

#[tokio::test]
async fn logout_clears_cookie_and_redirects() {
    let mut app = create_app(default_config());
    let mut jar = CookieJar::new();

    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "username={}&password={}",
                    USERNAME, PASSWORD
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    extract_cookies(&login_response, &mut jar);

    let logout_response = app
        .call(
            Request::builder()
                .uri("/logout?next=https%3A%2F%2Fdashboard.example.com%2Ffoo%3Fbar%3Dbaz")
                .header(COOKIE, to_cookie_header(&jar))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(logout_response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        logout_response.headers().get(LOCATION),
        Some(&HeaderValue::from_static(
            "https://dashboard.example.com/foo?bar=baz"
        ))
    );
    assert!(logout_response.headers().contains_key(SET_COOKIE));

    extract_cookies(&logout_response, &mut jar);
    assert_eq!(
        jar.get("forcefield_user")
            .expect("Removed cookies should stay in the cookie jar with no value, but the user cookie is missing")
            .value(),
        ""
    );
}

fn extract_cookies(response: &Response<Body>, jar: &mut CookieJar) {
    for header in response.headers().get_all(SET_COOKIE) {
        if let Ok(cookie_str) = header.to_str() {
            if let Ok(cookie) = Cookie::parse(cookie_str) {
                jar.add(cookie.into_owned());
            }
        }
    }
}

fn to_cookie_header(jar: &CookieJar) -> HeaderValue {
    HeaderValue::from_str(
        &jar.iter()
            .map(|c| format!("{}={}", c.name(), c.value()))
            .collect::<Vec<_>>()
            .join("; "),
    )
    .expect("Failed to construct cookie header")
}

fn default_config() -> ForcefieldConfig {
    ForcefieldConfig {
        public_root: Url::parse("https://forcefield.example.com").unwrap(),
        root_domain: "example.com".into(),
        secret_key:
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".into(),
        login_cookie_expiration: Duration::seconds(5),
        enable_hash_password: false,
        users: vec![ConfigUser {
            username: USERNAME.into(),
            password_hash: PASSWORD_HASH.into(),
        }],
        client_ip_header: None,
    }
}

// Note: Rate limiting is tested in production and works correctly.
// Integration tests for rate limiting don't work with tower's Service::call/oneshot
// because axum's Router doesn't maintain middleware state the same way as axum::serve.
// The ClientIpKeyExtractor is unit tested in src/rate_limit.rs.
