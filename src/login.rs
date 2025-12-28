use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{PasswordHashString, SaltString, rand_core::OsRng},
};
use rocket::{
    State,
    form::Form,
    http::{ext::IntoOwned, uri::Reference},
    response::{Redirect, status::Forbidden},
};
use rocket_dyn_templates::{Template, context};

use crate::{
    authenticated_user::{AuthenticatedUser, AuthenticatedUserStore},
    config::{Config, ConfigUser},
};

const DUMMY_HASH: &'static str = "$argon2id$v=19$m=19456,t=2,p=1$fKZfiZ9ioXzAPxb6I/IMLQ$EY+FN6zRB5YlFtHumtVWe/eGZUl1pmofDThztZHtL+U";

#[derive(Debug, Clone, Copy, rocket::UriDisplayQuery, rocket::FromFormField)]
pub enum LoginError {
    #[field(value = "invalid_credentials")]
    InvalidCredentials,
}

impl LoginError {
    pub fn message(&self) -> &'static str {
        match self {
            LoginError::InvalidCredentials => "Username or password was incorrect",
        }
    }
}

#[rocket::get("/login?<next>", rank = 1)]
pub fn login_redirect_to_logged_in(
    next: Option<&str>,
    config: &State<Config>,
    _authenticated_user: AuthenticatedUser,
) -> Redirect {
    Redirect::to(get_redirect_uri(next, config))
}

#[rocket::get("/login?<next>&<error>", rank = 2)]
pub fn show_login(next: Option<&str>, error: Option<LoginError>) -> Template {
    Template::render(
        "login",
        context! {
            next: next,
            error: error.map(|e| e.message()),
        },
    )
}

#[rocket::post("/login?<next>", data = "<request>")]
pub fn login(
    next: Option<&str>,
    request: Form<LoginRequest>,
    config: &State<Config>,
    authenticated_user_store: AuthenticatedUserStore,
) -> Redirect {
    let mut matching_user: Option<&ConfigUser> = None;
    for user in &config.users {
        if user.username == request.username {
            matching_user = Some(user);
        }
    }

    if verify_password(
        request.password,
        matching_user.map(|user| &user.password_hash),
    ) && let Some(user) = matching_user
    {
        authenticated_user_store.set_authenticated_user(&user.username);
        Redirect::to(get_redirect_uri(next, config))
    } else {
        let uri = rocket::uri!(show_login(next, Some(LoginError::InvalidCredentials)));
        Redirect::to(uri)
    }
}

#[rocket::get("/logout?<next>")]
pub fn logout(
    next: Option<&str>,
    config: &State<Config>,
    authenticated_user_store: AuthenticatedUserStore,
) -> Redirect {
    authenticated_user_store.clear_authenticated_user();
    Redirect::to(get_redirect_uri(next, config))
}

#[rocket::post("/hash-password", data = "<password>")]
pub fn hash_password(
    password: &str,
    config: &State<Config>,
) -> Result<String, Forbidden<&'static str>> {
    if !config.enable_hash_password {
        return Err(Forbidden("Endpoint not enabled"));
    }

    let a2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);
    Ok(a2
        .hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string())
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

fn get_redirect_uri(uri_param: Option<&str>, config: &Config) -> Reference<'static> {
    uri_param
        .and_then(|uri| Reference::parse(uri).ok())
        .filter(|uri| {
            uri.scheme()
                .is_some_and(|scheme| scheme.eq("http") || scheme.eq("https"))
        })
        .filter(|uri| {
            uri.authority().is_some_and(|authority| {
                authority.host().eq(&config.root_domain)
                    || authority
                        .host()
                        .ends_with(&format!(".{}", config.root_domain))
            })
        })
        .unwrap_or_else(|| uri!("/").into())
        .into_owned()
}

#[derive(rocket::FromForm)]
pub struct LoginRequest<'a> {
    username: &'a str,
    password: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{Argon2, password_hash::{PasswordHashString, SaltString, rand_core::OsRng}};
    use rocket::State;
    use rocket::http::uri::Absolute;
    use rocket::http::{Status, ContentType};
    use rocket::local::blocking::Client;

    const USER_COOKIE: &str = "forcefield_user";

    fn test_config() -> Config<'static> {
        Config {
            public_root: Absolute::parse("https://example.com").unwrap(),
            root_domain: "example.com".to_string(),
            login_cookie_expiration: time::Duration::days(90),
            enable_hash_password: true,
            users: vec![],
        }
    }

    fn test_config_with_user() -> Config<'static> {
        // Generate hash for "testpassword"
        let password_hash = Argon2::default()
            .hash_password("testpassword".as_bytes(), &SaltString::generate(&mut OsRng))
            .expect("Failed to hash password")
            .to_string();
        let password_hash = PasswordHashString::new(&password_hash).expect("Invalid hash");

        Config {
            public_root: Absolute::parse("https://example.com").unwrap(),
            root_domain: "example.com".to_string(),
            login_cookie_expiration: time::Duration::days(90),
            enable_hash_password: true,
            users: vec![ConfigUser {
                username: "testuser".to_string(),
                password_hash,
            }],
        }
    }

    fn client_with_user() -> Client {
        let rocket = rocket::build()
            .manage(test_config_with_user())
            .attach(Template::fairing())
            .mount(
                "/",
                routes![
                    login_redirect_to_logged_in,
                    show_login,
                    login,
                    logout,
                    hash_password
                ],
            );
        Client::tracked(rocket).expect("Failed to create client")
    }

    #[test]
    fn test_hash_password_fails_when_disabled() {
        let mut config = test_config();
        config.enable_hash_password = false;
        let password = "test_password_123";
        let result = hash_password(password, &State::from(&config));

        assert!(result.is_err());
    }

    #[test]
    fn test_verify_password_with_correct_password() {
        let config = test_config();
        let password = "test_password_123";
        let hash =
            hash_password(password, &State::from(&config)).expect("Hash password should succeed");
        let hash_string = PasswordHashString::new(&hash).expect("Invalid hash");

        assert!(verify_password(password, Some(&hash_string)));
    }

    #[test]
    fn test_verify_password_with_incorrect_password() {
        let config = test_config();
        let password = "test_password_123";
        let hash =
            hash_password(password, &State::from(&config)).expect("Hash password should succeed");
        let hash_string = PasswordHashString::new(&hash).expect("Invalid hash");

        assert!(!verify_password("wrong_password", Some(&hash_string)));
    }

    #[test]
    fn test_verify_password_with_none_hash_returns_false() {
        assert!(!verify_password("password", None));
    }

    #[test]
    fn test_get_redirect_uri_with_none() {
        let config = test_config();
        let uri = get_redirect_uri(None, &config);
        assert_eq!(uri.to_string(), "/");
    }

    #[test]
    fn test_get_redirect_uri_with_valid_same_domain() {
        let config = test_config();
        let uri = get_redirect_uri(Some("https://example.com/dashboard"), &config);
        assert_eq!(uri.to_string(), "https://example.com/dashboard");
    }

    #[test]
    fn test_get_redirect_uri_with_subdomain() {
        let config = test_config();
        let uri = get_redirect_uri(Some("https://app.example.com/dashboard"), &config);
        assert_eq!(uri.to_string(), "https://app.example.com/dashboard");
    }

    #[test]
    fn test_get_redirect_uri_with_different_domain_rejects() {
        let config = test_config();
        // Should reject different domain and return default /
        let uri = get_redirect_uri(Some("https://evil.com/phishing"), &config);
        assert_eq!(uri.to_string(), "/");
    }

    #[test]
    fn test_get_redirect_uri_with_invalid_uri() {
        let config = test_config();
        // Invalid URI should fall back to /
        let uri = get_redirect_uri(Some("not a valid uri!!!"), &config);
        assert_eq!(uri.to_string(), "/");
    }

    #[test]
    fn test_get_redirect_uri_with_path_only_rejects() {
        let config = test_config();
        // Path-only URIs don't have scheme, should fall back to /
        let uri = get_redirect_uri(Some("/dashboard"), &config);
        assert_eq!(uri.to_string(), "/");
    }

    #[test]
    fn test_get_redirect_uri_without_scheme_rejects() {
        let config = test_config();
        // URIs without scheme should be rejected
        let uri = get_redirect_uri(Some("//example.com/dashboard"), &config);
        assert_eq!(uri.to_string(), "/");
    }

    #[test]
    fn test_get_redirect_uri_with_query_params() {
        let config = test_config();
        let uri = get_redirect_uri(Some("https://example.com/page?foo=bar&baz=qux"), &config);
        assert_eq!(uri.to_string(), "https://example.com/page?foo=bar&baz=qux");
    }

    #[test]
    fn test_get_redirect_uri_rejects_non_http_schemes() {
        let config = test_config();
        // Should reject javascript: and other dangerous schemes
        let uri = get_redirect_uri(Some("javascript:alert(1)"), &config);
        assert_eq!(uri.to_string(), "/");

        let uri = get_redirect_uri(Some("data:text/html,<script>alert(1)</script>"), &config);
        assert_eq!(uri.to_string(), "/");
    }

    // Endpoint integration tests

    #[test]
    fn test_login_endpoint_with_valid_credentials() {
        let client = client_with_user();
        let response = client
            .post(uri!(login(None::<&str>)))
            .header(ContentType::Form)
            .body("username=testuser&password=testpassword")
            .dispatch();

        // Should redirect to root
        assert_eq!(response.status(), Status::SeeOther);
        assert_eq!(
            response.headers().get_one("Location"),
            Some("/")
        );

        // Should set authentication cookie
        let cookie = response.cookies().get_private(USER_COOKIE);
        assert!(cookie.is_some(), "Authentication cookie should be set");
    }

    #[test]
    fn test_login_endpoint_with_invalid_password() {
        let client = client_with_user();
        let response = client
            .post(uri!(login(None::<&str>)))
            .header(ContentType::Form)
            .body("username=testuser&password=wrongpassword")
            .dispatch();

        // Should redirect to login page with error
        assert_eq!(response.status(), Status::SeeOther);
        let location = response.headers().get_one("Location").unwrap();
        assert!(location.contains("/login"));
        assert!(location.contains("error=invalid_credentials"));

        // Should NOT set authentication cookie
        let cookie = response.cookies().get_private(USER_COOKIE);
        assert!(cookie.is_none(), "Authentication cookie should not be set");
    }

    #[test]
    fn test_login_endpoint_with_nonexistent_user() {
        let client = client_with_user();
        let response = client
            .post(uri!(login(None::<&str>)))
            .header(ContentType::Form)
            .body("username=nonexistent&password=anypassword")
            .dispatch();

        // Should redirect to login page with error
        assert_eq!(response.status(), Status::SeeOther);
        let location = response.headers().get_one("Location").unwrap();
        assert!(location.contains("/login"));
        assert!(location.contains("error=invalid_credentials"));

        // Should NOT set authentication cookie
        let cookie = response.cookies().get_private(USER_COOKIE);
        assert!(cookie.is_none(), "Authentication cookie should not be set");
    }

    #[test]
    fn test_login_endpoint_redirects_to_next_parameter() {
        let client = client_with_user();
        let response = client
            .post(uri!(login(Some("https://example.com/dashboard"))))
            .header(ContentType::Form)
            .body("username=testuser&password=testpassword")
            .dispatch();

        // Should redirect to the next URL
        assert_eq!(response.status(), Status::SeeOther);
        assert_eq!(
            response.headers().get_one("Location"),
            Some("https://example.com/dashboard")
        );
    }

    #[test]
    fn test_login_endpoint_rejects_malicious_next_parameter() {
        let client = client_with_user();
        let response = client
            .post(uri!(login(Some("https://evil.com/phishing"))))
            .header(ContentType::Form)
            .body("username=testuser&password=testpassword")
            .dispatch();

        // Should redirect to root, not the malicious URL
        assert_eq!(response.status(), Status::SeeOther);
        assert_eq!(
            response.headers().get_one("Location"),
            Some("/")
        );
    }

    #[test]
    fn test_login_redirect_to_logged_in_when_already_authenticated() {
        let client = client_with_user();

        // First, log in
        let login_response = client
            .post(uri!(login(None::<&str>)))
            .header(ContentType::Form)
            .body("username=testuser&password=testpassword")
            .dispatch();
        assert_eq!(login_response.status(), Status::SeeOther);

        // Now try to access the login page while authenticated
        let response = client.get(uri!(login_redirect_to_logged_in(None::<&str>))).dispatch();

        // Should redirect away from login page
        assert_eq!(response.status(), Status::SeeOther);
        assert_eq!(response.headers().get_one("Location"), Some("/"));
    }

    #[test]
    fn test_login_redirect_respects_next_parameter_when_authenticated() {
        let client = client_with_user();

        // First, log in
        let login_response = client
            .post(uri!(login(None::<&str>)))
            .header(ContentType::Form)
            .body("username=testuser&password=testpassword")
            .dispatch();
        assert_eq!(login_response.status(), Status::SeeOther);

        // Try to access login page with next parameter
        let response = client
            .get(uri!(login_redirect_to_logged_in(Some("https://example.com/dashboard"))))
            .dispatch();

        // Should redirect to next parameter
        assert_eq!(response.status(), Status::SeeOther);
        assert_eq!(
            response.headers().get_one("Location"),
            Some("https://example.com/dashboard")
        );
    }

    #[test]
    fn test_logout_endpoint_clears_authentication() {
        let client = client_with_user();

        // First, log in
        let login_response = client
            .post(uri!(login(None::<&str>)))
            .header(ContentType::Form)
            .body("username=testuser&password=testpassword")
            .dispatch();
        assert_eq!(login_response.status(), Status::SeeOther);
        assert!(login_response.cookies().get_private(USER_COOKIE).is_some());

        // Now log out
        let logout_response = client.get(uri!(logout(None::<&str>))).dispatch();

        // Should redirect to root
        assert_eq!(logout_response.status(), Status::SeeOther);
        assert_eq!(logout_response.headers().get_one("Location"), Some("/"));

        // Verify user is actually logged out by attempting to access login redirect endpoint
        // This endpoint only matches for authenticated users (rank 1)
        let check_response = client.get(uri!(login_redirect_to_logged_in(None::<&str>))).dispatch();

        // Should show the login page (rank 2) instead of redirecting (rank 1)
        assert_eq!(check_response.status(), Status::Ok);
        assert_eq!(check_response.content_type(), Some(ContentType::HTML));
    }

    #[test]
    fn test_logout_endpoint_respects_next_parameter() {
        let client = client_with_user();

        // First, log in
        let login_response = client
            .post(uri!(login(None::<&str>)))
            .header(ContentType::Form)
            .body("username=testuser&password=testpassword")
            .dispatch();
        assert_eq!(login_response.status(), Status::SeeOther);

        // Log out with next parameter
        let logout_response = client
            .get(uri!(logout(Some("https://example.com/goodbye"))))
            .dispatch();

        // Should redirect to next parameter
        assert_eq!(logout_response.status(), Status::SeeOther);
        assert_eq!(
            logout_response.headers().get_one("Location"),
            Some("https://example.com/goodbye")
        );
    }

    #[test]
    fn test_show_login_renders_without_error() {
        let client = client_with_user();
        let response = client.get(uri!(show_login(None::<&str>, None::<LoginError>))).dispatch();

        assert_eq!(response.status(), Status::Ok);
        // Template should be rendered (check content type)
        assert_eq!(response.content_type(), Some(ContentType::HTML));
    }

    #[test]
    fn test_login_failure_preserves_next_parameter_in_redirect() {
        let client = client_with_user();
        let response = client
            .post(uri!(login(Some("https://example.com/dashboard"))))
            .header(ContentType::Form)
            .body("username=testuser&password=wrongpassword")
            .dispatch();

        // Should redirect to login page with both error and next parameter
        assert_eq!(response.status(), Status::SeeOther);
        let location = response.headers().get_one("Location").unwrap();
        assert!(location.contains("/login"), "Location should be login page");
        assert!(location.contains("error=invalid_credentials"), "Location should contain error");
        assert!(location.contains("next="), "Location should preserve next parameter");
        assert!(location.contains("example.com"), "Location should contain the redirect domain");
    }
}
