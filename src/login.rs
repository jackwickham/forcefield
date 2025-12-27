use argon2::{
    Argon2, PasswordHasher, PasswordVerifier,
    password_hash::{PasswordHashString, SaltString, rand_core::OsRng},
};
use rocket::{
    State,
    form::Form,
    http::{ext::IntoOwned, uri::Reference},
    response::Redirect,
};
use rocket_dyn_templates::{Template, context};

use crate::{
    authenticated_user::{AuthenticatedUser, AuthenticatedUserStore},
    config::Config,
};

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
    for user in &config.users {
        if user.username == request.username {
            if verify_password(request.password, &user.password_hash) {
                authenticated_user_store.set_authenticated_user(&user.username);
                return Redirect::to(get_redirect_uri(next, config));
            }
        }
    }
    let uri = rocket::uri!(show_login(next, Some(LoginError::InvalidCredentials)));
    Redirect::to(uri)
}

#[rocket::post("/hash-password", data = "<password>")]
pub fn hash_password(password: &str) -> String {
    let a2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);
    a2.hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string()
}

fn verify_password(password: &str, password_hash: &PasswordHashString) -> bool {
    Argon2::default()
        .verify_password(password.as_bytes(), &password_hash.password_hash())
        .is_ok()
}

fn get_redirect_uri(uri_param: Option<&str>, config: &Config) -> Reference<'static> {
    uri_param
        .and_then(|uri| Reference::parse(uri).ok())
        .filter(|uri| {
            uri.authority()
                .is_some_and(|authority| config.root_domain.eq(authority.host()))
        })
        .unwrap_or_else(|| uri!("/").into())
        .into_owned()
}

#[derive(rocket::FromForm)]
pub struct LoginRequest<'a> {
    username: &'a str,
    password: &'a str,
}
