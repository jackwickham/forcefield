use std::convert::Infallible;

use rocket::{
    Request,
    http::{Cookie, CookieJar, Status},
    outcome::Outcome,
    request::{self, FromRequest},
};
use serde::{Deserialize, Serialize};
use time::UtcDateTime;

use crate::config::Config;

const USER_COOKIE: &'static str = "forcefield_user";

pub struct AuthenticatedUser {
    pub username: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedUser {
    type Error = Infallible;

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        match AuthenticatedUserStore::from_request(req).await {
            Outcome::Success(store) => store
                .get_authenticated_user()
                .map_or(Outcome::Forward(Status::Unauthorized), Outcome::Success),
            Outcome::Forward(forward) => Outcome::Forward(forward),
            Outcome::Error(error) => Outcome::Error(error),
        }
    }
}

pub struct AuthenticatedUserStore<'a> {
    cookies: &'a CookieJar<'a>,
    config: &'a Config<'a>,
}

impl<'a> AuthenticatedUserStore<'a> {
    pub fn get_authenticated_user(&self) -> Option<AuthenticatedUser> {
        let cookie = self
            .cookies
            .get_private(USER_COOKIE)
            .and_then(|cookie| serde_json::from_str::<UserCookie>(cookie.value()).ok())
            .filter(|cookie| {
                cookie.issued + self.config.login_cookie_expiration > time::UtcDateTime::now()
            })?;
        if cookie.issued + self.config.login_cookie_expiration / 2 < time::UtcDateTime::now() {
            // Refresh the cookie if < 50% time left
            self.set_authenticated_user(&cookie.username);
        }
        Some(AuthenticatedUser {
            username: cookie.username,
        })
    }

    pub fn set_authenticated_user(&self, username: &str) {
        self.cookies.add_private(
            Cookie::build((
                USER_COOKIE,
                serde_json::to_string(&UserCookie {
                    username: username.to_owned(),
                    issued: UtcDateTime::now(),
                })
                .expect("Failed to serialize user cookie"),
            ))
            .domain(self.config.root_domain.clone())
            .max_age(self.config.login_cookie_expiration)
            .http_only(true)
            .same_site(rocket::http::SameSite::Lax)
            .build(),
        )
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedUserStore<'r> {
    type Error = Infallible;

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        Outcome::Success(AuthenticatedUserStore {
            cookies: req.cookies(),
            config: req.rocket().state::<Config>().expect("Config not loaded"),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct UserCookie {
    username: String,
    issued: UtcDateTime,
}
