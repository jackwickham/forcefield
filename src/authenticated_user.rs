use std::convert::Infallible;

use rocket::{
    Request,
    http::{Cookie, CookieJar, Status},
    outcome::Outcome,
    request::{self, FromRequest},
    time::Duration,
};

use crate::config::Config;

const USER_COOKIE: &'static str = "forcefield_user";

pub struct AuthenticatedUser {
    pub id: String,
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
        self.cookies
            .get_private(USER_COOKIE)
            .map(|cookie| AuthenticatedUser {
                id: cookie.value().to_string(),
            })
    }

    pub fn set_authenticated_user(&self, username: &str) {
        self.cookies.add_private(
            Cookie::build((USER_COOKIE, username.to_string()))
                .domain(self.config.cookie_domain.clone())
                .max_age(Duration::hours(1))
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
