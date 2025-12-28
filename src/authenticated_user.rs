use std::convert::Infallible;

use axum::{extract::FromRequestParts, http::StatusCode};
use cookie::Cookie;
use serde::{Deserialize, Serialize};
use time::UtcDateTime;

use crate::{cookies::PrivateCookieJar, state::ForcefieldState};

const USER_COOKIE: &'static str = "forcefield_user";

pub struct AuthenticatedUserState {
    cookies: PrivateCookieJar,
    state: ForcefieldState,
}

impl AuthenticatedUserState {
    pub async fn get_authenticated_user(mut self) -> Option<AuthenticatedUser> {
        let cookie = self
            .cookies
            .get(USER_COOKIE)
            .await
            .and_then(|cookie| serde_json::from_str::<UserCookie>(cookie.value()).ok())
            .filter(|cookie| {
                cookie.issued + self.state.login_cookie_expiration > time::UtcDateTime::now()
            })?;
        if cookie.issued + self.state.login_cookie_expiration / 2 < time::UtcDateTime::now() {
            // Refresh the cookie if < 50% time left
            self.set_authenticated_user(&cookie.username).await;
        }
        Some(AuthenticatedUser {
            username: cookie.username,
        })
    }

    pub async fn set_authenticated_user(&mut self, username: &str) {
        assert!(username.len() > 0, "Username cannot be blank");
        self.cookies
            .add(AuthenticatedUserState::make_cookie(
                Some(&UserCookie {
                    username: username.to_owned(),
                    issued: UtcDateTime::now(),
                }),
                &self.state,
            ))
            .await;
    }

    pub async fn clear_authenticated_user(&mut self) {
        self.cookies
            .remove(AuthenticatedUserState::make_cookie(None, &self.state))
            .await;
    }

    fn make_cookie(value: Option<&UserCookie>, config: &ForcefieldState) -> Cookie<'static> {
        Cookie::build((
            USER_COOKIE,
            value.map_or("".to_owned(), |val| {
                serde_json::to_string(val).expect("Failed to serialize user cookie")
            }),
        ))
        .domain(config.root_domain.clone())
        .max_age(config.login_cookie_expiration)
        .http_only(true)
        .same_site(cookie::SameSite::Lax) // Fixed: was rocket::http::SameSite
        .secure(true)
        .build()
    }
}

impl FromRequestParts<ForcefieldState> for AuthenticatedUserState {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &ForcefieldState,
    ) -> Result<Self, Infallible> {
        let cookie_jar = PrivateCookieJar::from_request_parts(parts, state).await?;
        Ok(AuthenticatedUserState {
            cookies: cookie_jar,
            state: state.clone(),
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct AuthenticatedUser {
    pub username: String,
}

impl FromRequestParts<ForcefieldState> for AuthenticatedUser {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &ForcefieldState,
    ) -> Result<Self, Self::Rejection> {
        let auth_state = AuthenticatedUserState::from_request_parts(parts, state)
            .await
            .expect("Failed to create AuthenticatedUserState");

        auth_state
            .get_authenticated_user()
            .await
            .ok_or(StatusCode::UNAUTHORIZED)
    }
}

impl FromRequestParts<ForcefieldState> for Option<AuthenticatedUser> {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &ForcefieldState,
    ) -> Result<Self, Self::Rejection> {
        AuthenticatedUser::from_request_parts(parts, state)
            .await
            .map(Some)
            .or(Ok(None))
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
struct UserCookie {
    username: String,
    issued: UtcDateTime,
}
