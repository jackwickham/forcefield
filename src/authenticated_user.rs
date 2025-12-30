use std::convert::Infallible;

use axum::{extract::FromRequestParts, http::StatusCode};
use cookie::Cookie;
use serde::{Deserialize, Serialize};
use time::UtcDateTime;

use crate::{cookies::PrivateCookieJar, state::ForcefieldState};

const USER_COOKIE: &'static str = "forcefield_user";

pub struct AuthenticatedUserManager {
    cookies: PrivateCookieJar,
    state: ForcefieldState,
}

impl AuthenticatedUserManager {
    #[cfg(test)]
    pub fn new_for_test(cookies: PrivateCookieJar, state: ForcefieldState) -> Self {
        AuthenticatedUserManager { cookies, state }
    }

    pub async fn get_authenticated_user(mut self) -> Option<AuthenticatedUser> {
        let raw_cookie = self.cookies.get(USER_COOKIE).await?;

        let valid_cookie = serde_json::from_str::<UserCookie>(raw_cookie.value())
            .ok()
            .filter(|cookie| {
                cookie.issued + self.state.login_cookie_expiration > time::UtcDateTime::now()
            });
        if let Some(cookie) = valid_cookie {
            if cookie.issued + self.state.login_cookie_expiration / 2 < time::UtcDateTime::now() {
                // Refresh the cookie if < 50% time left
                self.set_authenticated_user(&cookie.username).await;
            }
            Some(AuthenticatedUser {
                username: cookie.username,
            })
        } else {
            println!("Cookie was expired or invalid");
            self.clear_authenticated_user().await;
            None
        }
    }

    pub async fn set_authenticated_user(&mut self, username: &str) {
        assert!(username.len() > 0, "Username cannot be blank");
        self.cookies
            .add(AuthenticatedUserManager::make_cookie(
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
            .remove(AuthenticatedUserManager::make_cookie(None, &self.state))
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
        .same_site(cookie::SameSite::Lax)
        .secure(true)
        .build()
    }
}

impl FromRequestParts<ForcefieldState> for AuthenticatedUserManager {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &ForcefieldState,
    ) -> Result<Self, Infallible> {
        let cookie_jar = PrivateCookieJar::from_request_parts(parts, state).await?;
        Ok(AuthenticatedUserManager {
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
        let auth_state = AuthenticatedUserManager::from_request_parts(parts, state)
            .await
            .expect("Failed to create AuthenticatedUserManager");

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

#[cfg(test)]
mod test {
    use cookie::Key;
    use time::macros::datetime;

    use super::*;

    #[test]
    fn user_cookie_roundtrip() {
        let original = UserCookie {
            username: "testuser123".to_string(),
            issued: datetime!(2024-06-20 15:30:45 UTC).into(),
        };

        let json = serde_json::to_string(&original).expect("Failed to serialize");
        let deserialized: UserCookie = serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(original.username, deserialized.username);
        assert_eq!(original.issued, deserialized.issued);
    }

    #[tokio::test]
    async fn get_authenticated_user_no_cookie() {
        let cookies = PrivateCookieJar::create_with_cookies(Key::generate(), vec![]);
        let state = AuthenticatedUserManager {
            cookies: cookies.clone(),
            state: ForcefieldState::default(),
        };

        assert_eq!(state.get_authenticated_user().await, None);
        assert_eq!(cookies.get_delta().await, Vec::<Cookie>::new());
    }

    #[tokio::test]
    async fn get_authenticated_user_logged_in() {
        let cookies = PrivateCookieJar::create_with_cookies(
            Key::generate(),
            user_cookie("test-user", UtcDateTime::now()),
        );
        let state = AuthenticatedUserManager {
            cookies: cookies.clone(),
            state: ForcefieldState::default(),
        };

        assert_eq!(
            state.get_authenticated_user().await,
            Some(AuthenticatedUser {
                username: "test-user".to_owned(),
            })
        );
        assert_eq!(cookies.get_delta().await, Vec::<Cookie>::new());
    }

    #[tokio::test]
    async fn get_authenticated_user_refreshes_nearly_expired_cookie() {
        let state = ForcefieldState::default();
        let cookies = PrivateCookieJar::create_with_cookies(
            Key::generate(),
            user_cookie(
                "test-user",
                UtcDateTime::now() - state.login_cookie_expiration / 2,
            ),
        );
        let state = AuthenticatedUserManager {
            cookies: cookies.clone(),
            state: state,
        };

        assert_eq!(
            state.get_authenticated_user().await,
            Some(AuthenticatedUser {
                username: "test-user".to_owned(),
            })
        );
        let set_cookies = cookies.get_delta().await;
        assert_eq!(set_cookies.len(), 1);
        assert_eq!(set_cookies.first().unwrap().name(), USER_COOKIE);
        let cookie_val: UserCookie = serde_json::from_str(
            cookies
                .decrypt(set_cookies.first().unwrap().clone())
                .await
                .expect("Failed to decrypt cookie")
                .value(),
        )
        .expect("Failed to deserialize set cookie");
        assert_eq!(cookie_val.username, "test-user");
    }

    #[tokio::test]
    async fn get_authenticated_user_invalid_cookie() {
        let cookies = PrivateCookieJar::create_with_cookies(
            Key::generate(),
            vec![(USER_COOKIE.to_owned(), "invalid".to_owned())],
        );
        let state = AuthenticatedUserManager {
            cookies: cookies.clone(),
            state: ForcefieldState::default(),
        };

        assert_eq!(state.get_authenticated_user().await, None);
        let set_cookies = cookies.get_delta().await;
        assert_eq!(set_cookies.len(), 1);
        assert_eq!(set_cookies.first().unwrap().name(), USER_COOKIE);
        assert_eq!(set_cookies.first().unwrap().value(), "");
    }

    #[tokio::test]
    async fn get_authenticated_user_expired_cookie() {
        let state = ForcefieldState::default();
        let cookies = PrivateCookieJar::create_with_cookies(
            Key::generate(),
            user_cookie(
                "test-user",
                UtcDateTime::now() - state.login_cookie_expiration,
            ),
        );
        let state = AuthenticatedUserManager {
            cookies: cookies.clone(),
            state: ForcefieldState::default(),
        };

        assert_eq!(state.get_authenticated_user().await, None);
        let set_cookies = cookies.get_delta().await;
        assert_eq!(set_cookies.len(), 1);
        assert_eq!(set_cookies.first().unwrap().name(), USER_COOKIE);
        assert_eq!(set_cookies.first().unwrap().value(), "");
    }

    #[tokio::test]
    async fn set_authenticated_user_sets_cookie() {
        let cookies = PrivateCookieJar::create_with_cookies(
            Key::generate(),
            user_cookie("existing-user", UtcDateTime::now()),
        );
        let mut state = AuthenticatedUserManager {
            cookies: cookies.clone(),
            state: ForcefieldState::default(),
        };

        state.set_authenticated_user("test-user").await;

        let set_cookies = cookies.get_delta().await;
        assert_eq!(set_cookies.len(), 1);
        assert_eq!(set_cookies.first().unwrap().name(), USER_COOKIE);
        let cookie_val: UserCookie = serde_json::from_str(
            cookies
                .decrypt(set_cookies.first().unwrap().clone())
                .await
                .expect("Failed to decrypt cookie")
                .value(),
        )
        .expect("Failed to deserialize set cookie");
        assert_eq!(cookie_val.username, "test-user");
    }

    #[tokio::test]
    async fn clear_authenticated_user_clears_cookie() {
        let cookies = PrivateCookieJar::create_with_cookies(
            Key::generate(),
            user_cookie("existing-user", UtcDateTime::now()),
        );
        let mut state = AuthenticatedUserManager {
            cookies: cookies.clone(),
            state: ForcefieldState::default(),
        };

        state.clear_authenticated_user().await;

        let set_cookies = cookies.get_delta().await;
        assert_eq!(set_cookies.len(), 1);
        assert_eq!(set_cookies.first().unwrap().name(), USER_COOKIE);
        assert_eq!(set_cookies.first().unwrap().value(), "");
    }

    fn user_cookie(username: &str, issued: UtcDateTime) -> Vec<(String, String)> {
        vec![(
            USER_COOKIE.to_owned(),
            serde_json::to_string(&UserCookie {
                username: username.to_owned(),
                issued,
            })
            .expect("Failed to serialize test cookie"),
        )]
    }
}
