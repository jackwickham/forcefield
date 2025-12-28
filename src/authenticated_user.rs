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

#[derive(Debug, PartialEq, Eq)]
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
        assert!(username.len() > 0, "Username cannot be blank");
        self.cookies
            .add_private(AuthenticatedUserStore::make_cookie(
                Some(&UserCookie {
                    username: username.to_owned(),
                    issued: UtcDateTime::now(),
                }),
                &self.config,
            ))
    }

    pub fn clear_authenticated_user(&self) {
        self.cookies
            .remove_private(AuthenticatedUserStore::make_cookie(None, self.config));
    }

    fn make_cookie(value: Option<&UserCookie>, config: &Config) -> Cookie<'static> {
        Cookie::build((
            USER_COOKIE,
            value.map_or("".to_owned(), |val| {
                serde_json::to_string(val).expect("Failed to serialize user cookie")
            }),
        ))
        .domain(config.root_domain.clone())
        .max_age(config.login_cookie_expiration)
        .http_only(true)
        .same_site(rocket::http::SameSite::Lax)
        .secure(true)
        .build()
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
#[cfg_attr(test, derive(PartialEq, Clone))]
struct UserCookie {
    username: String,
    issued: UtcDateTime,
}

#[cfg(test)]
mod tests {
    use crate::config::get_test_figment;
    use crate::rocket;

    use super::*;
    use rocket::fairing::AdHoc;
    use rocket::http::Cookie;
    use rocket::local::blocking::Client;
    use rocket::response::status::NoContent;
    use time::macros::datetime;

    fn test_config() -> Config<'static> {
        get_test_figment()
            .extract::<Config<'static>>()
            .expect("Failed to deserialize test config")
    }

    #[rocket::get("/authenticated")]
    fn endpoint_get_authenticated_user(
        user: Option<AuthenticatedUser>,
    ) -> Result<String, NoContent> {
        user.map(|u| u.username).ok_or(NoContent)
    }

    #[rocket::post("/set-authenticated?<username>")]
    fn endpoint_set_authenticated_user(store: AuthenticatedUserStore, username: &str) {
        store.set_authenticated_user(username);
    }

    #[rocket::post("/clear-authenticated")]
    fn endpoint_clear_authenticated_user(store: AuthenticatedUserStore) {
        store.clear_authenticated_user();
    }

    fn client() -> Client {
        let rocket = rocket::custom(get_test_figment())
            .attach(AdHoc::config::<Config>())
            .mount(
                "/",
                routes![
                    endpoint_get_authenticated_user,
                    endpoint_set_authenticated_user,
                    endpoint_clear_authenticated_user
                ],
            );
        Client::tracked(rocket).expect("Failed to create rocket")
    }

    #[test]
    fn test_user_cookie_roundtrip() {
        let original = UserCookie {
            username: "testuser123".to_string(),
            issued: datetime!(2024-06-20 15:30:45 UTC).into(),
        };

        let json = serde_json::to_string(&original).expect("Failed to serialize");
        let deserialized: UserCookie = serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(original.username, deserialized.username);
        assert_eq!(original.issued, deserialized.issued);
    }

    #[test]
    fn test_user_cookie_with_special_characters() {
        let cookie = UserCookie {
            username: "user@!#💩".to_string(),
            issued: datetime!(2024-01-01 00:00:00 UTC).into(),
        };

        let json = serde_json::to_string(&cookie).expect("Failed to serialize");
        let deserialized: UserCookie = serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(cookie.username, deserialized.username);
    }

    #[test]
    fn test_authenticated_user_store_get_authenticated_user_not_logged_in() {
        let client = Client::tracked(rocket()).expect("Not a valid rocket");
        let store = AuthenticatedUserStore {
            cookies: &client.cookies(),
            config: &test_config(),
        };

        assert_eq!(store.get_authenticated_user(), None)
    }

    #[test]
    fn test_get_authenticated_user_no_cookie() {
        let client = client();
        let resp = client.get(uri!(endpoint_get_authenticated_user)).dispatch();
        assert_eq!(resp.status(), Status::NoContent);
        assert_eq!(
            resp.cookies().iter().collect::<Vec<&Cookie>>(),
            vec![] as Vec<&Cookie>
        );
    }

    #[test]
    fn test_get_authenticated_user_valid_user() {
        let client = client();
        let resp = client
            .get(uri!(endpoint_get_authenticated_user))
            .private_cookie(AuthenticatedUserStore::make_cookie(
                Some(&UserCookie {
                    username: "test-username".to_owned(),
                    issued: UtcDateTime::now(),
                }),
                &test_config(),
            ))
            .dispatch();
        assert_eq!(resp.status(), Status::Ok);
        assert_eq!(
            resp.cookies().iter().collect::<Vec<&Cookie>>(),
            vec![] as Vec<&Cookie>
        );
        assert_eq!(resp.into_string(), Some("test-username".to_owned()));
    }

    #[test]
    fn test_get_authenticated_user_expired() {
        let client = client();
        let resp = client
            .get(uri!(endpoint_get_authenticated_user))
            .private_cookie(AuthenticatedUserStore::make_cookie(
                Some(&UserCookie {
                    username: "test-username".to_owned(),
                    issued: UtcDateTime::now() - test_config().login_cookie_expiration,
                }),
                &test_config(),
            ))
            .dispatch();
        assert_eq!(resp.status(), Status::NoContent);
        assert_eq!(
            resp.cookies().iter().collect::<Vec<&Cookie>>(),
            vec![] as Vec<&Cookie>
        );
    }

    #[test]
    fn test_get_authenticated_user_refreshes_nearly_expired() {
        let client = client();
        let start_time = UtcDateTime::now();
        let resp = client
            .get(uri!(endpoint_get_authenticated_user))
            .private_cookie(AuthenticatedUserStore::make_cookie(
                Some(&UserCookie {
                    username: "test-username".to_owned(),
                    issued: start_time - test_config().login_cookie_expiration / 2,
                }),
                &test_config(),
            ))
            .dispatch();
        assert_eq!(resp.status(), Status::Ok);
        let raw_cookie = resp
            .cookies()
            .get_private(USER_COOKIE)
            .expect("Cookie not set");
        let cookie: UserCookie =
            serde_json::from_str(raw_cookie.value()).expect("Failed to deserialize cookie");
        assert_eq!(cookie.username, "test-username");
        assert!(
            cookie.issued > start_time,
            "Issued time on cookie was too early"
        );
        assert!(
            cookie.issued < UtcDateTime::now(),
            "Issued time on cookie was too late"
        );
        assert_eq!(resp.into_string(), Some("test-username".to_owned()));
    }

    #[test]
    fn test_get_authenticated_user_invalid_cookie_ignored() {
        let client = client();
        let resp = client
            .get(uri!(endpoint_get_authenticated_user))
            .private_cookie((USER_COOKIE, "INVALID"))
            .dispatch();
        assert_eq!(resp.status(), Status::NoContent);
        assert_eq!(
            resp.cookies().iter().collect::<Vec<&Cookie>>(),
            vec![] as Vec<&Cookie>
        );
    }

    #[test]
    fn test_get_authenticated_user_not_private_cookie_ignored() {
        let client = client();
        let resp = client
            .get(uri!(endpoint_get_authenticated_user))
            .cookie(AuthenticatedUserStore::make_cookie(
                Some(&UserCookie {
                    username: "test-username".to_owned(),
                    issued: UtcDateTime::now(),
                }),
                &test_config(),
            ))
            .dispatch();
        assert_eq!(resp.status(), Status::NoContent);
        assert_eq!(
            resp.cookies().iter().collect::<Vec<&Cookie>>(),
            vec![] as Vec<&Cookie>
        );
    }

    #[test]
    fn test_set_authenticated_user() {
        let client = client();
        let start_time = UtcDateTime::now();
        let set_resp = client
            .post(uri!(endpoint_set_authenticated_user("test-username")))
            .dispatch();

        assert_eq!(set_resp.status(), Status::Ok);
        let raw_cookie = set_resp
            .cookies()
            .get_private(USER_COOKIE)
            .expect("Cookie not set");
        let cookie: UserCookie =
            serde_json::from_str(raw_cookie.value()).expect("Failed to deserialize cookie");
        assert_eq!(cookie.username, "test-username");
        assert!(
            cookie.issued > start_time,
            "Issued time on cookie was too early"
        );
        assert!(
            cookie.issued < UtcDateTime::now(),
            "Issued time on cookie was too late"
        );

        let get_resp = client.get(uri!(endpoint_get_authenticated_user)).dispatch();
        assert_eq!(get_resp.status(), Status::Ok);
        assert_eq!(
            get_resp.cookies().iter().collect::<Vec<&Cookie>>(),
            vec![] as Vec<&Cookie>
        );
        assert_eq!(get_resp.into_string(), Some("test-username".to_owned()));
    }

    #[test]
    fn test_clear_authenticated_user() {
        let client = client();
        let set_resp = client
            .post(uri!(endpoint_set_authenticated_user("test-username")))
            .dispatch();
        assert_eq!(set_resp.status(), Status::Ok);

        let clear_resp = client
            .post(uri!(endpoint_clear_authenticated_user))
            .dispatch();
        assert_eq!(clear_resp.status(), Status::Ok);

        let get_resp = client.get(uri!(endpoint_get_authenticated_user)).dispatch();
        assert_eq!(get_resp.status(), Status::NoContent);
        assert_eq!(
            get_resp.cookies().iter().collect::<Vec<&Cookie>>(),
            vec![] as Vec<&Cookie>
        );
    }
}
