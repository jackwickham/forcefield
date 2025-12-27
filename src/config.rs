use std::fmt;

use argon2::password_hash::PasswordHashString;
use duration_str::deserialize_duration_time;
use rocket::{
    http::uri::Absolute,
    serde::{Deserialize, Deserializer, de::Error},
};
use time::Duration;

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct Config<'a> {
    pub public_root: Absolute<'a>,
    pub root_domain: String,

    #[serde(
        default = "default_cookie_expiration",
        deserialize_with = "deserialize_duration_time"
    )]
    pub login_cookie_expiration: Duration,

    pub users: Vec<ConfigUser>,
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct ConfigUser {
    pub username: String,

    #[serde(deserialize_with = "deserialize_password_hash_string")]
    pub password_hash: PasswordHashString,
}

fn deserialize_password_hash_string<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<PasswordHashString, D::Error> {
    deserializer.deserialize_str(StrVisitor)
}

struct StrVisitor;

impl<'a> rocket::serde::de::Visitor<'a> for StrVisitor {
    type Value = PasswordHashString;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a borrowed string")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        PasswordHashString::new(v).map_err(Error::custom)
    }

    fn visit_borrowed_str<E>(self, v: &'a str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        PasswordHashString::new(v).map_err(Error::custom)
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: Error,
    {
        PasswordHashString::new(&v).map_err(Error::custom)
    }
}

fn default_cookie_expiration() -> Duration {
    Duration::days(90)
}
