use std::fmt;

use argon2::password_hash::PasswordHashString;
use duration_str::deserialize_duration_time;
use figment::{
    Figment, Profile,
    providers::{Format, Toml},
};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Error},
};
use time::Duration;
use url::Url;

pub fn get_figment<P: Into<Profile>>(profile: P) -> Figment {
    Figment::from(Toml::file("Rocket.toml").nested())
        .merge(Toml::file("secrets.toml"))
        .select(profile)
}

#[cfg(test)]
pub fn get_test_figment() -> Figment {
    get_figment("test")
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub public_root: Url,
    pub root_domain: String,

    pub secret_key: String,

    #[serde(
        default = "default_cookie_expiration",
        deserialize_with = "deserialize_duration_time"
    )]
    pub login_cookie_expiration: Duration,

    #[serde(default)]
    pub enable_hash_password: bool,

    pub users: Vec<ConfigUser>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ConfigUser {
    pub username: String,

    #[serde(
        deserialize_with = "deserialize_password_hash_string",
        serialize_with = "serialize_password_hash_string"
    )]
    pub password_hash: PasswordHashString,
}

fn deserialize_password_hash_string<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<PasswordHashString, D::Error> {
    deserializer.deserialize_str(StrVisitor)
}

fn serialize_password_hash_string<S: Serializer>(
    value: &PasswordHashString,
    serializer: S,
) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> {
    serializer.serialize_str(value.as_str())
}

struct StrVisitor;

impl<'a> de::Visitor<'a> for StrVisitor {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_deserialization_with_all_fields() {
        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "Rocket.toml",
                r#"
                [global]
                public_root = "https://example.com"
                root_domain = "example.com"
                login_cookie_expiration = "30d"
                enable_hash_password = true
                "#,
            )?;
            jail.create_file("secrets.toml", r#"
                secret_key = "7Zbj9EawZGn+YtMCBncReneuwI7pJJna9JPVBllMHq8="

                [[users]]
                username = "test-1"
                password_hash = "$argon2id$v=19$m=19456,t=2,p=1$VE1xSlEvTDFnQlBuTGlzVA$cIPcGzaGOxdkRz+bOq1n4LXl/TRHMd06CjKlMdWkLd0"

                [[users]]
                username = "test-2"
                password_hash = "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQxMjM0NTY3OA$2MFj/F1FfRVS9fDN2N1j0WGZ1nS0q3n6m5Z3N1L0H8Y"
            "#)?;

            let figment = get_figment("test");
            let config: Config = figment.extract().expect("Failed to deserialize config");

            assert_eq!(config.public_root.to_string(), "https://example.com");
            assert_eq!(config.root_domain, "example.com");
            assert_eq!(config.login_cookie_expiration, Duration::days(30));
            assert_eq!(config.enable_hash_password, true);
            assert_eq!(config.users.len(), 2);
            assert_eq!(config.users[0].username, "test-1");
            assert_eq!(config.users[1].username, "test-2");

            Ok(())
        })
    }

    #[test]
    fn test_config_deserialization_with_defaults() {
        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "Rocket.toml",
                r#"
                [global]
                public_root = "https://example.com"
                root_domain = "example.com"

                users = []
                "#,
            )?;

            let figment = get_figment("test");
            let config: Config = figment.extract().expect("Failed to deserialize config");

            assert_eq!(config.login_cookie_expiration, Duration::days(90));
            assert_eq!(config.enable_hash_password, false);
            assert_eq!(config.users.len(), 0);

            Ok(())
        })
    }
}
