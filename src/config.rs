use config::{Config, ConfigError, File};
use duration_str::deserialize_duration_time;
use serde::{Deserialize, Serialize};
use time::Duration;
use url::Url;

#[derive(Serialize, Deserialize)]
pub struct ForcefieldConfig {
    pub public_root: Url,
    pub root_domain: String,

    pub secret_key: String,

    #[serde(deserialize_with = "deserialize_duration_time")]
    pub login_cookie_expiration: Duration,

    #[serde(default)]
    pub enable_hash_password: bool,

    pub users: Vec<ConfigUser>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ConfigUser {
    pub username: String,
    pub password_hash: String,
}

impl ForcefieldConfig {
    pub fn load() -> Result<Self, ConfigError> {
        let s = Config::builder()
            .set_default("login_cookie_expiration", "7d")?
            .set_default("enable_hash_password", false)?
            .add_source(File::with_name("config.toml"))
            .add_source(File::with_name("secrets.toml").required(false))
            .build()?;

        s.try_deserialize()
    }
}
