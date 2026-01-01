use std::env;

use config::{Config, ConfigError, File};
use duration_str::deserialize_duration_time;
use serde::{Deserialize, Serialize};
use time::Duration;
use url::Url;

#[derive(Serialize, Deserialize)]
pub struct ForcefieldConfig {
    pub public_root: Url,
    pub root_domain: String,
    pub enable_hash_password: bool,

    /// Optional header name to read client IP from (e.g., "X-Real-IP").
    /// If not set, the connecting socket address is used.
    pub client_ip_header: Option<String>,

    #[serde(deserialize_with = "deserialize_duration_time")]
    pub login_cookie_expiration: Duration,

    pub secret_key: String,
    pub users: Vec<ConfigUser>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ConfigUser {
    pub username: String,
    pub password_hash: String,
}

impl ForcefieldConfig {
    pub fn load() -> Result<Self, ConfigError> {
        let secrets_file_path = env::var("FORCEFIELD_SECRETS_FILE")
            .unwrap_or_else(|_| "forcefield-secrets.toml".into());
        let s = Config::builder()
            .set_default("login_cookie_expiration", "7d")?
            .set_default("enable_hash_password", false)?
            .add_source(File::with_name("forcefield.toml"))
            .add_source(File::with_name(&secrets_file_path).required(false))
            .build()?;

        s.try_deserialize()
    }
}
