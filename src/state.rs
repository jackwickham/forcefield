use std::{collections::HashMap, fmt::Debug, ops::Deref, sync::Arc};

use anyhow::{Error, Result};
use argon2::password_hash::PasswordHashString;
use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;
use base64::Engine;
use time::Duration;
use url::Url;

use crate::config::{ConfigUser, ForcefieldConfig};

#[derive(Clone, Debug)]
pub struct InnerForcefieldState {
    pub public_root: Url,
    pub root_domain: String,
    pub login_cookie_expiration: Duration,
    pub cookie_encryption_key: Key,
    pub users: HashMap<String, User>,
}

#[derive(Clone)]
pub struct User {
    pub username: String,
    pub password_hash: PasswordHashString,
}

impl Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("username", &self.username)
            .field("password_hash", &"redacted")
            .finish()
    }
}

impl TryFrom<ConfigUser> for User {
    type Error = Error;

    fn try_from(user: ConfigUser) -> Result<Self> {
        Ok(User {
            username: user.username,
            password_hash: PasswordHashString::new(&user.password_hash)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ForcefieldState(Arc<InnerForcefieldState>);

impl Deref for ForcefieldState {
    type Target = InnerForcefieldState;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl<'a> FromRef<ForcefieldState> for Key {
    fn from_ref(state: &ForcefieldState) -> Self {
        state.0.as_ref().cookie_encryption_key.clone()
    }
}

impl ForcefieldState {
    pub fn new(state: InnerForcefieldState) -> Self {
        ForcefieldState(Arc::new(state))
    }
}

impl TryFrom<ForcefieldConfig> for ForcefieldState {
    type Error = Error;

    fn try_from(config: ForcefieldConfig) -> Result<ForcefieldState> {
        let mut users = HashMap::<String, User>::with_capacity(config.users.len());
        for user in config.users {
            users.insert(user.username.clone(), user.try_into()?);
        }
        Ok(ForcefieldState::new(InnerForcefieldState {
            public_root: config.public_root,
            root_domain: config.root_domain,
            login_cookie_expiration: config.login_cookie_expiration,
            cookie_encryption_key: Key::from(
                &base64::prelude::BASE64_STANDARD
                    .decode(&config.secret_key)
                    .expect("Failed to deserialize encryption key"),
            ),
            users,
        }))
    }
}

#[cfg(test)]
impl Default for ForcefieldState {
    fn default() -> Self {
        Self(Arc::new(InnerForcefieldState {
            public_root: Url::parse("http://localhost/")
                .expect("Failed to parse default test public root"),
            root_domain: "localhost".to_owned(),
            login_cookie_expiration: Duration::hours(24),
            cookie_encryption_key: Key::generate(),
            users: HashMap::new(),
        }))
    }
}
