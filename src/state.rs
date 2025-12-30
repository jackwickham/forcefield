use std::{ops::Deref, sync::Arc};

use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;
use time::Duration;
use url::Url;

#[derive(Clone)]
pub struct InnerForcefieldState {
    pub public_root: Url,
    pub root_domain: String,
    pub login_cookie_expiration: Duration,
    pub cookie_encryption_key: Key,
    pub users: Vec<()>,
}

#[derive(Clone)]
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

#[cfg(test)]
impl Default for ForcefieldState {
    fn default() -> Self {
        Self(Arc::new(InnerForcefieldState {
            public_root: Url::parse("http://localhost/")
                .expect("Failed to parse default test public root"),
            root_domain: "localhost".to_owned(),
            login_cookie_expiration: Duration::hours(24),
            cookie_encryption_key: Key::generate(),
            users: vec![],
        }))
    }
}
