use std::{ops::Deref, sync::Arc};

use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;
use time::Duration;

#[derive(Clone)]
pub struct InnerForcefieldState {
    pub public_root: (),
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
