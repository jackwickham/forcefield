use std::{convert::Infallible, sync::Arc};

use axum::{
    extract::{FromRef, FromRequestParts, Request},
    http::{
        HeaderMap,
        header::{COOKIE, SET_COOKIE},
        request::Parts,
    },
    middleware::Next,
    response::Response,
};
use cookie::{Cookie, Key};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct PrivateCookieJar {
    jar: Arc<RwLock<cookie::CookieJar>>,
    key: Key,
}

impl<S> FromRequestParts<S> for PrivateCookieJar
where
    S: Send + Sync,
    Key: FromRef<S>,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let k = Key::from_ref(state);
        let key = k.into();
        let jar = PrivateCookieJar::from_headers(&parts.headers, key);

        // Store the (potentially updated) cookie jar in extensions
        // The middleware will pick this up and add cookies to the response
        parts.extensions.insert(jar.jar.clone());

        Ok(jar)
    }
}

impl PrivateCookieJar {
    /// Create a new `PrivateCookieJar` from a map of request headers.
    ///
    /// The valid cookies in `headers` will be added to the jar.
    ///
    /// This is intended to be used in middleware and other where places it might be difficult to
    /// run extractors. Normally you should create `PrivateCookieJar`s through [`FromRequestParts`].
    ///
    /// [`FromRequestParts`]: axum::extract::FromRequestParts
    pub fn from_headers(headers: &HeaderMap, key: Key) -> Self {
        let mut jar = cookie::CookieJar::new();
        let mut private_jar = jar.private_mut(&key);
        for cookie in cookies_from_request(headers) {
            if let Some(cookie) = private_jar.decrypt(cookie) {
                private_jar.add_original(cookie);
            }
        }

        Self {
            jar: Arc::new(RwLock::new(jar)),
            key,
        }
    }

    /// Create a new empty `PrivateCookieJarIter`.
    ///
    /// This is intended to be used in middleware and other places where it might be difficult to
    /// run extractors. Normally you should create `PrivateCookieJar`s through [`FromRequestParts`].
    ///
    /// [`FromRequestParts`]: axum::extract::FromRequestParts
    pub fn new(key: Key) -> Self {
        Self {
            jar: Default::default(),
            key,
        }
    }

    /// Get a cookie from the jar.
    ///
    /// If the cookie exists and can be decrypted then it is returned in plaintext.
    #[must_use]
    pub async fn get(&self, name: &str) -> Option<Cookie<'static>> {
        self.jar.read().await.private(&self.key).get(name)
    }

    /// Remove a cookie from the jar.
    pub async fn remove<C: Into<Cookie<'static>>>(&mut self, cookie: C) {
        self.jar.write().await.private_mut(&self.key).remove(cookie);
    }

    /// Add a cookie to the jar.
    ///
    /// The value will automatically be percent-encoded.
    pub async fn add<C: Into<Cookie<'static>>>(&mut self, cookie: C) {
        self.jar.write().await.private_mut(&self.key).add(cookie);
    }

    pub async fn apply_response_headers(&mut self, header_map: &mut HeaderMap) {
        for cookie in self.jar.read().await.delta() {
            if let Ok(header_value) = cookie.encoded().to_string().parse() {
                header_map.append(SET_COOKIE, header_value);
            }
        }
    }
}

/// Middleware that automatically adds cookies from PendingCookieJar to responses
/// Add this to your app with: `.layer(middleware::from_fn(auto_cookie_middleware))`
pub async fn auto_cookie_middleware(mut request: Request, next: Next) -> Response {
    // Extract the pending cookie jar from request extensions (set by the extractor)
    let pending_jar = request.extensions_mut().remove::<PrivateCookieJar>();

    let mut response = next.run(request).await;

    // If there was a pending cookie jar, apply it to the response
    if let Some(mut jar) = pending_jar {
        jar.apply_response_headers(response.headers_mut()).await;
    }
    response
}

fn cookies_from_request(headers: &HeaderMap) -> impl Iterator<Item = Cookie<'static>> + '_ {
    headers
        .get_all(COOKIE)
        .into_iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|cookie| Cookie::parse_encoded(cookie.to_owned()).ok())
}
