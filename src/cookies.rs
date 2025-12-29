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

/// Struct to allow reserving a space for the cookie jar to be stored
#[derive(Clone)]
struct CookieJarRef(Arc<RwLock<Option<PrivateCookieJar>>>);

impl CookieJarRef {
    fn new() -> Self {
        CookieJarRef(Arc::new(RwLock::new(None)))
    }
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

        // Store the cookie jar in extensions, so updates to the jar can be picked up by the
        // middleware and sent in the response.
        parts
            .extensions
            .get::<CookieJarRef>()
            .expect("Cookie middleware not registered")
            .0
            .write()
            .await
            .replace(jar.clone());

        Ok(jar)
    }
}

impl PrivateCookieJar {
    /// Create a new `PrivateCookieJar` from a map of request headers.
    ///
    /// The valid cookies in `headers` will be created in the jar already.
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

    /// Create a cookie jar with cookies already in it, for testing.
    #[cfg(test)]
    pub fn create_with_cookies(key: Key, cookies: Vec<(String, String)>) -> Self {
        let mut jar = cookie::CookieJar::new();
        let mut private_jar = jar.private_mut(&key);
        for cookie in cookies {
            private_jar.add_original(cookie);
        }

        Self {
            jar: Arc::new(RwLock::new(jar)),
            key,
        }
    }

    /// Get a cookie from the jar.
    ///
    /// If the cookie exists and can be decrypted then it is returned in plaintext,
    /// otherwise None is returned.
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

    /// Apply the changes to the cookie jar as Set-Cookie headers.
    pub async fn apply_response_headers(&mut self, header_map: &mut HeaderMap) {
        for cookie in self.jar.read().await.delta() {
            if let Ok(header_value) = cookie.encoded().to_string().parse() {
                header_map.append(SET_COOKIE, header_value);
            }
        }
    }

    /// Decrypt a cookie, for debugging.
    #[cfg(test)]
    pub async fn decrypt(&self, cookie: Cookie<'static>) -> Option<Cookie<'static>> {
        self.jar.read().await.private(&self.key).decrypt(cookie)
    }

    /// Get a list of changes that have been made to cookies, for testing.
    #[cfg(test)]
    pub async fn get_delta(&self) -> Vec<Cookie<'static>> {
        self.jar
            .read()
            .await
            .delta()
            .map(|cookie| cookie.clone())
            .collect()
    }
}

/// Middleware that automatically sends cookies that were added during the request.
pub async fn auto_cookie_middleware(mut request: Request, next: Next) -> Response {
    let cookie_jar_ref = CookieJarRef::new();
    request.extensions_mut().insert(cookie_jar_ref.clone());

    let mut response = next.run(request).await;

    if let &mut Some(ref mut jar) = &mut *cookie_jar_ref.0.write().await {
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
        .map(|cookie| Cookie::parse_encoded(cookie.to_owned()).expect("Failed to parse cookie"))
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use super::*;

    use axum::http::{HeaderMap, HeaderValue, header::COOKIE};
    use percent_encoding::percent_decode_str;
    use rocket::futures;
    use time::Duration;

    // The cookie name is added as additional data in the encrypted value, so the value is only valid with that specific cookie
    const ENCRYPTED_FOO_ALPHA: &'static str = "MeWbk95B2umJO%2FSm7Hpe1E55VSLoQnC%2FOfuObXp8QrKp";
    const ENCRYPTED_BAR_BETA: &'static str = "X2RrM0oLZvMeduelLZtighRauVolvihe1K3NIzBmvlM%3D";
    const ENCRYPTED_BAZ_GAMMA: &'static str = "3WH2CbePTxjHyZZmq2AJxUhSMsDSGwK21NVgxOHjGMXN";

    #[tokio::test]
    async fn parses_from_headers() {
        let mut headers = HeaderMap::new();
        headers.append(
            COOKIE,
            HeaderValue::from_str(&format!(
                "foo={}; bar={}",
                ENCRYPTED_FOO_ALPHA, ENCRYPTED_BAR_BETA
            ))
            .expect("Failed to parse header"),
        );
        headers.append(
            "X-Not-Cookie",
            HeaderValue::from_str(&format!("baz={}", ENCRYPTED_BAZ_GAMMA))
                .expect("Failed to parse header"),
        );
        let jar = PrivateCookieJar::from_headers(&headers, Key::derive_from(&[0; 32]));

        assert_eq!(jar.get_delta().await, Vec::<Cookie>::new());
        assert_eq!(jar.get("foo").await, Some(Cookie::new("foo", "alpha")));
        assert_eq!(jar.get("bar").await, Some(Cookie::new("bar", "beta")));
        assert_eq!(jar.get("my-value").await, None);
    }

    #[tokio::test]
    async fn sets_new_cookies_in_response() {
        let mut req_headers = HeaderMap::new();
        req_headers.append(
            COOKIE,
            HeaderValue::from_str(&format!(
                "foo={}; bar={}",
                ENCRYPTED_FOO_ALPHA, ENCRYPTED_BAR_BETA
            ))
            .expect("Failed to parse header"),
        );
        let mut jar = PrivateCookieJar::from_headers(&req_headers, Key::derive_from(&[0; 32]));

        jar.add(("foo", "delta")).await;
        jar.add(("baz", "epsilon")).await;

        let delta_cookies = jar.get_delta().await;
        let decrypted_delta: HashSet<(String, String)> =
            futures::future::join_all(delta_cookies.iter().map(async |cookie| {
                jar.decrypt(cookie.clone())
                    .await
                    .expect("Failed to deserialize cookie that was set")
            }))
            .await
            .into_iter()
            .map(|cookie| (cookie.name().to_owned(), cookie.value().to_owned()))
            .collect();
        assert_eq!(
            decrypted_delta,
            vec![("foo", "delta"), ("baz", "epsilon")]
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect()
        );

        let mut resp_headers = HeaderMap::new();
        jar.apply_response_headers(&mut resp_headers).await;

        let cookie_headers = resp_headers.get_all(SET_COOKIE);
        assert_eq!(
            cookie_headers
                .iter()
                .map(|header| {
                    header
                        .to_str()
                        .map(|value| percent_decode_str(value).decode_utf8_lossy())
                        .expect("Failed to convert header to string")
                        .to_string()
                })
                .collect::<HashSet<_>>(),
            delta_cookies
                .iter()
                .map(|cookie| format!("{}={}", cookie.name(), cookie.value()))
                .collect::<HashSet<_>>()
        )
    }

    #[tokio::test]
    async fn removes_cookies() {
        let mut req_headers = HeaderMap::new();
        req_headers.append(
            COOKIE,
            HeaderValue::from_str(&format!(
                "foo={}; bar={}",
                ENCRYPTED_FOO_ALPHA, ENCRYPTED_BAR_BETA
            ))
            .expect("Failed to parse header"),
        );
        let mut jar = PrivateCookieJar::from_headers(&req_headers, Key::derive_from(&[0; 32]));
        assert_eq!(jar.get("foo").await, Some(Cookie::new("foo", "alpha")));

        jar.remove(Cookie::from("foo")).await;

        assert_eq!(jar.get("foo").await, None);
        let delta_cookies = jar.get_delta().await;
        assert_eq!(delta_cookies.len(), 1);

        let removed_cookie = &delta_cookies[0];
        assert_eq!(removed_cookie.name(), "foo");
        assert!(
            removed_cookie
                .max_age()
                .is_some_and(|v| v == Duration::ZERO)
                && removed_cookie.value().is_empty()
        );
    }

    #[tokio::test]
    async fn silently_ignores_invalid_cookies() {
        let mut headers = HeaderMap::new();

        headers.append(
            COOKIE,
            HeaderValue::from_str(&format!(
                "foo={}; invalid_cookie=not_encrypted_data; bar={}; another_bad=xyz123",
                ENCRYPTED_FOO_ALPHA, ENCRYPTED_BAR_BETA
            ))
            .expect("Failed to parse header"),
        );

        let jar = PrivateCookieJar::from_headers(&headers, Key::derive_from(&[0; 32]));

        assert_eq!(jar.get("foo").await, Some(Cookie::new("foo", "alpha")));
        assert_eq!(jar.get("bar").await, Some(Cookie::new("bar", "beta")));
        assert_eq!(jar.get("invalid_cookie").await, None);
        assert_eq!(jar.get("another_bad").await, None);

        assert_eq!(jar.get_delta().await, Vec::<Cookie>::new());
    }

    #[tokio::test]
    async fn middleware_applies_cookies_to_response() {
        use axum::{Router, body::Body, routing::get};
        use tower::ServiceExt;

        async fn test_handler(mut jar: PrivateCookieJar) -> &'static str {
            jar.add(("session", "test_session_id")).await;
            jar.add(("user", "john_doe")).await;
            "ok"
        }

        let app = Router::new()
            .route("/", get(test_handler))
            .layer(axum::middleware::from_fn(auto_cookie_middleware))
            .with_state(Key::derive_from(&[0; 32]));

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let set_cookies: Vec<_> = response.headers().get_all(SET_COOKIE).iter().collect();
        assert_eq!(set_cookies.len(), 2, "Expected 2 Set-Cookie headers");
        let cookie_names: HashSet<String> = set_cookies
            .iter()
            .map(|header| {
                let cookie_str = header.to_str().unwrap();
                // Extract cookie name (before the '=' sign)
                cookie_str.split('=').next().unwrap().to_owned()
            })
            .collect();
        assert_eq!(
            cookie_names,
            HashSet::from(["session".to_owned(), "user".to_owned()])
        );
    }
}
