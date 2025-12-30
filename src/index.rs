use askama::Template;
use axum::response::{Html, Redirect};

use crate::authenticated_user::AuthenticatedUser;

pub async fn index_handler(
    authenticated_user: Option<AuthenticatedUser>,
) -> Result<Html<String>, Redirect> {
    if let Some(user) = authenticated_user {
        Ok(Html(
            LoggedInTemplate {
                username: &user.username,
            }
            .render()
            .expect("Failed to render logged in template"),
        ))
    } else {
        Err(Redirect::to("/login"))
    }
}

#[derive(Template)]
#[template(path = "logged_in.html")]
struct LoggedInTemplate<'a> {
    username: &'a str,
}

#[cfg(test)]
mod test {
    use axum::{
        http::{
            HeaderValue, StatusCode,
            header::{CONTENT_TYPE, LOCATION},
        },
        response::IntoResponse,
    };

    use super::*;

    #[tokio::test]
    async fn logged_in_renders_template() {
        let raw_response = index_handler(Some(AuthenticatedUser {
            username: "test-user".into(),
        }))
        .await
        .expect("Did not receive a successful response");
        assert!(raw_response.0.contains("test-user"));

        let response = raw_response.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .expect("Content type not present")
                .to_str()
                .expect("Failed to convert to str")
                .starts_with("text/html"),
            "Content type was not text/html"
        );
    }

    #[tokio::test]
    async fn not_logged_in_redirects() {
        let response = index_handler(None)
            .await
            .expect_err("Unexpectedly receive a successful response")
            .into_response();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(LOCATION),
            HeaderValue::from_str("/login").ok().as_ref()
        );
    }
}
