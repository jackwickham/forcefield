use axum::http::StatusCode;

use crate::authenticated_user::AuthenticatedUser;

pub async fn index_handler(authenticated_user: Option<AuthenticatedUser>) -> (StatusCode, String) {
    if let Some(user) = authenticated_user {
        (StatusCode::OK, user.username)
    } else {
        (StatusCode::UNAUTHORIZED, "You're not logged in".to_owned())
    }
}
