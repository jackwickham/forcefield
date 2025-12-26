use rocket::{
    Request,
    http::Header,
    response::{Redirect, status::NoContent},
};

use crate::{authenticated_user::AuthenticatedUser, config::Config, login::LoginError};

#[rocket::get("/check-auth")]
pub fn check_auth(user: AuthenticatedUser) -> WithAuthenticatedHeaders<'static, NoContent> {
    WithAuthenticatedHeaders::create(NoContent, user.id)
}

#[derive(rocket::Responder)]
pub struct WithAuthenticatedHeaders<'a, I> {
    inner: I,
    user: Header<'a>,
}

impl<'a, I> WithAuthenticatedHeaders<'a, I> {
    pub fn create(inner: I, user_id: String) -> WithAuthenticatedHeaders<'a, I> {
        WithAuthenticatedHeaders {
            inner,
            user: Header::new("X-Forcefield-UserId", user_id.clone()),
        }
    }
}

#[rocket::catch(401)]
pub async fn unauthorized(req: &Request<'_>) -> Redirect {
    let root = req
        .rocket()
        .state::<Config>()
        .expect("Config not loaded")
        .public_root
        .clone();
    let return_uri = req.headers().get_one("X-Forwarded-Uri");
    let uri = rocket::uri![
        root,
        crate::login::show_login(return_uri, None::<crate::login::LoginError>)
    ];
    Redirect::to(uri)
}
