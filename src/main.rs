mod authenticated_user;
mod check_auth;
mod config;
mod login;

use rocket::{catchers, fairing::AdHoc, fs::FileServer, response::Redirect};
use rocket_dyn_templates::{Template, context};

use authenticated_user::AuthenticatedUser;
use config::Config;
use login::LoginError;

#[macro_use]
extern crate rocket;

#[get("/")]
fn index_logged_in(user: AuthenticatedUser) -> Template {
    Template::render(
        "logged_in",
        context! {
            username: user.username,
        },
    )
}

#[get("/", rank = 10)]
fn index_not_logged_in() -> Redirect {
    Redirect::to(uri!(login::show_login(None::<&str>, None::<LoginError>)))
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(AdHoc::config::<Config>())
        .attach(Template::fairing())
        .mount("/static", FileServer::from("static"))
        .mount(
            "/",
            routes![
                index_logged_in,
                index_not_logged_in,
                check_auth::check_auth,
                login::login_redirect_to_logged_in,
                login::show_login,
                login::login,
                login::hash_password
            ],
        )
        .register("/check-auth", catchers![check_auth::unauthorized])
}
