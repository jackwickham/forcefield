mod authenticated_user;
mod check_auth;
mod config;
mod login;

use rocket::{catchers, fairing::AdHoc};

use config::Config;

#[macro_use]
extern crate rocket;

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(AdHoc::config::<Config>())
        .mount(
            "/",
            routes![
                check_auth::check_auth,
                login::show_login,
                login::login,
                login::hash_password
            ],
        )
        .register("/check-auth", catchers![check_auth::unauthorized])
}
