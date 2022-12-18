use rocket::Rocket;
use rocket_cgi::CGIDir;

#[macro_use]
extern crate rocket;

#[launch]
async fn rocket() -> _ {
    Rocket::build().mount("/a", CGIDir::new("examples/"))
}
