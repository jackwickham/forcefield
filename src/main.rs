use forcefield::start_server_with_default_config;

#[tokio::main]
async fn main() {
    start_server_with_default_config().await.unwrap();
}
