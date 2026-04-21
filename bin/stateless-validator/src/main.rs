#[tokio::main]
async fn main() -> eyre::Result<()> {
    stateless_validator::app::run().await
}
