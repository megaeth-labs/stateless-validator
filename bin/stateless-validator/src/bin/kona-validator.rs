#[tokio::main]
async fn main() -> eyre::Result<()> {
    stateless_validator::run_kona().await
}
