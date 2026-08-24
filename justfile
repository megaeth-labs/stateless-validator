# Build the kona-validator binary (opt-in `kona` feature / Kona execution backend).
build-kona-validator:
    cargo build --release --features kona --bin kona-validator
