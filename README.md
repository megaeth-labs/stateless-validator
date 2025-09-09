# Stateless Validator

A Rust implementation of a stateless blockchain validator that processes witness data for block validation without maintaining full blockchain state.

## Overview

The stateless validator consists of:

- **`validate`**: Core library providing stateless validation logic, witness data handling, and file I/O operations
- **`megaeth-validator`**: Main validator binary that processes blocks using witness data
- **`witness-decoder`**: Utility tool for decoding and inspecting `.w` witness files

## Architecture

### Core Components

- **StateData**: Wrapper structure providing BLAKE3 hash verification for serialized data
- **WitnessStatus**: Contains block validation state, pre-state root, parent hash, blob data, and witness information
- **File Management**: Handles witness file storage with backup directories and hash-based naming

### Witness File Format

Witness files (`.w`) use a layered binary format:
1. **Outer Layer**: `StateData` struct with BLAKE3 hash for integrity verification
2. **Inner Layer**: `WitnessStatus` struct containing actual witness and validation data
3. **Serialization**: Uses bincode with legacy configuration for cross-version compatibility

File naming convention: `{block_number}.{block_hash}.w`

## Usage

### Building

```bash
cargo build --release
```

### Running the Validator

```bash
cargo run --bin megaeth-validator -- [OPTIONS]
```

### Decoding Witness Files

```bash
# Pretty print witness file information
cargo run --bin witness-decoder -- --file path/to/witness.w

# Output as JSON
cargo run --bin witness-decoder -- --file path/to/witness.w --format json

# Show hex dump of first 100 bytes
cargo run --bin witness-decoder -- --file path/to/witness.w --hex-dump-bytes 100
```

## Development

### Prerequisites

- Rust nightly toolchain (specified in `rust-toolchain.toml`)
- Components: rustfmt, clippy, rust-src, miri, rust-analyzer

### Project Structure

```
stateless-validator/
├── bin/
│   ├── validator/          # Main validator binary
│   └── witness-decoder/    # Witness file decoder utility
├── validate/               # Core validation library
├── test_data/              # Test blocks and witness files
└── Cargo.toml             # Workspace configuration
```

### Testing

```bash
cargo test
```

### Code Quality

```bash
cargo +nightly fmt
cargo +stable clippy
```

## License

[Add your license information here]