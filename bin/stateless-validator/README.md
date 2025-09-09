# Validator

## multi validator
run validators

First select a port for the server to listen on and make sure the port is not occupied. Here we use 8600:

terminal 1:
```sh
cd stateless-validator/

cargo run --release --bin megaeth-validator -- --datadir ~/.chain-ops/devnet/stateless_witness/stateless --api http://127.0.0.1:9545 --port 8600
```

```sh
curl -X POST http://localhost:8600/ -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "stateless_getValidation", "params": ["1185.0x155702b6cf76f101ea4b328bb33192e293a63e93932e9bf5ba8ad24fd144a919"], "id": 1}'
```

The second one does not need to start the server. If the port information is not passed, the server will not be started.
terminal 2:
```sh
cd mega-reth/bin/stateless/validator

cargo run --release --bin megaeth-validator -- --datadir ~/.chain-ops/devnet/stateless_witness/stateless --api http://127.0.0.1:9545
```

## test case
run test:
```sh
cd mega-reth

cargo test --package megaeth-validator --bin megaeth-validator --all-features -- tests --show-output
```
