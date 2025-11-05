# Logging

Configure logging via environment variables. Output goes to terminal by default; optional daily-rotated files when a directory is set.

## Environment variables

- STATELESS_VALIDATOR_LOG_STDOUT_FILTER: debug|info|warn|error (default: info)
- STATELESS_VALIDATOR_LOG_FILE_FILTER: debug|info|warn|error (default: debug)
- STATELESS_VALIDATOR_LOG_FILE_DIRECTORY: directory for log files; enables file logging when set. Files rotate daily as stateless-validator.log.YYYY-MM-DD
- STATELESS_VALIDATOR_LOG_STDOUT_FORMAT: terminal|json (default: terminal)
- STATELESS_VALIDATOR_LOG_FILE_FORMAT: terminal|json (default: terminal)

## Examples

Default (info to terminal):
```bash
./stateless-validator \
  --data-dir /data \
  --rpc-endpoint http://localhost:8545 \
  --witness-endpoint http://localhost:8545
```

Info to terminal + debug to file:
```bash
STATELESS_VALIDATOR_LOG_STDOUT_FILTER=info \
STATELESS_VALIDATOR_LOG_FILE_FILTER=debug \
STATELESS_VALIDATOR_LOG_FILE_DIRECTORY=/var/log/stateless-validator \
./stateless-validator \
  --data-dir /data \
  --rpc-endpoint http://localhost:8545 \
  --witness-endpoint http://localhost:8545
```

JSON for production monitoring:
```bash
STATELESS_VALIDATOR_LOG_STDOUT_FILTER=info \
STATELESS_VALIDATOR_LOG_STDOUT_FORMAT=json \
STATELESS_VALIDATOR_LOG_FILE_FILTER=debug \
STATELESS_VALIDATOR_LOG_FILE_FORMAT=json \
STATELESS_VALIDATOR_LOG_FILE_DIRECTORY=/var/log/stateless-validator \
./stateless-validator \
  --data-dir /data \
  --rpc-endpoint http://localhost:8545 \
  --witness-endpoint http://localhost:8545
```

## Log levels

- DEBUG: detailed diagnostics (worker states, queues, fetching, pruning)
- INFO: key operations (validations, sync, startup/shutdown, config)
- WARN: non-critical issues (transient network, pruning failures, reorgs)
- ERROR: serious issues (validation, database, RPC, task failures)

## Rotation

Daily file rotation (stateless-validator.log.YYYY-MM-DD). Old files are not deleted; manage retention externally (e.g., logrotate).

## Recommended presets

Development/testing:
```bash
STATELESS_VALIDATOR_LOG_STDOUT_FILTER=debug
```

Production (terminal + file):
```bash
STATELESS_VALIDATOR_LOG_STDOUT_FILTER=info
STATELESS_VALIDATOR_LOG_FILE_FILTER=debug
STATELESS_VALIDATOR_LOG_FILE_DIRECTORY=/var/log/stateless-validator
```

Production with aggregation (ELK, Splunk):
```bash
STATELESS_VALIDATOR_LOG_STDOUT_FILTER=info
STATELESS_VALIDATOR_LOG_STDOUT_FORMAT=json
STATELESS_VALIDATOR_LOG_FILE_FILTER=debug
STATELESS_VALIDATOR_LOG_FILE_FORMAT=json
STATELESS_VALIDATOR_LOG_FILE_DIRECTORY=/var/log/stateless-validator
```