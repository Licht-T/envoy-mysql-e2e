# Envoy MySQL Proxy E2E Tests

End-to-end tests for Envoy's MySQL proxy filter with SSL termination and RSA-mediated `caching_sha2_password` authentication.

Tests run against real MySQL servers (5.7, 8.0, 8.4, 9.0, 9.1) using Docker, validating three `downstream_ssl` modes:

| Port | Mode | Behavior |
|------|------|----------|
| 3307 | `REQUIRE` | Envoy terminates TLS, rejects non-SSL clients, mediates RSA auth |
| 3308 | `DISABLE` | Plain TCP proxy with MySQL protocol sniffing, SSL passthrough |
| 3309 | `ALLOW` | Terminates TLS if client requests, accepts cleartext otherwise |

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) with Docker Compose
- [curl](https://curl.se/)

## Quick Start

### Option 1: Build from Envoy source

Clone the repos side by side:

```
parent/
├── envoy/              # https://github.com/envoyproxy/envoy
└── envoy-mysql-e2e/    # this repo
```

Then build using `build_envoy.sh`, which runs the build inside Envoy's devcontainer (works on macOS and Linux):

```bash
# Default: expects ../envoy as the Envoy source
./build_envoy.sh

# Or specify the path explicitly
ENVOY_SRCDIR=/path/to/envoy ./build_envoy.sh
```

This:
- Uses Envoy's official build image (same as CI)
- Persists the bazel cache in a Docker volume (`envoy-build`) — first build takes ~2 hours, incremental rebuilds ~1 minute
- Produces a Linux ELF binary at `./envoy-contrib`

Then run the tests:

```bash
# Run all MySQL versions
./run_tests.sh

# Run specific versions
./run_tests.sh 8.0
./run_tests.sh 8.0 9.1
```

### Option 2: Use the upstream image (no local changes)

```bash
# Uses envoyproxy/envoy-contrib-dev:latest from Docker Hub
ENVOY_DOCKER_IMAGE=envoyproxy/envoy-contrib-dev:latest ./run_tests.sh 8.0
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ENVOY_SRCDIR` | `../envoy` | Path to Envoy source tree (used by `build_envoy.sh`) |
| `ENVOY_BINARY` | `./envoy-contrib` | Path to a local Envoy binary |
| `ENVOY_DOCKER_IMAGE` | — | Use a pre-built Docker image directly (skips binary build) |
| `ENVOY_LOG_LEVEL` | `debug` | Envoy log level (`trace`, `debug`, `info`, `warning`, `error`) |
| `KEEP_RUNNING` | — | Set to `1` to keep containers running after tests for log inspection |
| `REBUILD` | — | Set to `1` to force rebuild of the Docker image |

## Inspecting Logs

```bash
# Run with trace logging and keep containers alive
ENVOY_LOG_LEVEL=trace KEEP_RUNNING=1 ./run_tests.sh 8.0

# View Envoy logs
docker compose logs -f envoy

# Filter for mysql_proxy trace
docker compose logs envoy | grep mysql_proxy

# Clean up when done
docker compose down -v
```

## Test Cases

### SSL Terminated (REQUIRE, port 3307)

| Test | Description |
|------|-------------|
| `basic_connectivity` | SELECT through Envoy with TLS |
| `wrong_password_rejected` | ERR propagated correctly |
| `dml_operations` | CREATE/INSERT/SELECT through proxy |
| `multiple_connections` | 5 sequential connections (state cleanup) |
| `envoy_stats` | Envoy admin stats report sessions |
| `ssl_multi_query_session` | 3 queries in single TLS session |
| `ssl_transaction` | BEGIN/INSERT/ROLLBACK verified |
| `ssl_prepared_statement` | PREPARE/EXECUTE/DEALLOCATE |
| `ssl_large_result` | 20-row result set |
| `ssl_empty_password` | Empty password user |
| `ssl_require_rejects_non_ssl` | Non-SSL client rejected (8.0+) |
| `caching_sha2_warm_cache` | Fast auth path — cache hit, no RSA (8.0+) |
| `caching_sha2_cold_cache` | Full auth — cache miss, RSA mediation (8.0+) |
| `ssl_native_password` | `mysql_native_password` user (8.0 only) |
| `ssl_long_password_cold_cache` | 54-char password, tests XOR cycling (8.0+) |
| `ssl_rsa_then_query` | RSA cold cache then DML in same session (8.0+) |

### No-SSL (DISABLE, port 3308)

| Test | Description |
|------|-------------|
| `no_ssl_connectivity` | Plaintext connection through Envoy |
| `no_ssl_wrong_password` | ERR propagated |
| `no_ssl_dml` | DML operations |
| `no_ssl_multi_conn` | Multiple connections |
| `no_ssl_stats` | Envoy stats |
| `no_ssl_passthrough_with_ssl` | Client SSL goes end-to-end to MySQL server |

### SSL ALLOW (port 3310)

| Test | Description |
|------|-------------|
| `allow_ssl_connectivity` | SSL client through ALLOW port |
| `allow_no_ssl_connectivity` | Non-SSL client through ALLOW port |
| `allow_ssl_wrong_password` | ERR propagated |
| `allow_ssl_dml` | DML operations via SSL |
| `allow_stats` | Envoy stats |
| `allow_ssl_cold_cache` | RSA mediation via ALLOW port (8.0+) |

## MySQL Version Support

| Version | SSL Termination | RSA Mediation | Notes |
|---------|----------------|---------------|-------|
| 5.7 | Yes | N/A | Uses `mysql_native_password` (no RSA needed). Runs via `--platform linux/amd64` on ARM. |
| 8.0 | Yes | Yes | Default `caching_sha2_password`. Full test coverage. |
| 8.4 | Yes | Yes | `mysql_native_password` removed. |
| 9.0 | Yes | Yes | Same as 8.4. |
| 9.1 | Yes | Yes | Same as 8.4. |

## Documentation

- **[docs/implementation.md](docs/implementation.md)** — Detailed implementation design covering the MySQL authentication protocol, RSA mediation state machine, sequence number management, secure password handling, and the full protocol walkthrough with byte-level detail.

## Project Structure

```
.
├── README.md
├── run_tests.sh           # Test runner
├── build_envoy.sh         # Build Envoy binary via devcontainer
├── docker-compose.yaml    # Envoy + MySQL services
├── envoy.yaml             # Multi-listener Envoy config (REQUIRE/DISABLE/ALLOW)
├── Dockerfile             # Minimal image for the Envoy binary
├── docs/
│   └── implementation.md  # Implementation design document
├── certs/
│   └── generate.sh        # Self-signed CA + server cert generator
└── .gitignore
```

## Envoy Configuration

The `envoy.yaml` configures three listeners demonstrating the `downstream_ssl` proto enum:

```yaml
# REQUIRE — terminate SSL, reject non-SSL
- name: envoy.filters.network.mysql_proxy
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.network.mysql_proxy.v3.MySQLProxy
    stat_prefix: mysql
    downstream_ssl: REQUIRE

# DISABLE (default) — passthrough, no SSL termination
- name: envoy.filters.network.mysql_proxy
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.network.mysql_proxy.v3.MySQLProxy
    stat_prefix: mysql

# ALLOW — terminate if client requests, accept cleartext
- name: envoy.filters.network.mysql_proxy
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.network.mysql_proxy.v3.MySQLProxy
    stat_prefix: mysql
    downstream_ssl: ALLOW
```

Listeners using `REQUIRE` or `ALLOW` must have a `starttls` transport socket with TLS certificates configured.
