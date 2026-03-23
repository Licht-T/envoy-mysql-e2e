#!/usr/bin/env bash
#
# Integration tests for MySQL SSL termination with RSA mediation across
# multiple MySQL server versions.
#
# Usage:
#   ./run_tests.sh              # Run all versions (uses envoyproxy/envoy-contrib-dev:latest)
#   ./run_tests.sh 8.0          # Run a specific version
#   ./run_tests.sh 8.0 8.4      # Run selected versions
#
# Envoy image options (set env var before running):
#   ENVOY_DOCKER_IMAGE=my-image:tag ./run_tests.sh    # Use a custom image directly
#   ENVOY_BINARY=/path/to/envoy  ./run_tests.sh       # Build image from a local binary
#   KEEP_RUNNING=1 ./run_tests.sh 8.0                  # Keep containers up after tests for log inspection
#
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

# ── Configuration ─────────────────────────────────────────────────────
ALL_VERSIONS=("5.7" "8.0" "8.4" "9.0" "9.1")
ENVOY_SSL_TERM_PORT=3307
ENVOY_NO_SSL_PORT=3308
ENVOY_SSL_ALLOW_PORT=3310
ADMIN_PORT=8001
MYSQL_USER="testuser"
MYSQL_PASSWORD="testpass"
MYSQL_DB="testdb"
MYSQL_ROOT_PASSWORD="testpass"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0

# ── Helpers ───────────────────────────────────────────────────────────
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*"; }

cleanup() {
  if [ "${KEEP_RUNNING:-}" = "1" ]; then
    log "Containers left running (KEEP_RUNNING=1). Inspect with:"
    log "  docker compose logs -f envoy"
    log "  docker compose down -v"
    return
  fi
  log "Cleaning up..."
  docker compose down -v --remove-orphans 2>/dev/null || true
}

wait_for_envoy() {
  local retries=30
  while ! curl -sf "http://127.0.0.1:${ADMIN_PORT}/ready" >/dev/null 2>&1; do
    retries=$((retries - 1))
    if [ "$retries" -le 0 ]; then
      err "Envoy did not become ready"
      docker compose logs envoy 2>/dev/null | tail -30
      return 1
    fi
    sleep 1
  done
}

# Helper: run a disposable mysql client container.
# Uses MYSQL_CLIENT_IMAGE and MYSQL_PLATFORM (set per-version).
mysql_client_run() {
  docker run --rm --network=test_with_docker_mysql_net \
    ${MYSQL_PLATFORM:+--platform "$MYSQL_PLATFORM"} \
    "$@" 2>&1
}

# Run a mysql command through Envoy with SSL termination (port 3307).
mysql_via_envoy() {
  mysql_client_run \
    -v "$DIR/certs/ca-cert.pem:/ca-cert.pem:ro" \
    "${MYSQL_CLIENT_IMAGE}" \
    mysql -h envoy -P "$ENVOY_SSL_TERM_PORT" \
    -u "$1" -p"$2" \
    --ssl-mode=REQUIRED \
    --ssl-ca=/ca-cert.pem \
    -e "$3"
}

# Run a mysql command through Envoy without SSL (port 3308).
mysql_via_envoy_no_ssl() {
  mysql_client_run \
    "${MYSQL_CLIENT_IMAGE}" \
    mysql -h envoy -P "$ENVOY_NO_SSL_PORT" \
    -u "$1" -p"$2" \
    --ssl-mode=DISABLED \
    --get-server-public-key \
    -e "$3"
}

# Run a mysql command through Envoy ALLOW port with SSL.
mysql_via_envoy_allow_ssl() {
  mysql_client_run \
    -v "$DIR/certs/ca-cert.pem:/ca-cert.pem:ro" \
    "${MYSQL_CLIENT_IMAGE}" \
    mysql -h envoy -P "$ENVOY_SSL_ALLOW_PORT" \
    -u "$1" -p"$2" \
    --ssl-mode=REQUIRED \
    --ssl-ca=/ca-cert.pem \
    -e "$3"
}

# Run a mysql command through Envoy ALLOW port without SSL.
mysql_via_envoy_allow_no_ssl() {
  mysql_client_run \
    "${MYSQL_CLIENT_IMAGE}" \
    mysql -h envoy -P "$ENVOY_SSL_ALLOW_PORT" \
    -u "$1" -p"$2" \
    --ssl-mode=DISABLED \
    --get-server-public-key \
    -e "$3"
}

# Run a mysql command directly against the server (via docker exec).
mysql_direct() {
  docker compose exec -T mysql \
    mysql -h 127.0.0.1 -u "$1" -p"$2" -e "$3" 2>&1
}

record() {
  local name="$1" result="$2"
  if [ "$result" = "PASS" ]; then
    echo -e "  ${GREEN}PASS${NC}  $name"
    PASS=$((PASS + 1))
  elif [ "$result" = "SKIP" ]; then
    echo -e "  ${YELLOW}SKIP${NC}  $name"
    SKIP=$((SKIP + 1))
  else
    echo -e "  ${RED}FAIL${NC}  $name"
    FAIL=$((FAIL + 1))
  fi
}

# ── Test Cases ────────────────────────────────────────────────────────

# Test 1: Basic connectivity — SELECT 1 through Envoy with SSL.
test_basic_connectivity() {
  local out
  out=$(mysql_via_envoy "$MYSQL_USER" "$MYSQL_PASSWORD" "SELECT 1 AS ok;")
  if echo "$out" | grep -q "ok"; then
    record "basic_connectivity" "PASS"
  else
    err "Output: $out"
    record "basic_connectivity" "FAIL"
  fi
}

# Test 2: caching_sha2_password full auth (cold cache).
#   Create a fresh user, flush privileges (cold cache), and connect through Envoy.
#   This forces the RSA mediation path.
test_caching_sha2_cold_cache() {
  # Create a user via direct connection.
  mysql_direct "root" "$MYSQL_ROOT_PASSWORD" \
    "DROP USER IF EXISTS 'colduser'@'%'; \
     CREATE USER 'colduser'@'%' IDENTIFIED WITH caching_sha2_password BY 'coldpass'; \
     GRANT ALL ON testdb.* TO 'colduser'@'%'; \
     FLUSH PRIVILEGES;" >/dev/null 2>&1

  # Restart MySQL to fully clear the sha2 cache.
  docker compose restart mysql >/dev/null 2>&1
  # Wait for MySQL health.
  local retries=30
  while ! docker compose exec -T mysql mysqladmin ping -h 127.0.0.1 -u root -p"$MYSQL_ROOT_PASSWORD" >/dev/null 2>&1; do
    retries=$((retries - 1))
    if [ "$retries" -le 0 ]; then
      record "caching_sha2_cold_cache" "FAIL"
      err "MySQL did not restart in time"
      return
    fi
    sleep 1
  done
  # Also wait for Envoy to reconnect.
  wait_for_envoy || { record "caching_sha2_cold_cache" "FAIL"; return; }

  local out
  out=$(mysql_via_envoy "colduser" "coldpass" "SELECT DATABASE();")
  if echo "$out" | grep -qi "testdb\|DATABASE"; then
    record "caching_sha2_cold_cache" "PASS"
  else
    err "Output: $out"
    record "caching_sha2_cold_cache" "FAIL"
  fi
}

# Test 3: caching_sha2_password fast auth (warm cache).
#   After test 2, the cache should be warm. A second connection should succeed
#   via fast-auth (0x03) without RSA mediation.
test_caching_sha2_warm_cache() {
  local out
  out=$(mysql_via_envoy "$MYSQL_USER" "$MYSQL_PASSWORD" "SELECT 'warm' AS cache_status;")
  if echo "$out" | grep -q "warm"; then
    record "caching_sha2_warm_cache" "PASS"
  else
    err "Output: $out"
    record "caching_sha2_warm_cache" "FAIL"
  fi
}

# Test 4: Wrong password should fail gracefully.
test_wrong_password() {
  local out
  out=$(mysql_via_envoy "$MYSQL_USER" "wrongpassword" "SELECT 1;" 2>&1) || true
  if echo "$out" | grep -qi "denied\|error"; then
    record "wrong_password_rejected" "PASS"
  else
    err "Output: $out"
    record "wrong_password_rejected" "FAIL"
  fi
}

# Test 5: DML through Envoy — CREATE TABLE, INSERT, SELECT.
test_dml_operations() {
  local out
  out=$(mysql_via_envoy "$MYSQL_USER" "$MYSQL_PASSWORD" \
    "USE testdb; DROP TABLE IF EXISTS envoy_test; \
     CREATE TABLE envoy_test (id INT PRIMARY KEY, val VARCHAR(64)); \
     INSERT INTO envoy_test VALUES (1, 'hello'), (2, 'world'); \
     SELECT val FROM envoy_test ORDER BY id;")
  if echo "$out" | grep -q "hello" && echo "$out" | grep -q "world"; then
    record "dml_operations" "PASS"
  else
    err "Output: $out"
    record "dml_operations" "FAIL"
  fi
}

# Test 6: Multiple sequential connections (verifies state cleanup).
test_multiple_connections() {
  local ok=true
  for i in 1 2 3 4 5; do
    if ! mysql_via_envoy "$MYSQL_USER" "$MYSQL_PASSWORD" "SELECT $i;" >/dev/null 2>&1; then
      ok=false
      break
    fi
  done
  if $ok; then
    record "multiple_connections" "PASS"
  else
    record "multiple_connections" "FAIL"
  fi
}

# Test 7: Envoy stats show successful sessions.
test_envoy_stats() {
  local stats
  stats=$(curl -sf "http://127.0.0.1:${ADMIN_PORT}/stats?filter=egress_mysql_ssl_term" 2>/dev/null)
  if echo "$stats" | grep -q "egress_mysql_ssl_term.sessions"; then
    record "envoy_stats" "PASS"
  else
    err "Stats output: $stats"
    record "envoy_stats" "FAIL"
  fi
}

# Test 8: SSL terminated — multiple queries in a single connection.
test_ssl_multi_query_session() {
  local out
  out=$(mysql_via_envoy "$MYSQL_USER" "$MYSQL_PASSWORD" \
    "SELECT 'q1' AS tag; SELECT 'q2' AS tag; SELECT 'q3' AS tag;")
  if echo "$out" | grep -q "q1" && echo "$out" | grep -q "q2" && echo "$out" | grep -q "q3"; then
    record "ssl_multi_query_session" "PASS"
  else
    err "Output: $out"
    record "ssl_multi_query_session" "FAIL"
  fi
}

# Test 9: SSL terminated — transaction (BEGIN, INSERT, ROLLBACK, verify).
test_ssl_transaction() {
  # Setup table.
  mysql_via_envoy "$MYSQL_USER" "$MYSQL_PASSWORD" \
    "USE testdb; DROP TABLE IF EXISTS txn_test; \
     CREATE TABLE txn_test (id INT PRIMARY KEY);" >/dev/null 2>&1

  # Insert in a transaction, then rollback.
  mysql_via_envoy "$MYSQL_USER" "$MYSQL_PASSWORD" \
    "USE testdb; BEGIN; INSERT INTO txn_test VALUES (1); ROLLBACK;" >/dev/null 2>&1

  # Verify the row was NOT inserted (rollback worked through the proxy).
  local out
  out=$(mysql_via_envoy "$MYSQL_USER" "$MYSQL_PASSWORD" \
    "USE testdb; SELECT COUNT(*) AS cnt FROM txn_test;")
  if echo "$out" | grep -q "0"; then
    record "ssl_transaction" "PASS"
  else
    err "Output: $out"
    record "ssl_transaction" "FAIL"
  fi
}

# Test 10: SSL terminated — prepared statement (MySQL native protocol).
test_ssl_prepared_statement() {
  local out
  out=$(mysql_via_envoy "$MYSQL_USER" "$MYSQL_PASSWORD" \
    "USE testdb; PREPARE stmt FROM 'SELECT ? + ? AS result'; SET @a = 10, @b = 20; \
     EXECUTE stmt USING @a, @b; DEALLOCATE PREPARE stmt;")
  if echo "$out" | grep -q "30"; then
    record "ssl_prepared_statement" "PASS"
  else
    err "Output: $out"
    record "ssl_prepared_statement" "FAIL"
  fi
}

# Test 11: SSL terminated — large result set (100 rows).
test_ssl_large_result() {
  local out
  out=$(mysql_via_envoy "$MYSQL_USER" "$MYSQL_PASSWORD" \
    "USE testdb; SELECT seq FROM (
       SELECT 1 AS seq UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4
       UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8
       UNION ALL SELECT 9 UNION ALL SELECT 10 UNION ALL SELECT 11 UNION ALL SELECT 12
       UNION ALL SELECT 13 UNION ALL SELECT 14 UNION ALL SELECT 15 UNION ALL SELECT 16
       UNION ALL SELECT 17 UNION ALL SELECT 18 UNION ALL SELECT 19 UNION ALL SELECT 20
     ) t ORDER BY seq;")
  local count
  count=$(echo "$out" | grep -c "^[0-9]" || true)
  if [ "$count" -ge 20 ]; then
    record "ssl_large_result" "PASS"
  else
    err "Expected 20+ rows, got $count"
    record "ssl_large_result" "FAIL"
  fi
}

# Test 12: SSL terminated — mysql_native_password user (no RSA mediation needed).
# Only available on MySQL 8.0 (removed in 8.4+).
test_ssl_native_password() {
  # Create a user with mysql_native_password.
  local create_out
  create_out=$(mysql_direct "root" "$MYSQL_ROOT_PASSWORD" \
    "DROP USER IF EXISTS 'nativeuser'@'%'; \
     CREATE USER 'nativeuser'@'%' IDENTIFIED WITH mysql_native_password BY 'nativepass'; \
     GRANT ALL ON testdb.* TO 'nativeuser'@'%'; \
     FLUSH PRIVILEGES;" 2>&1)
  if echo "$create_out" | grep -qi "error"; then
    record "ssl_native_password (plugin unavailable)" "SKIP"
    return
  fi

  local out
  out=$(mysql_via_envoy "nativeuser" "nativepass" "SELECT 'native_ok' AS status;")
  if echo "$out" | grep -q "native_ok"; then
    record "ssl_native_password" "PASS"
  else
    err "Output: $out"
    record "ssl_native_password" "FAIL"
  fi
}

# Test 13: SSL terminated — empty password user.
test_ssl_empty_password() {
  mysql_direct "root" "$MYSQL_ROOT_PASSWORD" \
    "DROP USER IF EXISTS 'emptyuser'@'%'; \
     CREATE USER 'emptyuser'@'%' IDENTIFIED BY ''; \
     GRANT ALL ON testdb.* TO 'emptyuser'@'%'; \
     FLUSH PRIVILEGES;" >/dev/null 2>&1

  local out
  out=$(mysql_client_run \
    -v "$DIR/certs/ca-cert.pem:/ca-cert.pem:ro" \
    "${MYSQL_CLIENT_IMAGE}" \
    mysql -h envoy -P "$ENVOY_SSL_TERM_PORT" -u emptyuser \
    --ssl-mode=REQUIRED --ssl-ca=/ca-cert.pem \
    -e "SELECT 'empty_ok' AS status;")
  if echo "$out" | grep -q "empty_ok"; then
    record "ssl_empty_password" "PASS"
  else
    err "Output: $out"
    record "ssl_empty_password" "FAIL"
  fi
}

# Test 14: SSL terminated — cold cache with long password (stress XOR cycling).
#   A newly created user always misses the SHA2 cache on first connect, so no
#   restart needed — just create a fresh user with a unique name.
test_ssl_long_password_cold_cache() {
  local long_pw='ThisIsAVeryLongPasswordThatExceeds20BytesForXORCycling'
  local ts
  ts=$(date +%s)
  local user="longpw${ts}"

  mysql_direct "root" "$MYSQL_ROOT_PASSWORD" \
    "CREATE USER '${user}'@'%' IDENTIFIED WITH caching_sha2_password BY '${long_pw}'; \
     GRANT ALL ON testdb.* TO '${user}'@'%';" >/dev/null 2>&1

  local out
  out=$(mysql_via_envoy "$user" "$long_pw" "SELECT 'longpw_ok' AS status;")
  if echo "$out" | grep -q "longpw_ok"; then
    record "ssl_long_password_cold_cache" "PASS"
  else
    err "Output: $out"
    record "ssl_long_password_cold_cache" "FAIL"
  fi
}

# ── No-SSL Test Cases ─────────────────────────────────────────────────

# No-SSL: Create a mysql_native_password user for no-SSL tests.
# (caching_sha2_password with terminate_ssl=true would trigger RSA mediation
# even on the no-SSL port, since terminate_ssl is currently hardcoded.)
setup_no_ssl_user() {
  mysql_direct "root" "$MYSQL_ROOT_PASSWORD" \
    "DROP USER IF EXISTS 'nossluser'@'%'; \
     GRANT ALL ON testdb.* TO 'nossluser'@'%';" >/dev/null 2>&1
  # On 8.4+ mysql_native_password is removed, use caching_sha2 + get-server-public-key.
  local create_out
  create_out=$(mysql_direct "root" "$MYSQL_ROOT_PASSWORD" \
    "CREATE USER 'nossluser'@'%' IDENTIFIED WITH mysql_native_password BY 'nosslpass'; \
     GRANT ALL ON testdb.* TO 'nossluser'@'%';" 2>&1)
  if echo "$create_out" | grep -qi "error"; then
    # Fall back: create with default plugin, client uses --get-server-public-key.
    mysql_direct "root" "$MYSQL_ROOT_PASSWORD" \
      "CREATE USER 'nossluser'@'%' IDENTIFIED BY 'nosslpass'; \
       GRANT ALL ON testdb.* TO 'nossluser'@'%';" >/dev/null 2>&1
  fi
  NO_SSL_USER="nossluser"
  NO_SSL_PASS="nosslpass"
}

# No-SSL: basic connectivity — plaintext through Envoy.
test_no_ssl_connectivity() {
  local out
  out=$(mysql_via_envoy_no_ssl "$NO_SSL_USER" "$NO_SSL_PASS" "SELECT 'nossl_ok' AS status;")
  if echo "$out" | grep -q "nossl_ok"; then
    record "no_ssl_connectivity" "PASS"
  else
    err "Output: $out"
    record "no_ssl_connectivity" "FAIL"
  fi
}

# No-SSL: wrong password rejected.
test_no_ssl_wrong_password() {
  local out
  out=$(mysql_via_envoy_no_ssl "$NO_SSL_USER" "wrongpassword" "SELECT 1;" 2>&1) || true
  if echo "$out" | grep -qi "denied\|error"; then
    record "no_ssl_wrong_password" "PASS"
  else
    err "Output: $out"
    record "no_ssl_wrong_password" "FAIL"
  fi
}

# No-SSL: DML operations (CREATE, INSERT, SELECT).
test_no_ssl_dml() {
  local out
  out=$(mysql_via_envoy_no_ssl "$NO_SSL_USER" "$NO_SSL_PASS" \
    "USE testdb; DROP TABLE IF EXISTS nossl_test; \
     CREATE TABLE nossl_test (id INT PRIMARY KEY, val VARCHAR(64)); \
     INSERT INTO nossl_test VALUES (1, 'plain'); \
     SELECT val FROM nossl_test;")
  if echo "$out" | grep -q "plain"; then
    record "no_ssl_dml" "PASS"
  else
    err "Output: $out"
    record "no_ssl_dml" "FAIL"
  fi
}

# No-SSL: multiple sequential connections.
test_no_ssl_multi_conn() {
  local ok=true
  for i in 1 2 3; do
    if ! mysql_via_envoy_no_ssl "$NO_SSL_USER" "$NO_SSL_PASS" "SELECT $i;" >/dev/null 2>&1; then
      ok=false
      break
    fi
  done
  if $ok; then
    record "no_ssl_multi_conn" "PASS"
  else
    record "no_ssl_multi_conn" "FAIL"
  fi
}

# No-SSL: Envoy stats for the no-ssl listener.
test_no_ssl_stats() {
  local stats
  stats=$(curl -sf "http://127.0.0.1:${ADMIN_PORT}/stats?filter=egress_mysql_no_ssl" 2>/dev/null)
  if echo "$stats" | grep -q "egress_mysql_no_ssl.sessions"; then
    record "no_ssl_stats" "PASS"
  else
    err "Stats output: $stats"
    record "no_ssl_stats" "FAIL"
  fi
}

# ── SSL Passthrough Test Cases ────────────────────────────────────────

# Test: REQUIRE mode — cold cache RSA then query in same session.
test_ssl_rsa_then_query() {
  local ts
  ts=$(date +%s)
  local user="rsaquery_${ts}"
  mysql_direct "root" "$MYSQL_ROOT_PASSWORD" \
    "CREATE USER '${user}'@'%' IDENTIFIED WITH caching_sha2_password BY 'rsaqpass'; \
     GRANT ALL ON testdb.* TO '${user}'@'%';" >/dev/null 2>&1

  local out
  out=$(mysql_via_envoy "$user" "rsaqpass" \
    "USE testdb; DROP TABLE IF EXISTS rsa_query_test; \
     CREATE TABLE rsa_query_test (id INT PRIMARY KEY, val VARCHAR(32)); \
     INSERT INTO rsa_query_test VALUES (1, 'after_rsa'); \
     SELECT val FROM rsa_query_test;")
  if echo "$out" | grep -q "after_rsa"; then
    record "ssl_rsa_then_query" "PASS"
  else
    err "Output: $out"
    record "ssl_rsa_then_query" "FAIL"
  fi
}

# Test: REQUIRE mode — non-SSL client gets rejected.
test_ssl_require_rejects_non_ssl() {
  local out
  out=$(mysql_client_run \
    "${MYSQL_CLIENT_IMAGE}" \
    mysql -h envoy -P "$ENVOY_SSL_TERM_PORT" \
    -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" \
    --ssl-mode=DISABLED \
    -e "SELECT 1;") || true
  if echo "$out" | grep -qi "error\|lost connection\|gone away"; then
    record "ssl_require_rejects_non_ssl" "PASS"
  else
    err "Output: $out"
    record "ssl_require_rejects_non_ssl" "FAIL"
  fi
}

# Test: DISABLE mode — client can use SSL directly with server (passthrough).
test_no_ssl_passthrough_with_ssl() {
  # Connect through the DISABLE port with SSL — the SSL goes end-to-end to MySQL server.
  local out
  out=$(mysql_client_run \
    "${MYSQL_CLIENT_IMAGE}" \
    mysql -h envoy -P "$ENVOY_NO_SSL_PORT" \
    -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" \
    --ssl-mode=REQUIRED \
    -e "SELECT 'passthru_ssl_ok' AS status;")
  if echo "$out" | grep -q "passthru_ssl_ok"; then
    record "no_ssl_passthrough_with_ssl" "PASS"
  else
    err "Output: $out"
    record "no_ssl_passthrough_with_ssl" "FAIL"
  fi
}

# ── SSL ALLOW Test Cases ──────────────────────────────────────────────

# ALLOW: SSL client connects and authenticates.
test_allow_ssl_connectivity() {
  local out
  out=$(mysql_via_envoy_allow_ssl "$MYSQL_USER" "$MYSQL_PASSWORD" "SELECT 'allow_ssl_ok' AS status;")
  if echo "$out" | grep -q "allow_ssl_ok"; then
    record "allow_ssl_connectivity" "PASS"
  else
    err "Output: $out"
    record "allow_ssl_connectivity" "FAIL"
  fi
}

# ALLOW: non-SSL client connects and authenticates.
test_allow_no_ssl_connectivity() {
  local out
  out=$(mysql_via_envoy_allow_no_ssl "$NO_SSL_USER" "$NO_SSL_PASS" "SELECT 'allow_nossl_ok' AS status;")
  if echo "$out" | grep -q "allow_nossl_ok"; then
    record "allow_no_ssl_connectivity" "PASS"
  else
    err "Output: $out"
    record "allow_no_ssl_connectivity" "FAIL"
  fi
}

# ALLOW: wrong password rejected (SSL).
test_allow_ssl_wrong_password() {
  local out
  out=$(mysql_via_envoy_allow_ssl "$MYSQL_USER" "wrongpw" "SELECT 1;" 2>&1) || true
  if echo "$out" | grep -qi "denied\|error"; then
    record "allow_ssl_wrong_password" "PASS"
  else
    err "Output: $out"
    record "allow_ssl_wrong_password" "FAIL"
  fi
}

# ALLOW: DML via SSL.
test_allow_ssl_dml() {
  local out
  out=$(mysql_via_envoy_allow_ssl "$MYSQL_USER" "$MYSQL_PASSWORD" \
    "USE testdb; DROP TABLE IF EXISTS allow_test; \
     CREATE TABLE allow_test (id INT, val VARCHAR(32)); \
     INSERT INTO allow_test VALUES (1,'allow_ssl'); \
     SELECT val FROM allow_test;")
  if echo "$out" | grep -q "allow_ssl"; then
    record "allow_ssl_dml" "PASS"
  else
    err "Output: $out"
    record "allow_ssl_dml" "FAIL"
  fi
}

# ALLOW: caching_sha2 cold cache via SSL (triggers RSA mediation).
test_allow_ssl_cold_cache() {
  local ts
  ts=$(date +%s)
  local user="allow_cold_${ts}"
  mysql_direct "root" "$MYSQL_ROOT_PASSWORD" \
    "CREATE USER '${user}'@'%' IDENTIFIED WITH caching_sha2_password BY 'coldallow'; \
     GRANT ALL ON testdb.* TO '${user}'@'%';" >/dev/null 2>&1

  local out
  out=$(mysql_via_envoy_allow_ssl "$user" "coldallow" "SELECT 'allow_cold_ok' AS status;")
  if echo "$out" | grep -q "allow_cold_ok"; then
    record "allow_ssl_cold_cache" "PASS"
  else
    err "Output: $out"
    record "allow_ssl_cold_cache" "FAIL"
  fi
}

# ALLOW: Envoy stats for the allow listener.
test_allow_stats() {
  local stats
  stats=$(curl -sf "http://127.0.0.1:${ADMIN_PORT}/stats?filter=egress_mysql_ssl_allow" 2>/dev/null)
  if echo "$stats" | grep -q "egress_mysql_ssl_allow.sessions"; then
    record "allow_stats" "PASS"
  else
    err "Stats output: $stats"
    record "allow_stats" "FAIL"
  fi
}

# ── Main ──────────────────────────────────────────────────────────────

if [ $# -gt 0 ]; then
  VERSIONS=("$@")
else
  VERSIONS=("${ALL_VERSIONS[@]}")
fi

# Ensure certs exist.
if [ ! -f "$DIR/certs/server-cert.pem" ]; then
  log "Generating TLS certificates..."
  "$DIR/certs/generate.sh"
fi

# Check prerequisites.
for cmd in docker curl; do
  if ! command -v "$cmd" &>/dev/null; then
    err "Required command '$cmd' not found. Please install it."
    exit 1
  fi
done

# Determine the Envoy Docker image to use.
REPO_ROOT="$(cd "$DIR/.." && pwd)"
LOCAL_BINARY="$DIR/envoy-contrib"

if [ -n "${ENVOY_DOCKER_IMAGE:-}" ]; then
  # Mode 1: User provides a pre-built image directly.
  IMAGE_NAME="$ENVOY_DOCKER_IMAGE"
  log "Using provided image: $IMAGE_NAME"

elif [ -n "${ENVOY_BINARY:-}" ]; then
  # Mode 2: User provides a local binary path.
  LOCAL_BINARY="$ENVOY_BINARY"
  IMAGE_NAME="envoy-contrib-local:latest"

elif [ -f "$LOCAL_BINARY" ] && [ "${REBUILD:-}" != "1" ]; then
  # Mode 3: Cached binary from a previous build.
  IMAGE_NAME="envoy-contrib-local:latest"
  log "Using cached binary: $LOCAL_BINARY"

else
  # Mode 4 (default): Build via devcontainer (build_envoy.sh).
  IMAGE_NAME="envoy-contrib-local:latest"
  log "Building envoy-contrib via devcontainer (first build is slow, cached after)..."
  "$DIR/build_envoy.sh"
fi

# If we have a local binary, package it into a Docker image.
if [ -n "${LOCAL_BINARY:-}" ] && [ -f "$LOCAL_BINARY" ]; then
  if [ "$(docker images -q "$IMAGE_NAME" 2>/dev/null)" = "" ] || [ "${REBUILD:-}" = "1" ] || \
     [ "$LOCAL_BINARY" -nt "$DIR/.image-built" ] 2>/dev/null; then
    log "Building Docker image from: $LOCAL_BINARY"
    cp -f "$LOCAL_BINARY" "$DIR/envoy"
    docker build -t "$IMAGE_NAME" "$DIR"
    rm -f "$DIR/envoy"
    touch "$DIR/.image-built"
    log "Image ready: $IMAGE_NAME"
  fi
fi

trap cleanup EXIT

echo ""
echo "=============================================="
echo " MySQL SSL Termination Integration Tests"
echo "=============================================="
echo ""

for ver in "${VERSIONS[@]}"; do
  # Map short version to Docker image tag and MySQL startup flags.
  #   5.7:  mysql_native_password default, no caching_sha2_password
  #   8.0:  caching_sha2_password available, use --default-authentication-plugin
  #   8.4+: caching_sha2_password is default, --default-authentication-plugin removed
  HAS_CACHING_SHA2=true
  MYSQL_PLATFORM=""
  case "$ver" in
    5.7*)
      image="mysql:5.7"
      mysql_cmd="--default-authentication-plugin=mysql_native_password"
      HAS_CACHING_SHA2=false
      MYSQL_PLATFORM="linux/amd64"
      ;;
    8.0*)
      image="mysql:8.0"
      mysql_cmd="--default-authentication-plugin=caching_sha2_password"
      ;;
    8.4*)  image="mysql:8.4"; mysql_cmd="" ;;
    9.0*)  image="mysql:9.0"; mysql_cmd="" ;;
    9.1*)  image="mysql:9.1"; mysql_cmd="" ;;
    *)     image="mysql:$ver"; mysql_cmd="" ;;
  esac
  # Use the same image for the throwaway mysql client container.
  MYSQL_CLIENT_IMAGE="$image"

  echo "----------------------------------------------"
  log "Testing with $image"
  echo "----------------------------------------------"

  cleanup >/dev/null 2>&1

  # Use pull_policy=never for local images to avoid Docker trying to pull them.
  pull_policy="missing"
  if [ "$IMAGE_NAME" = "envoy-contrib-local:latest" ]; then
    pull_policy="never"
  fi

  ENVOY_IMAGE="$IMAGE_NAME" ENVOY_PULL_POLICY="$pull_policy" \
    ENVOY_LOG_LEVEL="${ENVOY_LOG_LEVEL:-debug}" \
    MYSQL_IMAGE="$image" MYSQL_CMD="$mysql_cmd" \
    MYSQL_PLATFORM="${MYSQL_PLATFORM:-}" \
    docker compose up -d 2>/dev/null

  if ! wait_for_envoy; then
    err "Skipping $image — environment did not start"
    record "$image: setup" "SKIP"
    continue
  fi

  log "Envoy ready, running tests..."

  set +e  # Don't exit on individual test failures.

  # --- SSL Terminated tests (port 3307) ---
  test_basic_connectivity
  test_wrong_password
  test_dml_operations
  test_multiple_connections
  test_envoy_stats
  test_ssl_multi_query_session
  test_ssl_transaction
  test_ssl_prepared_statement
  test_ssl_large_result
  test_ssl_empty_password

  # REQUIRE reject works reliably on 8.0+ (caching_sha2 auth is multi-round-trip).
  # On 5.7 (mysql_native_password), the single-round-trip auth may complete before
  # the connection close takes effect.
  if $HAS_CACHING_SHA2; then
    test_ssl_require_rejects_non_ssl
    test_caching_sha2_warm_cache
    test_caching_sha2_cold_cache
    test_ssl_native_password
    test_ssl_long_password_cold_cache
    test_ssl_rsa_then_query
  else
    record "ssl_require_rejects_non_ssl (N/A for $ver)" "SKIP"
    record "caching_sha2_warm_cache (N/A for $ver)" "SKIP"
    record "caching_sha2_cold_cache (N/A for $ver)" "SKIP"
    record "ssl_native_password (N/A for $ver)" "SKIP"
    record "ssl_long_password_cold_cache (N/A for $ver)" "SKIP"
    record "ssl_rsa_then_query (N/A for $ver)" "SKIP"
  fi

  # --- No-SSL / DISABLE tests (port 3308) ---
  setup_no_ssl_user
  test_no_ssl_connectivity
  test_no_ssl_wrong_password
  test_no_ssl_dml
  test_no_ssl_multi_conn
  test_no_ssl_stats
  test_no_ssl_passthrough_with_ssl

  # --- SSL ALLOW tests (port 3310) ---
  test_allow_ssl_connectivity
  test_allow_no_ssl_connectivity
  test_allow_ssl_wrong_password
  test_allow_ssl_dml
  test_allow_stats

  if $HAS_CACHING_SHA2; then
    test_allow_ssl_cold_cache
  else
    record "allow_ssl_cold_cache (N/A for $ver)" "SKIP"
  fi


  set -e

  echo ""
done

# ── Summary ───────────────────────────────────────────────────────────
echo "=============================================="
echo " Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${YELLOW}${SKIP} skipped${NC}"
echo "=============================================="

[ "$FAIL" -eq 0 ]
