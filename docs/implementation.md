# Implementation: MySQL SSL Termination with RSA-Mediated Authentication

## Table of Contents

1. [Overview](#overview)
2. [MySQL Authentication Background](#mysql-authentication-background)
3. [Configuration (Proto API)](#configuration-proto-api)
4. [SSL Termination Mechanism](#ssl-termination-mechanism)
5. [Sequence Number Management](#sequence-number-management)
6. [RSA Mediation State Machine](#rsa-mediation-state-machine)
7. [Secure Password Handling](#secure-password-handling)
8. [Detailed Protocol Walkthrough](#detailed-protocol-walkthrough)
9. [Files Modified](#files-modified)
10. [Auth Switch and AuthMoreData Details](#auth-switch-and-authmoredata-details)
11. [RSA Encryption Details](#rsa-encryption-details)
12. [Error Handling](#error-handling)
13. [Testing](#testing)

---

## Overview

This implementation adds SSL termination to Envoy's MySQL proxy filter, enabling:

- Clients to connect to Envoy over TLS
- Envoy to connect to MySQL servers over plaintext
- Transparent mediation of `caching_sha2_password` full authentication (RSA public key exchange)
- Secure handling of cleartext passwords via libsodium guarded memory
- Correct sequence number rewriting across the proxy

The approach mirrors the Postgres filter's SSL termination ([PR #14634](https://github.com/envoyproxy/envoy/pull/14634)) using the `starttls` transport socket, with additional logic to handle MySQL's `caching_sha2_password` authentication plugin.

---

## MySQL Authentication Background

### Authentication Plugins

MySQL supports multiple authentication plugins. The relevant ones for SSL termination:

| Plugin | MySQL Version | Behavior |
|--------|--------------|----------|
| `mysql_native_password` | 5.x default | Challenge-response hash. No SSL/RSA needed. Works transparently with SSL termination. |
| `caching_sha2_password` | 8.0+ default | Two modes: **fast auth** (server cache hit) and **full auth** (cache miss, requires SSL or RSA). |
| `sha256_password` | 5.6+ optional | Always requires SSL or RSA. Different protocol entry point. Deprecated in 8.0, removed in 8.4. Not supported. |

### `caching_sha2_password` Protocol

After the client sends its login response (with the hashed password), the server responds with one of:

| Response | Code | Meaning |
|----------|------|---------|
| `OK` | `0x00` | Authentication succeeded |
| `ERR` | `0xff` | Authentication failed |
| `AuthMoreData(0x03)` | `0x01, 0x03` | **Fast auth success** -- server's cache had the password hash. Server will send OK next. |
| `AuthMoreData(0x04)` | `0x01, 0x04` | **Full auth required** -- cache miss. Client must send password via SSL or RSA. |

#### Fast auth path (cache hit)

```
Client → Server: ClientLogin (with password hash)
Server → Client: AuthMoreData [0x01, 0x03]    ← cache hit
Server → Client: OK
```

No special handling needed. The filter passes everything through with seq rewriting.

#### Full auth path (cache miss, over SSL)

When the client has an SSL connection to the server:

```
Client → Server: ClientLogin (with password hash)
Server → Client: AuthMoreData [0x01, 0x04]    ← cache miss, full auth required
Client → Server: cleartext password + \0       ← safe because SSL protects it
Server → Client: OK or ERR
```

#### Full auth path (cache miss, no SSL -- RSA)

When there is no SSL connection (or SSL is terminated at the proxy):

```
Client → Server: ClientLogin (with password hash)
Server → Client: AuthMoreData [0x01, 0x04]    ← cache miss
Client → Server: 0x02                         ← request public key
Server → Client: AuthMoreData [0x01, PEM key] ← server's RSA public key
Client → Server: RSA_encrypt(password XOR scramble)
Server → Client: OK or ERR
```

### The Mismatch Problem

When Envoy terminates SSL:

- **Client** has an SSL connection (to Envoy) and sends the **cleartext password** (trusting SSL).
- **Server** sees a plaintext connection (from Envoy) and expects **RSA-encrypted password**.

The filter must bridge this gap by intercepting the cleartext password, requesting the server's public key, RSA-encrypting the password, and forwarding it.

---

## Configuration (Proto API)

The `downstream_ssl` field in the `MySQLProxy` proto controls SSL behavior, matching the Postgres filter's `SSLMode` interface:

```protobuf
message MySQLProxy {
  enum SSLMode {
    DISABLE = 0;   // Passthrough (default)
    REQUIRE = 1;   // Terminate SSL, reject non-SSL clients
    ALLOW = 2;     // Terminate SSL if client requests, accept cleartext otherwise
  }

  string stat_prefix = 1;
  string access_log = 2;
  SSLMode downstream_ssl = 3;
  // TODO: upstream_ssl for encrypting Envoy→MySQL connection
}
```

| `downstream_ssl` | SSL Termination | RSA Mediation | Non-SSL Clients |
|---|---|---|---|
| `DISABLE` | No | No | Accepted |
| `REQUIRE` | Yes | Yes | Rejected (connection closed) |
| `ALLOW` | If client requests | If SSL active | Accepted |

The internal `bool terminate_ssl_` flag has been replaced with the `SSLMode` enum stored as `downstream_ssl_`. The `terminateSsl()` helper returns `true` when `downstream_ssl_ != DISABLE`.

---

## SSL Termination Mechanism

### How it works

1. The MySQL server sends its **Greeting** packet, which includes the `CLIENT_SSL` capability flag.
2. The filter captures the server's `auth_plugin_data` (20-byte scramble, truncated from the 21-byte greeting format) and `auth_plugin_name` from the greeting.
3. The client sees the `CLIENT_SSL` flag and sends an **SSL Connection Request** packet.
4. The filter intercepts this packet, calls `startSecureTransport()` on the connection to upgrade the downstream to TLS, and **does not forward** the SSL Request to the server.
5. After TLS is established, the client sends its **ClientLogin** packet over TLS.
6. The filter decrypts the ClientLogin (via the TLS layer), rewrites the sequence number, strips the `CLIENT_SSL` capability flag, and forwards it to the server over plaintext.
7. In `REQUIRE` mode, if the client sends a login without SSL (`getSeqOffset() == 0`), the connection is closed.

### Configuration example

```yaml
listeners:
  - name: mysql_listener
    filter_chains:
    - filters:
      - name: envoy.filters.network.mysql_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.mysql_proxy.v3.MySQLProxy
          stat_prefix: mysql
          downstream_ssl: REQUIRE
      - name: envoy.filters.network.tcp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
          stat_prefix: mysql_tcp
          cluster: mysql_cluster
      transport_socket:
        name: starttls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.starttls.v3.StartTlsConfig
          cleartext_socket_config:
          tls_socket_config:
            common_tls_context:
              tls_certificates:
                certificate_chain:
                  filename: /path/to/cert.pem
                private_key:
                  filename: /path/to/key.pem
```

---

## Sequence Number Management

MySQL uses a single monotonically-increasing sequence number shared between client and server for each authentication exchange. When Envoy consumes or injects packets, the sequence numbers on each side diverge.

### Offset tracking

The offset is tracked as `int8_t seq_offset_` in `MySQLSession` (generalized from the previous `bool is_in_ssl_auth_`):

```
client_seq = server_seq + seq_offset_
```

| Event | seq_offset_ | Reason |
|-------|------------|--------|
| Initial | `0` | No divergence |
| After SSL Request consumed | `+1` | Client sent seq=1 (SSL req) that server never saw |
| After RSA mediation complete | `-1` | Net effect: +2 injected to server, +1 consumed from server, -1 consumed from client |
| After OK/ERR (resetSeq) | `0` | Auth complete, both sides reset |

### Formula

```cpp
getExpectedSeq(is_upstream):
    return seq_ - (is_upstream ? 0 : seq_offset_);

convertToSeqOnReciever(seq, is_upstream):
    return seq - (is_upstream ? 1 : -1) * seq_offset_;
```

### Sequence number trace through RSA mediation

```
Step                        Canonical seq_  seq_offset_  Client sees  Server sees
─────────────────────────────────────────────────────────────────────────────────
Greeting                    1               0            seq=0        seq=0
SSL Request (consumed)      2               1            seq=1        (not sent)
ClientLogin                 3               1            seq=2        seq=1
AuthMoreData(0x04)          4               1            seq=3        seq=2
Client password             5               1            seq=4        (intercepted)
  → inject request-key     (bypass)         1                         seq=3
  ← server PEM key         (bypass)         1                         seq=4
  → inject encrypted pw    (bypass)         1→(-1)                    seq=5
  adjustSeqOffset(-2)       5               -1
OK from server              (reset)          0            seq=5        seq=6
```

---

## RSA Mediation State Machine

The filter uses a 4-state machine (`RsaAuthState`) to track the RSA mediation flow:

```
                  AuthMoreData(0x04)
    Inactive ──────────────────────→ WaitingClientPassword
       ↑                                     │
       │                          client pw received
       │                                     ↓
       │  OK/ERR received          WaitingServerKey
       │                                     │
       └──── WaitingServerResult ←───────────┘
                                   PEM key received,
                                   encrypted pw sent
```

### State transitions

| Current State | Event | Action | Next State |
|--------------|-------|--------|------------|
| `Inactive` | `onClientLoginResponse` with `AuthMoreData[0]=0x04` and `caching_sha2_password` | Set state | `WaitingClientPassword` |
| `WaitingClientPassword` | `onAuthSwitchMoreClientData` + `onData` returns | Drain data, inject `0x02` request-public-key to server | `WaitingServerKey` |
| `WaitingServerKey` | `onWrite` with complete packet | Parse PEM key, call `sendEncryptedPassword()`, `adjustSeqOffset(-2)` | `WaitingServerResult` |
| `WaitingServerResult` | `onMoreClientLoginResponse` with OK or ERR | Reset state | `Inactive` |

---

## Secure Password Handling

Cleartext passwords are handled using libsodium's guarded memory to prevent leakage:

1. **`BufferHelper::readSecureBytes()`**: Reads bytes from the Envoy buffer into a `SecureBytes` object (backed by `sodium_malloc` with guard pages), then zeroes the source buffer slices via `sodium_memzero`.
2. **`SecureBytes`** class (in `mysql_utils.h`): RAII wrapper around `sodium_malloc`/`sodium_free`. Memory is automatically zeroed on destruction. Non-copyable, move-only.
3. **Callback signature**: `onAuthSwitchMoreClientData(std::unique_ptr<SecureBytes>)` — password ownership is transferred directly, never touching `std::string`.

Password lifecycle:
```
Wire buffer → readSecureBytes() → SecureBytes (guarded memory)
                  ↓ zeroes source buffer slices
              callback passes ownership via std::move
              filter uses it for XOR + RSA encrypt (in SecureBytes)
              reset() → sodium_free (zeroes before freeing)
```

---

## Detailed Protocol Walkthrough

### Step-by-step with byte-level detail

**1. Server Greeting (server → client)**

```
Server sends: [len][seq=0][protocol=10][version][thread_id][scramble1(8)][filler]
              [cap_low(2)][charset][status][cap_high(2)][auth_data_len]
              [reserved(10)][scramble2(12)][filler][auth_plugin_name\0]
```

Filter action: `onServerGreeting()` captures `server_scramble_` (truncated to 20 bytes — the greeting may include a 21st null filler byte) and `auth_plugin_name_` ("caching_sha2_password").

**2. SSL Request (client → server) -- CONSUMED**

```
Client sends: [len=32][seq=1][cap_flags(4)][max_packet(4)][charset][reserved(23)]
              (cap_flags has CLIENT_SSL bit set, no username/password)
```

Filter action: `onSSLRequest()` calls `startSecureTransport()`, sets `seq_offset_ = 1`, sets state to `ChallengeReq`. Returns `Stopped` to prevent forwarding.

**3. TLS Handshake (client ↔ Envoy)**

Handled by the `starttls` transport socket. Transparent to the filter.

**4. ClientLogin (client → server) -- REWRITTEN**

```
Client sends: [len][seq=2][cap_flags(4)][max_packet(4)][charset][reserved(23)]
              [username\0][auth_data_len][auth_data][database\0][auth_plugin\0]
```

Filter action: `doRewrite()` rewrites seq from 2→1 and strips `CLIENT_SSL` from cap_flags. In `REQUIRE` mode, if `getSeqOffset() == 0` (no SSL was initiated), the connection is closed.

**5. AuthMoreData(0x04) (server → client) -- FORWARDED, TRIGGERS RSA**

```
Server sends: [len=2][seq=2][0x01][0x04]
```

Filter action: `onClientLoginResponse()` detects `MYSQL_RESP_MORE` with data `[0x04]` and plugin `caching_sha2_password`. Sets `rsa_auth_state_ = WaitingClientPassword`. Packet is forwarded to client with seq rewritten 2→3.

**6. Cleartext Password (client → server) -- INTERCEPTED**

```
Client sends: [len][seq=4][password\0]
```

Filter action: Decoder reads payload via `BufferHelper::readSecureBytes()` into guarded memory, calls `onAuthSwitchMoreClientData(std::unique_ptr<SecureBytes>)`. In `onData()`, detects `WaitingClientPassword` state, drains data, injects request-public-key:

```
Injected to server: [len=1][seq=3][0x02]
```

**7. PEM Public Key (server → client) -- INTERCEPTED**

```
Server sends: [len][seq=4][0x01][-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n]
```

Filter action: In `onWrite()`, detects `WaitingServerKey` state, parses PEM key from packet, calls `sendEncryptedPassword()`:

```
Injected to server: [len=256][seq=5][RSA_encrypted_data(256 bytes)]
```

Calls `adjustSeqOffset(-2)` to update offset from +1 to -1.

**8. OK or ERR (server → client) -- FORWARDED**

```
Server sends: [len][seq=6][0x00][affected_rows][last_insert_id][status][warnings]
```

Filter action: Normal decode path. `getExpectedSeq(false) = seq_(5) - (-1) = 6`, matches. `convertToSeqOnReciever(6, false) = 6 - 1 = 5`. Client receives seq=5.

---

## Files Modified

| File | Changes |
|------|---------|
| `mysql_proxy.proto` | Added `SSLMode` enum (`DISABLE`, `REQUIRE`, `ALLOW`) and `downstream_ssl` field. TODO for `upstream_ssl`. |
| `mysql_session.h` | `bool is_in_ssl_auth_` → `int8_t seq_offset_`. Added `getSeqOffset()`, `setSeqOffset()`, `adjustSeqOffset()`. |
| `mysql_codec.h` | Added constants: `MYSQL_CACHINGSHA2_FAST_AUTH_SUCCESS` (0x03), `MYSQL_CACHINGSHA2_FULL_AUTH_REQUIRED` (0x04), `MYSQL_REQUEST_PUBLIC_KEY` (0x02). |
| `mysql_utils.h` | Added `SecureBytes` class (libsodium guarded memory). Added `BufferHelper::readSecureBytes()`. |
| `mysql_utils.cc` | Implemented `readSecureBytes()`: reads into `SecureBytes`, zeroes source buffer slices. |
| `mysql_decoder.h` | Changed `onAuthSwitchMoreClientData` to take `std::unique_ptr<SecureBytes>`. |
| `mysql_decoder_impl.cc` | `AuthSwitchMore` upstream case: reads via `readSecureBytes()` and passes ownership. Changed `setIsInSslAuth(true)` → `adjustSeqOffset(1)`. |
| `mysql_filter.h` | `bool terminate_ssl_` → `SSLMode downstream_ssl_` with `terminateSsl()` helper. Added `RsaAuthState` enum, `write_callbacks_`, `cleartext_password_` (as `std::unique_ptr<SecureBytes>`), `server_scramble_`, `auth_plugin_name_`. |
| `mysql_filter.cc` | Main implementation. `onServerGreeting()` captures scramble (truncated to 20 bytes). `onClientLogin()` enforces REQUIRE mode. `onClientLoginResponse()` detects 0x04 full auth. `onData()` intercepts password. `onWrite()` intercepts PEM key. `sendEncryptedPassword()` does XOR + RSA encrypt. |
| `mysql_config.cc` | Reads `downstream_ssl` from proto instead of hardcoding `terminate_ssl = true`. |
| `source/BUILD` | Added `//bazel/foreign_cc:libsodium` to `util_lib`, `//source/common/crypto:utility_lib` and proto dep to `filter_lib`. |
| `bazel/` | Added libsodium as external dependency (`repository_locations.bzl`, `repositories.bzl`, `foreign_cc/BUILD`, `deps.yaml`). |

---

## Auth Switch and AuthMoreData Details

### AuthMoreData packet format

```
Byte 0:    0x01 (MYSQL_RESP_MORE marker)
Byte 1..n: plugin-specific data
```

For `caching_sha2_password`:
- `[0x01, 0x03]` = fast auth success (2-byte packet)
- `[0x01, 0x04]` = full auth required (2-byte packet)
- `[0x01, PEM_KEY_BYTES...]` = server public key (variable length)

### AuthSwitchRequest vs AuthMoreData

| Response | Code | When | Filter handling |
|----------|------|------|-----------------|
| `AuthSwitchRequest` | `0xfe` | Server wants client to use a different auth plugin | Forwarded. Client sends `AuthSwitchResponse`. Filter enters `AuthSwitchMore` state. |
| `AuthMoreData` | `0x01` | Server needs additional data exchange with current plugin | Forwarded. Filter checks the data byte for RSA mediation trigger. |

### Decoder callback for upstream auth data

The decoder reads client auth data via `BufferHelper::readSecureBytes()` directly into guarded memory:

```cpp
case MySQLSession::State::AuthSwitchMore: {
    if (is_upstream) {
        std::unique_ptr<SecureBytes> secure_data;
        BufferHelper::readSecureBytes(message, len, secure_data);
        callbacks_.onAuthSwitchMoreClientData(std::move(secure_data));
        break;
    }
    // ... downstream (server) response handling
}
```

---

## RSA Encryption Details

### XOR with scramble

MySQL's `caching_sha2_password` requires the password to be XOR'd with the server's 20-byte scramble before RSA encryption:

```
input[i] = password_with_null[i] XOR scramble[i % 20]
```

The password includes a trailing `\0` byte. The scramble is truncated to 20 bytes from the greeting (the 21st byte is a protocol filler null).

### RSA-OAEP encryption

MySQL requires RSA encryption with **OAEP padding using SHA-1**:

```cpp
EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha1());
```

For RSA-2048 (MySQL's default key size), this produces a 256-byte ciphertext.

### Key import

The server's PEM public key is imported via Envoy's crypto utility:

```cpp
auto pkey = Envoy::Common::Crypto::UtilitySingleton::get().importPublicKeyPEM(pem_key);
```

---

## Error Handling

| Scenario | Behavior |
|----------|----------|
| `startSecureTransport()` fails | Connection closed with `NoFlush`. |
| `REQUIRE` mode, client doesn't send SSL | Connection closed after ClientLogin. |
| PEM key import fails | Connection closed. Error logged. |
| RSA encryption fails | Connection closed. Error logged. `cleartext_password_` securely destroyed. |
| Unexpected marker in PEM response | Connection closed. Error logged. |
| Server returns ERR after RSA | ERR forwarded to client with corrected seq. `login_failures` counter incremented. |
| Partial PEM key packet | `onWrite` returns `StopIteration`, waits for more data. |
| Decode error during RSA mediation | `sniffing_` set to false, filter falls back to TCP passthrough. |

---

## Testing

### Unit tests (mysql_filter_test.cc)

48 tests covering all three SSL modes:

| Category | Tests |
|----------|-------|
| **REQUIRE** | Native password login, login+query, RSA full flow, RSA+query, fast auth passthrough, RSA ERR, startTLS failure, reject non-SSL client, accept SSL client |
| **DISABLE** | SSL passthrough, caching_sha2 full auth no mediation, caching_sha2 passthrough |
| **ALLOW** | Accept non-SSL client, SSL+RSA mediation, non-SSL no mediation |
| **Existing** | All 29 pre-existing tests continue to pass |

### Integration tests (mysql_ssl_integration_test.cc)

20 tests (10 scenarios x IPv4/IPv6) across three test classes:

| Class | Test | What it validates |
|-------|------|-------------------|
| **REQUIRE** | `CachingSha2FastAuth` | TLS handshake → fast auth → OK |
| | `CachingSha2FullAuthRsaMediation` | TLS → full auth → RSA. Verifies injected packets. |
| | `CachingSha2FullAuthRsaErr` | TLS → full auth → RSA → ERR |
| | `SslTerminateLoginThenQuery` | TLS → native password login → query after auth |
| | `CachingSha2FullAuthRsaThenQuery` | TLS → RSA mediation → query after auth |
| **DISABLE** | `DisableBasicLogin` | Plain TCP login, no SSL |
| | `DisableSslPassthrough` | SSL request forwarded to upstream unmodified |
| **ALLOW** | `AllowSslClientLogin` | SSL client terminates TLS, login OK |
| | `AllowNonSslClientLogin` | Non-SSL client accepted, login OK |
| | `AllowSslFullAuthRsaMediation` | SSL client → full auth → RSA mediation |

### Docker E2E tests (this repo)

130 tests across MySQL 5.7, 8.0, 8.4, 9.0, 9.1 with three listener modes:

| Mode (port) | Tests per version |
|---|---|
| **REQUIRE** (3307) | basic_connectivity, wrong_password, dml, multi_conn, stats, multi_query_session, transaction, prepared_statement, large_result, empty_password, require_rejects_non_ssl, warm_cache, cold_cache, native_password, long_password, rsa_then_query |
| **DISABLE** (3308) | connectivity, wrong_password, dml, multi_conn, stats, passthrough_with_ssl |
| **ALLOW** (3309) | ssl_connectivity, no_ssl_connectivity, ssl_wrong_password, ssl_dml, stats, ssl_cold_cache |
