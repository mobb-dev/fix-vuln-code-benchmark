# Security finding

> A code-security scan flagged the vulnerability below. No remediation is included; produce the fix yourself.

**Type:** CWE-295 — CWE-295
**Project:** `eclipse-vertx/vert.x`
**Primary location:** `vertx-core/src/main/java/io/vertx/core/impl/utils/LruCache.java`
**Other files possibly involved:** `vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java`, `vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java`

## Details

Potential unbounded server-side SNI `SslContext` cache growth in Vert.x TLS handling, with = resource-exhaustion / DoS impact.

The implementation differs slightly by branch, but the same sink appears to be present in released versions `4.3.4` through `5.0.11`:
- `4.3.x`: `SSLHelper`
- `4.4.x` / `4.5.x`: `SslChannelProvider`
- `5.0.x` and current `master`: `SslContextProvider`

When server-side SNI is enabled and wildcard or otherwise broad hostname mappings are used, an unauthenticated client can send many distinct matching SNI names and cause the server to retain increasing numbers of `SslContext` entries over time, leading to increasing memory consumption and possible DoS conditions.

## Steps to reproduce

1. Configure a Vert.x server with `setSsl(true)` and `setSni(true)`.
2. Use a keystore or mapping where many distinct SNI names match a wildcard or similarly broad rule.
3. Send repeated connections with distinct matching SNI values.
4. Observe that the SNI cache size grows with the number of unique matching names.
