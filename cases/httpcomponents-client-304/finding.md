# Security finding

> A code-security scan flagged the vulnerability below. No remediation is included; produce the fix yourself.

**Type:** CWE-304 — CWE-304
**Project:** `apache/httpcomponents-client`
**Primary location:** `httpclient5/src/main/java/org/apache/hc/client5/http/impl/DefaultAuthenticationStrategy.java`
**Other files possibly involved:** `httpclient5/src/main/java/org/apache/hc/client5/http/impl/auth/AuthenticationHandler.java`, `httpclient5/src/main/java/org/apache/hc/client5/http/impl/auth/ScramScheme.java`

## Details

Missing critical step in authentication in Apache HttpClient 5.6 allows an attacker to cause the client to accept SCRAM-SHA-256 authentication without proper mutual authentication verification.
