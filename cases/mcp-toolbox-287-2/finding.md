# Security finding

> A code-security scan flagged the vulnerability below. No remediation is included; produce the fix yourself.

**Type:** Improper Authentication — CWE-287
**Project:** `googleapis/mcp-toolbox`
**Primary location:** `internal/auth/generic/generic.go`

## Details

An authentication bypass vulnerability exists in the generic opaque token validation path (validateOpaqueToken) of googleapis/mcp-toolbox.

When the toolbox validates an opaque token via an OAuth 2.0 introspection endpoint (RFC 7662), it decodes the response into an introspectResp struct. However, the subsequent claim-checking logic (validateClaims) evaluates the issuer condition as if a.issuer != "" && iss != "". If the external OAuth provider's introspection response omits the optional iss (issuer) field completely, the variable iss defaults to an empty string. This causes the conditional block to evaluate to false and be skipped silently. Consequently, the application accepts tokens issued by unauthorized or unintended third-party identity providers.
