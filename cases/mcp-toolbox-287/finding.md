# Security finding

> A code-security scan flagged the vulnerability below. No remediation is included; produce the fix yourself.

**Type:** Improper Authentication — CWE-287
**Project:** `googleapis/mcp-toolbox`
**Primary location:** `internal/auth/auth.go`
**Other files possibly involved:** `internal/auth/generic/generic.go`, `internal/auth/google/google.go`, `internal/server/config.go`, `internal/server/mcp.go`, `internal/server/mcp/util/auth.go`

## Details

An authentication bypass vulnerability exists in the generic opaque token validation path (validateOpaqueToken) of googleapis/mcp-toolbox.

When verifying an unparsed opaque token via an OAuth 2.0 introspection endpoint (RFC 7662), the toolbox decodes the response into an introspectResp struct where the Active field is declared as a pointer to a boolean (*bool). The code only explicitly rejects a token if the response contains a populated active field set to false (if introspectResp.Active != nil && !*introspectResp.Active). If an introspection endpoint responds with a payload that completely omits the mandatory active key, the internal variable remains nil, causing the conditional check to short-circuit. As a result, Toolbox accepts authorization tokens missing the "active" field, granting access to protected tools and underlying data sources.
