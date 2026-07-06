# Security finding

> A code-security scan flagged the vulnerability below. No remediation is included; produce the fix yourself.

**Type:** Improper Authorization — CWE-285
**Project:** `forgekeep/nebula-mesh`
**Primary location:** `internal/api/audit.go`
**Other files possibly involved:** `internal/api/authz.go`, `internal/api/firewall.go`, `internal/api/hosts.go`, `internal/api/mobile_bundle.go`, `internal/api/networks.go`

## Details

`internal/api/audit.go:12` — `handleGetAuditLog` does no admin check. The route is bearer-auth gated only; any operator API key returns the full audit log via `store.ListAuditEntries` (up to limit=1000). This includes cross-tenant actor names, host/CA/operator IDs, action timestamps, and masked-IP entries from rate-limit refusals — enough surface for a tenant to enumerate the server's activity, infer staffing patterns, or identify high-value targets.

## Affected
All released versions up to v0.3.1.

## Reproducer
```
curl -H "Authorization: Bearer <any-operator-key>" \
  https://server/api/v1/audit-log?limit=1000
```
