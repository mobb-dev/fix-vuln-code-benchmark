# Security finding

> A code-security scan flagged the vulnerability below. No remediation is included; produce the fix yourself.

**Type:** Path Traversal — CWE-22
**Project:** `Basekick-Labs/arc`
**Primary location:** `cmd/arc/main.go`
**Other files possibly involved:** `internal/api/delete.go`, `internal/api/import.go`, `internal/database/duckdb.go`, `internal/database/duckdb_arrow.go`, `internal/database/sandbox.go`

## Details

### Summary

Arc's user-SQL validator (`internal/api/query.go:ValidateSQLRequest`) blocked only `read_parquet(` and `arc_partition_agg(` via regex denylist. The broader DuckDB I/O function family — `read_csv_auto`, `read_csv`, `read_json`, `read_json_auto`, `read_text`, `read_blob`, `glob`, `parquet_metadata`, `parquet_schema`, `read_xlsx`, etc. — was not blocked. RBAC table-reference extraction inspected only `FROM`/`JOIN` clauses, so scalar table functions in the `SELECT` list slipped past both layers.

### Impact

Any authenticated user, including a token with `permissions: []`, can read arbitrary local files via:

```
POST /api/v1/query
Authorization: Bearer <token>
{"sql": "SELECT * FROM read_csv_auto('/etc/passwd', header=false, columns={'l':'VARCHAR'}) LIMIT 5"}
```

Confirmed reachable targets:

- `auth.db` — bcrypt hashes for every API token, plus legacy SHA-256 rows.
- `arc.toml` — S3 secrets, TLS keys.
- `/proc/self/environ` — environment-variable secrets.
- Cross-tenant Parquet files — bypasses RBAC because the tenant scope is enforced at the table layer, not on raw file paths.
- SSRF when `httpfs` is loaded (any S3-backed deployment) — `read_csv_auto('http://169.254.169.254/latest/meta-data/...')` reaches instance metadata IPs.
