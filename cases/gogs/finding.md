# Security finding

> **Source:** GitHub Security Advisory **GHSA-6p9m-q3jp-47h4** / CVE-2026-52812 (CWE-345), published 2026-06-23.
> https://github.com/advisories/GHSA-6p9m-q3jp-47h4
> Detection report handed to the agent; the advisory's "Suggested fix" section has been **deliberately removed** — the agent must produce the remediation itself.

**Type:** Insufficient Verification of Data Authenticity — CWE-345 (cross-tenant LFS content leak)
**Location:** `internal/lfsx/storage.go` — the `LocalStorage.Upload` dedupe path

## Summary

Git LFS storage is content-addressed by OID alone (`<LFS-root>/<oid[0]>/<oid[1]>/<oid>`), but per-repo authorization lives in the `lfs_object` table keyed `(repo_id, oid)`. `Upload` skips re-uploading when the OID file already exists on disk and a new `(repo_id, oid)` row is inserted pointing at it **without verifying the request body hashes to the OID being claimed**. Any user with write access to one repo can bind their repo to an OID owned by a private repo and download the original bytes via their own download endpoint.

## Details

Dedupe shortcut in `internal/lfsx/storage.go` — when `os.Stat(fpath)` succeeds, it drains the body and returns the existing size with **no hash check**:

```go
if fi, err := os.Stat(fpath); err == nil {
    _, _ = io.Copy(io.Discard, rc)
    return fi.Size(), nil          // returns success with no hash check
}
```

Hash verification runs only in the *new-file* branch — the dedupe path returns earlier. The caller (`serveUpload`) trusts that success and inserts the per-repo binding via `CreateLFSObject`, an unconditional `INSERT` on `(repo_id, oid)` with no check that the OID is referenced by the requesting repo's history. `serveDownload` consults only the per-repo row, then streams from the shared content-addressed file — so a repo can claim and read another tenant's private object.
