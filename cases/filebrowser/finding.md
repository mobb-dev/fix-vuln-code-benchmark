# Security finding

> **Source:** GitHub Security Advisory **GHSA-j9jx-hp4c-ghhh** / CVE-2026-54091 (CWE-863), published 2026-06-12.
> https://github.com/advisories/GHSA-j9jx-hp4c-ghhh
> Detection report handed to the agent; remediation guidance withheld — the agent must produce the fix itself.

**Type:** Incorrect Authorization — CWE-863
**Location:** `http/public.go` (public share handlers) and `http/data.go` (the `d.Check` authorization)

## Summary

File Browser's public share handlers rebase the share owner's filesystem root to the shared directory and then evaluate descendant paths against the owner's global and per-user rules using the **rebased relative path** instead of the original path relative to the owner's scope. An attacker who knows a public directory-share URL can access files and subdirectories the owner explicitly blocked with rules, as long as those blocked paths are located underneath the shared directory — unauthenticated information disclosure through `GET /api/public/share/*` and `GET /api/public/dl/*`.

## Details

The public share flow first resolves the original shared path under the owner's filesystem, then switches `d.user.Fs` to a new `BasePathFs` rooted at the shared directory. The follow-up authorization check is still performed by `d.Check`, which compares the request path to rule strings using prefix matching. When the share target is a directory, the path passed to `d.Check` becomes relative to the shared directory, while the rules remain relative to the owner's original scope. A deny rule such as `/projects/private` therefore no longer matches a public share request for `/private/secret.txt`, even though the rebased filesystem resolves that request to the real path `/projects/private/secret.txt`.

```go
// http/public.go
if file.IsDir {
    basePath = filepath.Clean(link.Path)
    filePath = ifPath
}
d.user.Fs = afero.NewBasePathFs(d.user.Fs, basePath)
file, err = files.NewFileInfo(&files.FileOptions{
    Fs: d.user.Fs, Path: filePath, Expand: true, Checker: d,
})
```
```go
// http/data.go
func (d *data) Check(path string) bool {
    allow := true
    for _, rule := range d.settings.Rules { if rule.Matches(path) { allow = rule.Allow } }
    for _, rule := range d.user.Rules    { if rule.Matches(path) { allow = rule.Allow } }
    return allow
}
```
