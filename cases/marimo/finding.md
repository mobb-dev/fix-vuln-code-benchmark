# Security finding

> **Source:** GitHub Security Advisory **GHSA-8m59-7xv8-735h** / CVE-2026-54386 (CWE-79), published 2026-06-18.
> https://github.com/marimo-team/marimo/security/advisories/GHSA-8m59-7xv8-735h
>
> This is the **detection report** handed to the agent — what an upstream scanner / advisory tells you.
> Any remediation guidance has been withheld: the agent must produce the fix itself.

**Type:** Reflected Cross-site Scripting (XSS) — CWE-79
**Location:** `marimo/_server/api/endpoints/assets.py` — function `_inject_service_worker`

## Summary

marimo before 0.23.9 contains a reflected cross-site scripting vulnerability in the notebook page that allows unauthenticated attackers to inject arbitrary JavaScript by exploiting improper escaping of the user-controlled file key reflected into an inline JavaScript string literal. The value is the `file` query parameter, which `_inject_service_worker` interpolates directly into an inline `<script>` as a single-quoted JS string literal.

## Impact

Attackers can craft a malicious link with a payload beginning with `__new__` to bypass the 404 check and inject JavaScript into the page, which executes without Content-Security-Policy restrictions in the origin of a victim's marimo server.
