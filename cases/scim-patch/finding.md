# Security finding

> **Source:** GitHub Security Advisory **GHSA-9m6g-wc8r-q59c** / CVE-2026-48170 (CWE-1321), published 2026-06-22.
> https://github.com/advisories/GHSA-9m6g-wc8r-q59c
> Detection report handed to the agent; remediation guidance withheld — the agent must produce the fix itself.

**Type:** Prototype Pollution — CWE-1321
**Location:** `src/scimPatch.ts` — the path/key resolution (`resolvePaths`), reached from `addOrReplaceObjectAttribute`

## Summary

`scim-patch` performs prototype pollution when applying a SCIM PATCH operation whose `value` object contains a key like `"__proto__.someProp"` (or a `path` containing `__proto__` / `constructor` / `prototype`). After one such patch, `Object.prototype.someProp` is set process-wide, affecting every plain object in the Node process. Any service that calls `scimPatch()` on attacker-controlled JSON (any SCIM endpoint accepting `PATCH` from an external IdP) is exploitable on a stock Node runtime.

## Root cause

`addOrReplaceObjectAttribute` iterates the user-supplied `patch.value` with `Object.entries` and feeds each key to `resolvePaths`, which splits on `.`. The resulting key segments — including `__proto__`, `constructor`, `prototype` — are walked by the assign/navigate logic without filtering, so they reach and mutate `Object.prototype`.

## Impact

Process-wide prototype pollution. Realistic consequences: privilege escalation (auth code reading `actor.isAdmin` off a plain object that expects the key absent), logic bypass / DoS, and persistence until the Node process restarts.
