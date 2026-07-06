# Security finding

> **Source:** GitHub Security Advisory **GHSA-9r4w-jg96-92mv** (CWE-20), published 2026-06-12.
> https://github.com/google/go-attestation/security/advisories/GHSA-9r4w-jg96-92mv
>
> This is the **detection report** handed to the agent — what an upstream scanner / advisory tells you.
> The advisory's **"Fix" section (how it was patched) has been deliberately removed**: the agent must
> produce the remediation itself. Nothing below prescribes a fix.

**Type:** Improper Input Validation — CWE-20
**Location:** `attest/internal/events.go` — function `parseEfiSignatureList`

## Summary

`parseEfiSignatureList()` in `attest/internal/events.go` does not skip `SignatureHeaderSize` vendor bytes before reading `EFI_SIGNATURE_LIST` signature entries, violating UEFI specification section 31.4.1.

## Impact

For `hashSHA256SigGUID` lists, attacker-controlled vendor header bytes are appended directly to the trusted SHA256 hash list. A crafted TPM event log can inject arbitrary SHA256 hashes into the verifier's trusted measurement database, allowing a remote attestation verifier to accept a compromised boot state as legitimate — breaking the core integrity guarantee of remote attestation.

## Root Cause

After `binary.Read(&signatures.Header)` reads 28 bytes, `buf` points to the start of the `SignatureHeaderSize` vendor bytes. Both entry loops begin reading entries immediately, treating those vendor bytes as signature entries.
