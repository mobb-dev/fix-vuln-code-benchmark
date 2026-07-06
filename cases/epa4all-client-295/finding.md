# Security finding

> A code-security scan flagged the vulnerability below. No remediation is included; produce the fix yourself.

**Type:** CWE-295 — CWE-295
**Project:** `oviva-ag/epa4all-client`
**Primary location:** `vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidatorFactory.java`
**Other files possibly involved:** `vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidatorImpl.java`

## Details

### Impact
In SignedPublicKeysTrustValidatorImpl.isTrusted(), the ECDSA signature verification at line 45 discards the boolean return value of Signature.verify(). The method performs certificate chain validation, OCSP check, and signature algorithm setup, but never checks whether the signature actually matches. For any structurally valid signature, it returns true.

### Resources
- [MS-OVIVA-EPA4ALL-d76aec](https://www.machinespirits.com/advisory/d76aec/)
