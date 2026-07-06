**Claude:** I'll start by reading the FINDING.txt file to understand the vulnerability.

**→ Read**(file_path=/work/FINDING.txt)
  ↳ *result:* 1	Project: oviva-ag/epa4all-client
2	Vulnerability type: Improper Certificate Validation (CWE-295)
3	
4	Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):
5	
6	  vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidatorFactory.java
7	    - lines 2-7
8	    - lines 1  …(+491 more chars)
**Claude:** Let me read both files referenced in the finding.

**→ Read**(file_path=/work/vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidatorFactory.java)
  ↳ *result:* 1	package com.oviva.telematik.vau.httpclient.internal;
2	
3	import com.oviva.telematik.vau.httpclient.HttpClient;
4	import com.oviva.telematik.vau.httpclient.internal.cert.TrustValidator;
5	import de.gematik.vau.lib.VauClientStateMachine;
6	import java.net.URI;
7	
8	public class SignedPublicKeysTrustValidatorFactory {
9	
10	  private final boolean   …(+560 more chars)
**→ Read**(file_path=/work/vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidatorImpl.java)
  ↳ *result:* 1	package com.oviva.telematik.vau.httpclient.internal;
2	
3	import com.nimbusds.jose.JOSEException;
4	import com.nimbusds.jose.crypto.impl.ECDSA;
5	import com.oviva.telematik.vau.httpclient.HttpClient;
6	import com.oviva.telematik.vau.httpclient.internal.cert.CertificateValidationException;
7	import com.oviva.telematik.vau.httpclient.internal.cert.  …(+2007 more chars)
**Claude:** Now let me look at the related certificate validation classes to understand the full context.

**→ Read**(file_path=/work/vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/cert/VauCertificateClient.java)
  ↳ *result:* 1	package com.oviva.telematik.vau.httpclient.internal.cert;
2	
3	import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
4	import com.oviva.telematik.vau.httpclient.HttpClient;
5	import com.oviva.telematik.vau.httpclient.HttpRequest;
6	import com.oviva.telematik.vau.httpclient.VauClientException;
7	import de.gematik.vau.lib.exceptions.Vau  …(+4329 more chars)
**→ Read**(file_path=/work/vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/cert/TrustValidator.java)
  ↳ *result:* 1	package com.oviva.telematik.vau.httpclient.internal.cert;
2	
3	import java.security.cert.X509Certificate;
4	import java.util.List;
5	
6	public interface TrustValidator {
7	  /**
8	   * Implements A_24624-01
9	   *
10	   * <p>https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/latest/#A_24624-01
11	   *
12	   * <p>The requirement for the client   …(+733 more chars)
**Claude:** I now understand the vulnerability. In `SignedPublicKeysTrustValidatorImpl.isTrusted()`, line 45 calls `ecdsa.verify(signatureDer)` but **discards its boolean return value**. `Signature.verify()` returns `false` for a well-formed-but-invalid signature (it only throws `SignatureException` for malformed encoding). Since the result is ignored, the method unconditionally returns `true` at line 56 — so any forged signature with valid DER encoding is accepted as trusted. This is the CWE-295 improper certificate validation.

The fix is to return the result of the signature verification:

**→ Edit**(replace_all=false, file_path=/work/vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidatorImpl.java, old_string=      // https://www.rfc-editor.org/rfc/rfc7515.html#appendix-A.3.1
      var signatureDer = ECDSA.transcodeSignatureToDER(signedPublicKeys.  …(+392 more chars), new_string=      // https://www.rfc-editor.org/rfc/rfc7515.html#appendix-A.3.1
      var signatureDer = ECDSA.transcodeSignatureToDER(signedPublicKeys.  …(+382 more chars))
  ↳ *result:* The file /work/vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidatorImpl.java has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** The vulnerability is fixed. Here's a summary:

## Vulnerability: Improper Certificate Validation (CWE-295)

**Location:** `SignedPublicKeysTrustValidatorImpl.isTrusted()`

**The flaw:** The method verified an ECDSA signature over the VAU public keys but **ignored the result** of the verification:

```java
ecdsa.verify(signatureDer);   // boolean return value discarded
...
return true;                   // always returned trusted
```

Java's `Signature.verify()` returns `false` for a syntactically valid but cryptographically incorrect signature — it only throws `SignatureException` for malformed encoding. Because the boolean was discarded and the method unconditionally returned `true`, **any forged signature with valid DER encoding would be accepted as trusted**. This defeats the trust check entirely, enabling a man-in-the-middle to impersonate a VAU endpoint.

**The fix:** Return the actual verification result:

```java
return ecdsa.verify(signatureDer);
```

Now `isTrusted()` returns `true` only when the signature genuinely verifies against the validated certificate, and `false` otherwise — preserving the intended behavior (still returns `false` on any exception via the unchanged `catch` block) while actually enforcing the check.

I made only this single local source edit and did not alter any other behavior, commit, or push.


---
**Final (success):** The vulnerability is fixed. Here's a summary:

## Vulnerability: Improper Certificate Validation (CWE-295)

**Location:** `SignedPublicKeysTrustValidatorImpl.isTrusted()`

**The flaw:** The method verified an ECDSA signature over the VAU public keys but **ignored the result** of the verification:

```java
ecdsa.verify(signatureDer);   // boolean return value discarded
...
return true;                   // always returned trusted
```

Java's `Signature.verify()` returns `false` for a syntactically valid but cryptographically incorrect signature — it only throws `SignatureException` for malformed encoding. Because the boolean was discarded and the method unconditionally returned `true`, **any forged signature with valid DER encoding would be accepted as trusted**. This defeats the trust check entirely, enabling a man-in-the-middle to impersonate a VAU endpoint.

**The fix:** Return the actual verification result:

```java
return ecdsa.verify(signatureDer);
```

Now `isTrusted()` returns `true` only when the signature genuinely verifies against the validated certificate, and `false` otherwise — preserving the intended behavior (still returns `false` on any exception via the unchanged `catch` block) while actually enforcing the check.

I made only this single local source edit and did not alter any other behavior, commit, or push.

*turns 7 · cost $0.238*
