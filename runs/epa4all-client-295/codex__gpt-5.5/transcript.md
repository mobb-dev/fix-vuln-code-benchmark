**Codex:** I’ll inspect the vulnerability note first, then trace the referenced code paths before editing so the fix stays scoped to the reported issue.

**→ shell:** `/bin/bash -lc "pwd && rg --files -g 'FINDING.txt' -g '"'!node_modules'"' -g '"'!vendor'"'"`
```
FINDING.txt

```
**→ shell:** `/bin/bash -lc 'git status --short'`
**→ shell:** `/bin/bash -lc "sed -n '1,220p' FINDING.txt"`
```
Project: oviva-ag/epa4all-client
Vulnerability type: Improper Certificate Validation (CWE-295)

Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):

  vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidatorFactory.java
    - lines 2-7
    - lines 19-25   in: public SignedPublicKeysTrustValidatorFactory(

  vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidato  …(+305 more chars)
```
**→ shell:** `/bin/bash -lc 'rg --files'`
```
epa4all-client/src/main/java/com/oviva/telematik/epa4all/client/Epa4AllClientFactoryBuilder.java
epa4all-client/src/main/java/com/oviva/telematik/epa4all/client/DuplicateDocumentClientException.java
epa4all-client/src/main/java/com/oviva/telematik/epa4all/client/NotAuthorizedClientException.java
telematik-tsl/src/main/java/com/oviva/telematik/pkitrust/Main.java
telematik-tsl/src/main/java/com/oviva/telematik/pkitrust/DownloadCaRoots.java
telematik-tsl/src/main/java/com/oviva/telematik/pkitrust/D  …(+40650 more chars)
```
**Codex:** The finding points at the VAU HTTP client’s signed public key trust validation. I’m reading those classes and nearby tests/usages now to identify the intended verification path and where certificate validation is being bypassed.

**→ shell:** `/bin/bash -lc 'nl -ba vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidatorFactory.java'`
```
     1	package com.oviva.telematik.vau.httpclient.internal;
     2	
     3	import com.oviva.telematik.vau.httpclient.HttpClient;
     4	import com.oviva.telematik.vau.httpclient.internal.cert.TrustValidator;
     5	import de.gematik.vau.lib.VauClientStateMachine;
     6	import java.net.URI;
     7	
     8	public class SignedPublicKeysTrustValidatorFactory {
     9	
    10	  private final boolean isPu;
    11	  private final HttpClient outerClient;
    12	  private final TrustValidator trustValid  …(+516 more chars)
```
**→ shell:** `/bin/bash -lc 'nl -ba vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/cert/TrustValidator.java && nl -ba vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclien  …(+159 more chars)`
```
     1	package com.oviva.telematik.vau.httpclient.internal.cert;
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
    12	   * <p>The requirement for the client to validate the certificate chain
    13	   *
    14	   * @param certificate the certificate   …(+18629 more chars)
```
**→ shell:** `/bin/bash -lc 'nl -ba vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidatorImpl.java'`
```
     1	package com.oviva.telematik.vau.httpclient.internal;
     2	
     3	import com.nimbusds.jose.JOSEException;
     4	import com.nimbusds.jose.crypto.impl.ECDSA;
     5	import com.oviva.telematik.vau.httpclient.HttpClient;
     6	import com.oviva.telematik.vau.httpclient.internal.cert.CertificateValidationException;
     7	import com.oviva.telematik.vau.httpclient.internal.cert.TrustValidator;
     8	import com.oviva.telematik.vau.httpclient.internal.cert.VauCertificateClient;
     9	import   …(+2095 more chars)
```
**→ shell:** `/bin/bash -lc 'rg -n "SignedPublicKeysTrustValidator|SignedPublicKeysTrust|TrustValidator|VauCertificateClient|isTrusted" vau/vau-httpclient/src vau/vau-lib/src'`
```
vau/vau-lib/src/main/java/de/gematik/vau/lib/data/SignedPublicKeysTrustValidator.java:5:public interface SignedPublicKeysTrustValidator {
vau/vau-lib/src/main/java/de/gematik/vau/lib/data/SignedPublicKeysTrustValidator.java:7:  boolean isTrusted(SignedPublicKeys signedPublicKeys);
vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/VauClientFactoryBuilder.java:6:import com.oviva.telematik.vau.httpclient.internal.SignedPublicKeysTrustValidatorFactory;
vau/vau-httpclient/src/main/j  …(+11539 more chars)
```
**Codex:** The core bug is in the signature verification result: `Signature.verify(...)` is called, but its boolean return value is ignored, so a bad signature still reaches `return true`. I’m checking test structure next, then I’ll add a focused regression test around that validator.

**→ shell:** `/bin/bash -lc 'find vau/vau-httpclient/src/test/java -type f -maxdepth 10 | sort'`
```
vau/vau-httpclient/src/test/java/com/oviva/telematik/vau/httpclient/ConnectionFactoryTest.java
vau/vau-httpclient/src/test/java/com/oviva/telematik/vau/httpclient/internal/cert/TrustStoreValidatorTest.java
vau/vau-httpclient/src/test/java/com/oviva/telematik/vau/httpclient/internal/ConnectionFactoryTest.java
vau/vau-httpclient/src/test/java/com/oviva/telematik/vau/httpclient/internal/HeaderDecoratorHttpClientTest.java
vau/vau-httpclient/src/test/java/com/oviva/telematik/vau/httpclient/internal/H  …(+522 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,260p' vau/vau-httpclient/pom.xml"`
```
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>

  <parent>
    <groupId>com.oviva.telematik</groupId>
    <artifactId>vau-parent</artifactId>
    <version>1.0.0-SNAPSHOT</version>
  </parent>
  <artifactId>vau-httpclient</artifactId>

  <name>${project.groupId}:${pr  …(+2267 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,240p' vau/vau-httpclient/src/test/java/com/oviva/telematik/vau/httpclient/internal/cert/TrustStoreValidatorTest.java"`
```
package com.oviva.telematik.vau.httpclient.internal.cert;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import  …(+2925 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,180p' vau/vau-lib/src/main/java/de/gematik/vau/lib/data/SignedPublicKeysTrustValidator.java"`
```
package de.gematik.vau.lib.data;

import java.util.HexFormat;

public interface SignedPublicKeysTrustValidator {

  boolean isTrusted(SignedPublicKeys signedPublicKeys);

  /**
   * keys according to <a
   * href="https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/gemSpec_Krypt_V2.37.0/#A_24425-01">A_24425-01</a>
   * *
   */
  @SuppressWarnings("java:S6218")
  record SignedPublicKeys(
      byte[] signedPubKeys, byte[] signatureEs256, byte[] certHash, int cdv, byte[] ocspResponse) {
    @Ove  …(+409 more chars)
```
**→ shell:** `/bin/bash -lc 'nl -ba vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/cert/CertDataResponse.java && nl -ba vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpcli  …(+32 more chars)`
```
     1	package com.oviva.telematik.vau.httpclient.internal.cert;
     2	
     3	import com.fasterxml.jackson.annotation.JsonProperty;
     4	import java.util.List;
     5	
     6	/** A_24957 */
     7	@SuppressWarnings("java:S6218")
     8	public record CertDataResponse(
     9	    @JsonProperty("cert") byte[] cert,
    10	    @JsonProperty("ca") byte[] ca,
    11	    @JsonProperty("rca_chain") List<byte[]> rcaChain) {}
     1	package com.oviva.telematik.vau.httpclient.internal.cert;
     2	
     …(+189 more chars)
```
**→ shell:** `/bin/bash -lc 'nl -ba vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/HttpResponse.java && nl -ba vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/HttpRequest.ja  …(+97 more chars)`
```
     1	package com.oviva.telematik.vau.httpclient;
     2	
     3	import java.util.List;
     4	
     5	@SuppressWarnings("java:S6218")
     6	public record HttpResponse(int status, List<HttpHeader> headers, byte[] body) {}
     1	package com.oviva.telematik.vau.httpclient;
     2	
     3	import com.oviva.telematik.vau.httpclient.internal.HttpCodec;
     4	import java.net.URI;
     5	import java.nio.charset.StandardCharsets;
     6	import java.util.List;
     7	
     8	@SuppressWarnings("java:S6  …(+759 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"CBORMapper|writeValueAsBytes|CertDataResponse|signatureEs256\" vau -g '*.java'"`
```
vau/vau-lib/src/main/java/de/gematik/vau/lib/data/SignedPublicKeysTrustValidator.java:16:      byte[] signedPubKeys, byte[] signatureEs256, byte[] certHash, int cdv, byte[] ocspResponse) {
vau/vau-lib/src/main/java/de/gematik/vau/lib/data/SignedPublicKeysTrustValidator.java:20:      return "SignedPublicKeys[signedPubKeys='%s', signatureEs256='%s', certHash='%s', cdv=%s, ocspResponse='%s']"
vau/vau-lib/src/main/java/de/gematik/vau/lib/data/SignedPublicKeysTrustValidator.java:23:              hex.  …(+5635 more chars)
```
**Codex:** I’m going to make the production change by treating a `false` ECDSA verification result as trust failure. The regression test will drive the full validator path with fetched certificate data and a deliberately invalid ES256 signature, while keeping certificate-chain validation mocked so the test stays isolated to this bug.

**→ shell:** `/bin/bash -lc 'nl -ba vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/cert/CertificateValidationException.java'`
```
     1	package com.oviva.telematik.vau.httpclient.internal.cert;
     2	
     3	public class CertificateValidationException extends Exception {
     4	  public CertificateValidationException(String message, Throwable cause) {
     5	    super(message, cause);
     6	  }
     7	
     8	  public CertificateValidationException(String message) {
     9	    super(message);
    10	  }
    11	}

```
**→ shell:** `/bin/bash -lc "sed -n '1,220p' vau/vau-lib/src/main/java/de/gematik/vau/lib/data/SignedPublicVauKeys.java"`
```
/*
 * Copyright 2024 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Li  …(+4305 more chars)
```
**→ shell:** `/bin/bash -lc "find vau/vau-httpclient/src/test/resources -maxdepth 1 -type f -printf '%f\\n' | sort"`
```
ca.pem
cert.pem
chain.pem
ocsp.hex
truststore-test.p12

```
**Codex:** I found the expected signing format in `SignedPublicVauKeys`: signatures are raw ES256/P1363 bytes that are transcoded to DER before verification. I’m adding a test that supplies a structurally valid but wrong raw signature, which would have been accepted before because the false result was discarded.

**✎ files:** update `/work/vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidatorImpl.java`, add `/work/vau/vau-httpclient/src/test/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidatorImplTest.java`

**Codex:** The fix and regression test are in place. I’m running the VAU HTTP client test suite now; if formatting or provider assumptions show up, I’ll adjust locally.

**→ shell:** `/bin/bash -lc 'mvn -pl vau/vau-httpclient test'`
```
[INFO] Scanning for projects...
Downloading from central: https://repo.maven.apache.org/maven2/jakarta/platform/jakarta.jakartaee-bom/10.0.0/jakarta.jakartaee-bom-10.0.0.pom
Downloading from central: https://repo.maven.apache.org/maven2/org/apache/cxf/cxf-bom/4.2.0/cxf-bom-4.2.0.pom
Downloading from central: https://repo.maven.apache.org/maven2/org/slf4j/slf4j-bom/2.0.17/slf4j-bom-2.0.17.pom
Downloading from central: https://repo.maven.apache.org/maven2/com/fasterxml/jackson/jackson-bom/2.21.2/j  …(+4197 more chars)
```
**Codex:** The Maven run didn’t reach compilation because this environment could not resolve Maven Central (`repo.maven.apache.org`). I’ll still do a local source sanity pass and check the diff; if DNS recovers on retry I’ll rerun the targeted tests.

**→ shell:** `/bin/bash -lc 'git diff -- vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidatorImpl.java vau/vau-httpclient/src/test/java/com/oviva/telematik/vau  …(+65 more chars)`
```
diff --git a/vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidatorImpl.java b/vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidatorImpl.java
index bb73e05..cd5f7d6 100644
--- a/vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidatorImpl.java
+++ b/vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKey  …(+530 more chars)
```
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidatorImpl.java
?? vau/vau-httpclient/src/test/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidatorImplTest.java

```
**→ shell:** `/bin/bash -lc 'mvn -o -pl vau/vau-httpclient test'`
```
[INFO] Scanning for projects...
[ERROR] [ERROR] Some problems were encountered while processing the POMs:
[ERROR] Non-resolvable import POM: The following artifacts could not be resolved: jakarta.platform:jakarta.jakartaee-bom:pom:10.0.0 (absent): Cannot access central (https://repo.maven.apache.org/maven2) in offline mode and the artifact jakarta.platform:jakarta.jakartaee-bom:pom:10.0.0 has not been downloaded from it before. @ line 124, column 19
[ERROR] Non-resolvable import POM: The followi  …(+3576 more chars)
```
**Codex:** Offline Maven confirms the dependencies are not cached locally, so test execution is blocked by dependency resolution rather than code failure. I’m reviewing the new test source directly now and will make any cleanup needed before wrapping up.

**→ shell:** `/bin/bash -lc 'nl -ba vau/vau-httpclient/src/test/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidatorImplTest.java'`
```
     1	package com.oviva.telematik.vau.httpclient.internal;
     2	
     3	import static org.junit.jupiter.api.Assertions.assertFalse;
     4	
     5	import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
     6	import com.oviva.telematik.vau.httpclient.HttpResponse;
     7	import com.oviva.telematik.vau.httpclient.internal.cert.CertDataResponse;
     8	import de.gematik.vau.lib.data.SignedPublicKeysTrustValidator.SignedPublicKeys;
     9	import java.io.IOException;
    10	import java  …(+2553 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidatorImpl.java | sed -n '1,90p'"`
```
     1	package com.oviva.telematik.vau.httpclient.internal;
     2	
     3	import com.nimbusds.jose.JOSEException;
     4	import com.nimbusds.jose.crypto.impl.ECDSA;
     5	import com.oviva.telematik.vau.httpclient.HttpClient;
     6	import com.oviva.telematik.vau.httpclient.internal.cert.CertificateValidationException;
     7	import com.oviva.telematik.vau.httpclient.internal.cert.TrustValidator;
     8	import com.oviva.telematik.vau.httpclient.internal.cert.VauCertificateClient;
     9	import   …(+2202 more chars)
```
**→ shell:** `/bin/bash -lc "find ~/.m2/repository -path '*google-java-format*' -o -path '*spotless-maven-plugin*' | head -20"`
**Codex:** The direct review caught a Java inference issue in the test: `var` cannot be used as the target type for lambdas. I’m tightening those declarations to the actual interfaces so the test compiles cleanly.

**✎ files:** update `/work/vau/vau-httpclient/src/test/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidatorImplTest.java`

**→ shell:** `/bin/bash -lc "rg -n \"= \\(["'^)]*'"\\) ->|var .*->\" vau/vau-httpclient/src/test/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidatorImplTest.java"`
```
40:    TrustValidator trustValidator = (cert, issuerCa, certificateChain, ocspResponseDer) -> {};

```
**→ shell:** `/bin/bash -lc 'git diff --stat && git diff -- vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidatorImpl.java vau/vau-httpclient/src/test/java/com/  …(+84 more chars)`
```
 .../vau/httpclient/internal/SignedPublicKeysTrustValidatorImpl.java   | 4 +++-
 1 file changed, 3 insertions(+), 1 deletion(-)
diff --git a/vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidatorImpl.java b/vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidatorImpl.java
index bb73e05..cd5f7d6 100644
--- a/vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/SignedPubl  …(+658 more chars)
```
**→ shell:** `/bin/bash -lc 'mvn -pl vau/vau-httpclient test'`
```
[INFO] Scanning for projects...
Downloading from central: https://repo.maven.apache.org/maven2/jakarta/platform/jakarta.jakartaee-bom/10.0.0/jakarta.jakartaee-bom-10.0.0.pom
Downloading from central: https://repo.maven.apache.org/maven2/org/apache/cxf/cxf-bom/4.2.0/cxf-bom-4.2.0.pom
Downloading from central: https://repo.maven.apache.org/maven2/org/slf4j/slf4j-bom/2.0.17/slf4j-bom-2.0.17.pom
Downloading from central: https://repo.maven.apache.org/maven2/com/fasterxml/jackson/jackson-bom/2.21.2/j  …(+4197 more chars)
```
**Codex:** Implemented the remediation.

Changed [SignedPublicKeysTrustValidatorImpl.java](/work/vau/vau-httpclient/src/main/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidatorImpl.java:44) so ECDSA verification must return `true`; a `false` result now fails trust validation instead of falling through to `return true`.

Added a regression test in [SignedPublicKeysTrustValidatorImplTest.java](/work/vau/vau-httpclient/src/test/java/com/oviva/telematik/vau/httpclient/internal/SignedPublicKeysTrustValidatorImplTest.java:29) that exercises the validator with certificate data and an invalid ES256 signature, expecting `isTrusted(...)` to return `false`.

Verification: attempted `mvn -pl vau/vau-httpclient test`, but Maven could not resolve parent BOMs from Maven Central because `repo.maven.apache.org` failed DNS resolution in this environment. Offline mode also failed because those artifacts are not cached locally.


---
*tokens — input 476666 (cached 418176), output 5508, reasoning 1816*
