**Codex:** I’ll inspect the finding and the surrounding code first, then patch only the affected local source files and run the relevant checks if the project exposes them.

**→ shell:** `/bin/bash -lc "sed -n '1,220p' FINDING.txt"`
```
Project: eclipse-vertx/vert.x
Vulnerability type: Improper Certificate Validation (CWE-295)

Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):

  vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java
    - lines 17-22
    - lines 36-41
    - lines 50-55   in: public class SslContextManager {
    - lines 109-118   in: public synchronized int sniEntrySize() {
    - lines 236-258   in: private Future<Config> buildConfig(SSLOptions sslOptions,  …(+387 more chars)
```
**→ shell:** `/bin/bash -lc 'pwd && ls'`
```
/work
BENCHMARKING.md
BUILDING.md
CONTRIBUTING.md
FINDING.txt
LICENSE.md
NOTICE.md
pom.xml
README.md
vertx-core
vertx-core-logging

```
**→ shell:** `/bin/bash -lc 'rg --files'`
```
BUILDING.md
NOTICE.md
README.md
pom.xml
BENCHMARKING.md
LICENSE.md
FINDING.txt
vertx-core/src/main/asciidoc/net.adoc
vertx-core/src/main/asciidoc/filesystem.adoc
vertx-core/src/main/asciidoc/index.adoc
vertx-core/src/main/asciidoc/eventbus.adoc
vertx-core/src/main/asciidoc/shareddata.adoc
vertx-core/src/main/asciidoc/json.adoc
vertx-core/src/main/asciidoc/http.adoc
vertx-core/src/main/asciidoc/dns.adoc
vertx-core/src/main/asciidoc/virtualthreads.adoc
vertx-core/src/main/asciidoc/json-pointers.ad  …(+80487 more chars)
```
**Codex:** The finding points at TLS context construction and SNI lookup. I’m reading those classes plus nearby tests now so the fix preserves the existing API behavior.

**→ shell:** `/bin/bash -lc "nl -ba vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java | sed -n '1,220p'"`
```
     1	/*
     2	 * Copyright (c) 2011-2022 Contributors to the Eclipse Foundation
     3	 *
     4	 * This program and the accompanying materials are made available under the
     5	 * terms of the Eclipse Public License 2.0 which is available at
     6	 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
     7	 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
     8	 *
     9	 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
    10	 */
    11	package  …(+9257 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba vertx-core/src/test/java/io/vertx/tests/tls/SslContextManagerTest.java | sed -n '1,260p'"`
```
     1	/*
     2	 * Copyright (c) 2011-2019 Contributors to the Eclipse Foundation
     3	 *
     4	 * This program and the accompanying materials are made available under the
     5	 * terms of the Eclipse Public License 2.0 which is available at
     6	 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
     7	 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
     8	 *
     9	 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
    10	 */
    11	
    12  …(+10146 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java | sed -n '1,330p'"`
```
     1	/*
     2	 * Copyright (c) 2011-2019 Contributors to the Eclipse Foundation
     3	 *
     4	 * This program and the accompanying materials are made available under the
     5	 * terms of the Eclipse Public License 2.0 which is available at
     6	 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
     7	 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
     8	 *
     9	 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
    10	 */
    11	
    12  …(+13617 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"SslContextProvider|sslContext\\(|sni|SNIMatcher|Sni\" vertx-core/src/main/java vertx-core/src/test/java/io/vertx/tests/tls"`
```
vertx-core/src/test/java/io/vertx/tests/tls/SslContextManagerTest.java:20:import io.vertx.core.internal.tls.SslContextProvider;
vertx-core/src/test/java/io/vertx/tests/tls/SslContextManagerTest.java:48:      .buildSslContextProvider(new SSLOptions().setKeyCertOptions(Cert.CLIENT_JKS.get()).setTrustOptions(Trust.SERVER_JKS.get()), null, ClientAuth.NONE, null, false, (ContextInternal) vertx.getOrCreateContext())
vertx-core/src/test/java/io/vertx/tests/tls/SslContextManagerTest.java:61:    helper.b  …(+21728 more chars)
```
**Codex:** The risky shape is the provider cache key: it currently keys only by certificate/trust material, while provider behavior also depends on hostname verification, client auth, ALPN protocols, ciphers, and enabled TLS protocols. That can let a context built for one TLS policy be reused for another.

**→ shell:** `/bin/bash -lc "nl -ba vertx-core/src/main/java/io/vertx/core/net/SSLOptions.java | sed -n '1,260p'"`
```
     1	/*
     2	 * Copyright (c) 2011-2022 Contributors to the Eclipse Foundation
     3	 *
     4	 * This program and the accompanying materials are made available under the
     5	 * terms of the Eclipse Public License 2.0 which is available at
     6	 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
     7	 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
     8	 *
     9	 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
    10	 */
    11	package  …(+8914 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba vertx-core/src/main/java/io/vertx/core/net/ClientSSLOptions.java | sed -n '1,220p'"`
```
     1	/*
     2	 * Copyright (c) 2011-2023 Contributors to the Eclipse Foundation
     3	 *
     4	 * This program and the accompanying materials are made available under the
     5	 * terms of the Eclipse Public License 2.0 which is available at
     6	 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
     7	 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
     8	 *
     9	 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
    10	 */
    11	package  …(+5086 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java | sed -n '220,420p'"`
```
   220	      SslContext context = factory.create();
   221	      return new VertxSslContext(context) {
   222	        @Override
   223	        protected void initEngine(SSLEngine engine) {
   224	          configureEngine(engine, enabledProtocols, serverName, false);
   225	        }
   226	      };
   227	    } catch (Exception e) {
   228	      throw new VertxException(e);
   229	    }
   230	  }
   231	
   232	  public TrustManager[] defaultTrustManagers() {
   233	    return trustManagerFact  …(+4954 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba vertx-core/src/main/java/io/vertx/core/net/ServerSSLOptions.java | sed -n '1,180p'"`
```
     1	/*
     2	 * Copyright (c) 2011-2023 Contributors to the Eclipse Foundation
     3	 *
     4	 * This program and the accompanying materials are made available under the
     5	 * terms of the Eclipse Public License 2.0 which is available at
     6	 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
     7	 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
     8	 *
     9	 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
    10	 */
    11	package  …(+5704 more chars)
```
**Codex:** I’m going to split the cache key used for loaded TLS material from the cache key used for complete `SslContextProvider` instances. The loaded material can still be shared, but providers must be separated by TLS validation and negotiation settings.

**→ shell:** `/bin/bash -lc "nl -ba vertx-core/src/main/java/io/vertx/core/net/SSLOptions.java | sed -n '260,430p'"`
```
   260	  public Set<String> getEnabledSecureTransportProtocols() {
   261	    return new LinkedHashSet<>(enabledSecureTransportProtocols);
   262	  }
   263	
   264	  /**
   265	   * @return the SSL handshake timeout, in time unit specified by {@link #getSslHandshakeTimeoutUnit()}.
   266	   */
   267	  public long getSslHandshakeTimeout() {
   268	    return sslHandshakeTimeout;
   269	  }
   270	
   271	  /**
   272	   * Set the SSL handshake timeout, default time unit is seconds.
   273	   *
  …(+4693 more chars)
```
**→ shell:** `/bin/bash -lc 'rg -n "class TrustAllOptions|INSTANCE" vertx-core/src/main/java/io/vertx/core/net vertx-core/src/main/java/io/vertx/core/internal/tls'`
```
vertx-core/src/main/java/io/vertx/core/internal/tls/TrustAllOptions.java:25:class TrustAllOptions implements TrustOptions {
vertx-core/src/main/java/io/vertx/core/internal/tls/TrustAllOptions.java:27:  public static TrustAllOptions INSTANCE = new TrustAllOptions();
vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java:180:        return TrustAllOptions.INSTANCE;
vertx-core/src/main/java/io/vertx/core/net/endpoint/InteractionMetrics.java:24:  InteractionMetrics<?> INSTANCE =   …(+445 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"setEndpointIdentificationAlgorithm|getEndpointIdentificationAlgorithm|hostnameVerificationAlgorithm|resolveSslContextProvider\\(\" vertx-core/src/main/java/io/vertx/core"`
```
vertx-core/src/main/java/io/vertx/core/net/NetClientOptions.java:319:   * To disable hostname verification, set hostnameVerificationAlgorithm to an empty String
vertx-core/src/main/java/io/vertx/core/net/NetClientOptions.java:321:   * @param hostnameVerificationAlgorithm should be HTTPS, LDAPS or an empty String
vertx-core/src/main/java/io/vertx/core/net/NetClientOptions.java:325:  public NetClientOptions setHostnameVerificationAlgorithm(String hostnameVerificationAlgorithm) {
vertx-core/src/mai  …(+4251 more chars)
```
**Codex:** There’s a second cache-key bug in the material cache: CRL paths are read when building the trust managers, but they are not part of the key. I’m patching both key omissions and adding focused regression tests around hostname verification and CRL path separation.

**→ shell:** `/bin/bash -lc "nl -ba vertx-core/src/main/java/io/vertx/core/net/impl/NetClientImpl.java | sed -n '230,275p'"`
```
   230	      this.sslOptions = options;
   231	    }
   232	    return ctx.succeededFuture(true);
   233	  }
   234	
   235	  private void connectInternal(ConnectOptions connectOptions,
   236	                               boolean registerWriteHandlers,
   237	                               Promise<NetSocket> connectHandler,
   238	                               ContextInternal context,
   239	                               int remainingAttempts) {
   240	    if (closeSequence.started()) {
   2  …(+1854 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba vertx-core/src/main/java/io/vertx/core/net/impl/NetServerImpl.java | sed -n '330,500p'"`
```
   330	      ContextInternal ctx = vertx.getOrCreateContext();
   331	      Future<SslContextProvider> fut;
   332	      SslContextProvider current;
   333	      synchronized (this) {
   334	        current = sslContextProvider.result();
   335	        if (updateInProgress == null) {
   336	          ServerSSLOptions sslOptions = options.copy();
   337	          configure(sslOptions);
   338	          ClientAuth clientAuth = sslOptions.getClientAuth();
   339	          if (clientAuth == null) {
  …(+7911 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba vertx-core/src/main/java/io/vertx/core/net/impl/NetSocketImpl.java | sed -n '320,365p'"`
```
   320	      sslOptions != null ? sslOptions : this.sslOptions,
   321	      upgrade != null ? ((BufferInternal) upgrade).getByteBuf() : Unpooled.EMPTY_BUFFER);
   322	  }
   323	
   324	  private Future<Void> sslUpgrade(String serverName, SSLOptions sslOptions, ByteBuf msg) {
   325	    if (sslOptions == null) {
   326	      return context.failedFuture("Missing SSL options");
   327	    }
   328	    if (remoteAddress != null && !(sslOptions instanceof ClientSSLOptions)) {
   329	      return co  …(+1974 more chars)
```
**Codex:** I’m editing `SslContextManager` now. The change keeps the expensive key/trust loading cache intact, but makes provider reuse require an exact match of the full TLS policy that affects validation.

**✎ files:** update `/work/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java`

**Codex:** I’ve patched the key classes. Next I’m adding small tests that fail under the old cache behavior and pass when the TLS validation settings are isolated correctly.

**→ shell:** `/bin/bash -lc 'git diff -- vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java'`
```
diff --git a/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java b/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java
index 6fcd81d..22e217a 100755
--- a/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java
+++ b/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java
@@ -48,7 +48,7 @@ public class SslContextManager {
   private final Supplier<SslContextFactory> supplier;
   private final boolean useWorkerPoo  …(+5071 more chars)
```
**→ shell:** `/bin/bash -lc 'rg -n "addCrlPath|crl.pem|Certificate revoked|CRL" vertx-core/src/test/java vertx-core/src/test/resources'`
```
vertx-core/src/test/resources/tls/ssl.txt:248:openssl ca -config openssl.cnf -name CA_root -keyfile root-ca/ca-key.pem -passin pass:wibble -cert root-ca/ca-cert.pem -gencrl -out root-ca/crl.pem
vertx-core/src/test/resources/tls/root-ca/crl.pem:1:-----BEGIN X509 CRL-----
vertx-core/src/test/resources/tls/root-ca/crl.pem:11:-----END X509 CRL-----
vertx-core/src/test/java/io/vertx/tests/http/WebSocketTest.java:431:      options.addCrlPath("tls/root-ca/crl.pem");
vertx-core/src/test/java/io/vertx/te  …(+823 more chars)
```
**Codex:** The regression tests will exercise the public manager path rather than private key classes. That keeps the tests tied to the actual vulnerable behavior: a second TLS policy request must not get the first provider back from cache.

**✎ files:** update `/work/vertx-core/src/test/java/io/vertx/tests/tls/SslContextManagerTest.java`

**Codex:** The code and tests are in place. I’m running the focused TLS test class first so compile errors or cache regressions show up without waiting on the whole module.

**Codex:** The focused Maven run is still compiling after downloading dependencies for this fresh workspace. I’m waiting for the actual test result now.

**→ shell:** `/bin/bash -lc 'mvn -pl vertx-core -Dtest=SslContextManagerTest test'`
```
[INFO] Scanning for projects...
Downloading from central: https://repo.maven.apache.org/maven2/io/vertx/vertx5-parent/12/vertx5-parent-12.pom
Progress (1): 948 BProgress (1): 2.3 kBProgress (1): 4.8 kBProgress (1): 7.4 kBProgress (1): 9.8 kBProgress (1): 13 kB Progress (1): 18 kBProgress (1): 21 kBProgress (1): 21 kB                   Downloaded from central: https://repo.maven.apache.org/maven2/io/vertx/vertx5-parent/12/vertx5-parent-12.pom (21 kB at 72 kB/s)
Downloading from vertx-snapshots-re  …(+312453 more chars)
```
**Codex:** The focused test class passed: 13 tests, no failures. I’m doing a final diff and whitespace check now to catch formatting issues before I wrap up.

**→ shell:** `/bin/bash -lc 'git diff --check'`
**→ shell:** `/bin/bash -lc 'git diff --stat && git diff -- vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java vertx-core/src/test/java/io/vertx/tests/tls/SslContextManagerTest.java'`
```
 .../vertx/core/internal/tls/SslContextManager.java | 56 ++++++++++++++++++++--
 .../io/vertx/tests/tls/SslContextManagerTest.java  | 41 ++++++++++++++++
 2 files changed, 92 insertions(+), 5 deletions(-)
diff --git a/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java b/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java
index 6fcd81d..22e217a 100755
--- a/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java
+++ b/vertx-core/sr  …(+8001 more chars)
```
**Codex:** Whitespace is clean and the diff is limited to the TLS manager and its test. I’m checking the working tree status once so I can report exactly what changed.

**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java
 M vertx-core/src/test/java/io/vertx/tests/tls/SslContextManagerTest.java

```
**Codex:** Implemented the remediation.

Changed [SslContextManager.java](/work/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java) so cached `SslContextProvider` instances are keyed by the full TLS policy that affects validation and negotiation, including hostname verification algorithm, client auth, ALPN protocols, cipher suites, enabled TLS protocols, and the certificate/trust config. Also fixed the lower-level config cache to include CRL paths, so CRL-backed validation cannot reuse a non-CRL config.

Added regression coverage in [SslContextManagerTest.java](/work/vertx-core/src/test/java/io/vertx/tests/tls/SslContextManagerTest.java) for hostname verification, client auth, and CRL path cache separation.

Verification passed:

```bash
mvn -pl vertx-core -Dtest=SslContextManagerTest test
git diff --check
```


---
*tokens — input 727202 (cached 642432), output 5587, reasoning 1724*
