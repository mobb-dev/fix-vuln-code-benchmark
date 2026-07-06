**Codex:** I’ll inspect the vulnerability note and the nearby code first, then make the smallest source change that removes the issue without shifting behavior.

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
**Codex:** The finding points at Vert.x TLS SNI context selection. I’m reading those classes and their tests now so the fix matches the existing cache/provider model.

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
**→ shell:** `/bin/bash -lc "rg -n \"SslContextProvider|SslContextManager|sni|sslContext\\(\" vertx-core/src/test/java/io/vertx/tests/tls vertx-core/src/main/java/io/vertx/core -g '*.java'"`
```
vertx-core/src/test/java/io/vertx/tests/tls/SslContextManagerTest.java:19:import io.vertx.core.internal.tls.SslContextManager;
vertx-core/src/test/java/io/vertx/tests/tls/SslContextManagerTest.java:20:import io.vertx.core.internal.tls.SslContextProvider;
vertx-core/src/test/java/io/vertx/tests/tls/SslContextManagerTest.java:38:public class SslContextManagerTest extends VertxTestBase {
vertx-core/src/test/java/io/vertx/tests/tls/SslContextManagerTest.java:46:    SslContextManager helper = new Ssl  …(+18009 more chars)
```
**Codex:** The risky behavior is likely cache key collapse: provider cache keys currently ignore hostname verification, client-auth mode, ALPN/application protocols, cipher/protocol sets, and CRL paths. That can reuse a context built with different certificate-validation settings.

**→ shell:** `/bin/bash -lc "nl -ba vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java | sed -n '220,360p'"`
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
**→ shell:** `/bin/bash -lc "nl -ba vertx-core/src/test/java/io/vertx/tests/tls/SslContextManagerTest.java | sed -n '1,270p'"`
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
**→ shell:** `/bin/bash -lc "rg -n \"getEnabledCipherSuites|getEnabledSecureTransportProtocols|getCrlPaths|setHostnameVerificationAlgorithm|DEFAULT_HOSTNAME|hostnameVerificationAlgorithm|endpointIdentificationAlgor  …(+179 more chars)`
```
vertx-core/src/main/java/io/vertx/core/net/SSLOptions.java:89:    this.enabledCipherSuites = other.getEnabledCipherSuites() == null ? new LinkedHashSet<>() : new LinkedHashSet<>(other.getEnabledCipherSuites());
vertx-core/src/main/java/io/vertx/core/net/SSLOptions.java:90:    this.crlPaths = new ArrayList<>(other.getCrlPaths());
vertx-core/src/main/java/io/vertx/core/net/SSLOptions.java:93:    this.enabledSecureTransportProtocols = other.getEnabledSecureTransportProtocols() == null ? new LinkedH  …(+8011 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba vertx-core/src/main/java/io/vertx/core/net/SSLOptions.java | sed -n '1,330p'"`
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
    11	package  …(+11663 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba vertx-core/src/main/java/io/vertx/core/net/ClientSSLOptions.java | sed -n '1,140p'"`
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
    11	package  …(+4324 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"class .*SslContextFactory|interface SslContextFactory|serverName\\(|endpointIdentification|trustManagerFactory|keyMananagerFactory\" vertx-core/src/main/java -g '*.java'"`
```
vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java:49:  private final String endpointIdentificationAlgorithm;
vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java:51:  private final TrustManagerFactory trustManagerFactory;
vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java:62:                            String endpointIdentificationAlgorithm,
vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java:68:     …(+6612 more chars)
```
**Codex:** I’m going to split the manager’s cache keys: the lower-level key will cover certificate material and CRLs, while the provider key will also cover validation and TLS negotiation settings. That keeps existing reuse where it is safe, and prevents reusing a provider with stale certificate-validation state.

**→ shell:** `/bin/bash -lc "nl -ba vertx-core/src/main/java/io/vertx/core/spi/tls/DefaultSslContextFactory.java | sed -n '1,170p'"`
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
    12  …(+6596 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba vertx-core/src/main/java/io/vertx/core/spi/tls/SslContextFactory.java | sed -n '1,150p'"`
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
    11	package  …(+3457 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"maven-surefire|junit|artifactId\" pom.xml vertx-core/pom.xml | sed -n '1,180p'"`
```
vertx-core/pom.xml:19:    <artifactId>vertx-core-aggregator</artifactId>
vertx-core/pom.xml:23:  <artifactId>vertx-core</artifactId>
vertx-core/pom.xml:41:      <artifactId>vertx-core-logging</artifactId>
vertx-core/pom.xml:47:      <artifactId>netty-common</artifactId>
vertx-core/pom.xml:51:      <artifactId>netty-buffer</artifactId>
vertx-core/pom.xml:55:      <artifactId>netty-transport</artifactId>
vertx-core/pom.xml:59:      <artifactId>netty-handler</artifactId>
vertx-core/pom.xml:63:       …(+4159 more chars)
```
**Codex:** I’m editing `SslContextManager` now and adding regression coverage to lock down the cache behavior. The tests focus on provider identity because the bug is stale provider reuse before any engine is created.

**✎ files:** update `/work/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java`

**Codex:** The source change is in place. I’m adding a focused regression test for the stale-cache cases: hostname verification, client auth, ALPN protocols, cipher suites, secure transport protocols, and CRL paths.

**✎ files:** update `/work/vertx-core/src/test/java/io/vertx/tests/tls/SslContextManagerTest.java`

**Codex:** The regression test is added. I’m running the TLS manager test class now; if it exposes a compatibility issue with the chosen fixture paths or TLS settings, I’ll adjust the test without broadening the production change.

**→ shell:** `/bin/bash -lc 'mvn -pl vertx-core -Dtest=io.vertx.tests.tls.SslContextManagerTest test'`
```
[INFO] Scanning for projects...
Downloading from central: https://repo.maven.apache.org/maven2/io/vertx/vertx5-parent/12/vertx5-parent-12.pom
[ERROR] [ERROR] Some problems were encountered while processing the POMs:
[FATAL] Non-resolvable parent POM for io.vertx:vertx-core-aggregator:5.0.12-SNAPSHOT: The following artifacts could not be resolved: io.vertx:vertx5-parent:pom:12 (absent): Could not transfer artifact io.vertx:vertx5-parent:pom:12 from/to central (https://repo.maven.apache.org/maven2  …(+1276 more chars)
```
**Codex:** The targeted Maven test could not start because the parent POM is not available locally and Maven cannot resolve `repo.maven.apache.org` from this environment. I’m doing a local diff review next to catch type/import issues before wrapping up.

**→ shell:** `/bin/bash -lc 'git diff -- vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java vertx-core/src/test/java/io/vertx/tests/tls/SslContextManagerTest.java'`
```
diff --git a/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java b/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java
index 6fcd81d..3c99142 100755
--- a/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java
+++ b/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java
@@ -48,7 +48,7 @@ public class SslContextManager {
   private final Supplier<SslContextFactory> supplier;
   private final boolean useWorkerPoo  …(+7762 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"new ConfigKey|new ProviderKey|sslContextProviderMap|ConfigKey\\(\" vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java"`
```
51:  private final Map<ProviderKey, Future<SslContextProvider>> sslContextProviderMap;
55:    this.sslContextProviderMap = new LruCache<>(cacheMaxSize);
103:    for (Future<SslContextProvider> fut : sslContextProviderMap.values()) {
122:    ProviderKey k = new ProviderKey(options, hostnameVerificationAlgorithm, clientAuth, applicationProtocols);
125:        sslContextProviderMap.remove(k);
127:        Future<SslContextProvider> v = sslContextProviderMap.get(k);
133:      sslContextProviderMap.pu  …(+303 more chars)
```
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java
 M vertx-core/src/test/java/io/vertx/tests/tls/SslContextManagerTest.java

```
**Codex:** The diff review did not show missing imports; the test file already imports `java.util.*`. I’m checking whether Maven can at least run offline with the local cache, then I’ll report the verification status accurately.

**→ shell:** `/bin/bash -lc 'mvn -o -pl vertx-core -Dtest=io.vertx.tests.tls.SslContextManagerTest test'`
```
[INFO] Scanning for projects...
[ERROR] [ERROR] Some problems were encountered while processing the POMs:
[FATAL] Non-resolvable parent POM for io.vertx:vertx-core-aggregator:5.0.12-SNAPSHOT: The following artifacts could not be resolved: io.vertx:vertx5-parent:pom:12 (absent): Cannot access central (https://repo.maven.apache.org/maven2) in offline mode and the artifact io.vertx:vertx5-parent:pom:12 has not been downloaded from it before. and 'parent.relativePath' points at wrong local POM @ lin  …(+1072 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba vertx-core/src/main/java/io/vertx/core/net/TrustAllOptions.java | sed -n '1,220p'"`
```
nl: vertx-core/src/main/java/io/vertx/core/net/TrustAllOptions.java: No such file or directory

```
**→ shell:** `/bin/bash -lc "rg -n \"class TrustAllOptions|TrustAllOptions.INSTANCE|X509TrustManager|checkServerTrusted|checkClientTrusted\" vertx-core/src/main/java vertx-core/src/test/java -g '*.java'"`
**Codex:** I’m doing one more pass on adjacent TLS trust code to make sure the finding is not about an explicit trust-all path. `trustAll` is an intentional option here; the remediation stays focused on accidental reuse of insecure validation settings.

**→ shell:** `/bin/bash -lc "nl -ba vertx-core/src/main/java/io/vertx/core/net/impl/TrustAllTrustManager.java | sed -n '1,100p'"`
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
    12  …(+1031 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba vertx-core/src/main/java/io/vertx/core/internal/tls/TrustAllOptions.java | sed -n '1,160p'"`
```
     1	/*
     2	 * Copyright (c) 2011-2024 Contributors to the Eclipse Foundation
     3	 *
     4	 * This program and the accompanying materials are made available under the
     5	 * terms of the Eclipse Public License 2.0 which is available at
     6	 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
     7	 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
     8	 *
     9	 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
    10	 */
    11	package  …(+2174 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba vertx-core/src/main/java/io/vertx/core/net/impl/NetClientImpl.java | sed -n '230,270p' && nl -ba vertx-core/src/main/java/io/vertx/core/net/impl/NetSocketImpl.java | sed -n '330,  …(+103 more chars)`
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
   2  …(+3892 more chars)
```
**Codex:** One issue surfaced in the review: Java `Set.equals` ignores order, but this code preserves cipher/protocol ordering elsewhere. I’m tightening the provider key to snapshot those ordered sets as lists so two configurations with the same entries in a different order do not collapse.

**✎ files:** update `/work/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java`

**Codex:** The ordered-key adjustment is done. I’m running lightweight local checks that do not need Maven dependency resolution.

**→ shell:** `/bin/bash -lc 'git diff --stat'`
```
 .../vertx/core/internal/tls/SslContextManager.java | 61 ++++++++++++++++++++--
 .../io/vertx/tests/tls/SslContextManagerTest.java  | 26 +++++++++
 2 files changed, 82 insertions(+), 5 deletions(-)

```
**→ shell:** `/bin/bash -lc 'git diff --check'`
**→ shell:** `/bin/bash -lc 'git diff -- vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java vertx-core/src/test/java/io/vertx/tests/tls/SslContextManagerTest.java'`
```
diff --git a/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java b/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java
index 6fcd81d..5a52ba6 100755
--- a/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java
+++ b/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java
@@ -48,7 +48,7 @@ public class SslContextManager {
   private final Supplier<SslContextFactory> supplier;
   private final boolean useWorkerPoo  …(+7756 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java | sed -n '48,140p;250,350p'"`
```
    48	  private final Supplier<SslContextFactory> supplier;
    49	  private final boolean useWorkerPool;
    50	  private final Map<ConfigKey, Future<Config>> configMap;
    51	  private final Map<ProviderKey, Future<SslContextProvider>> sslContextProviderMap;
    52	
    53	  public SslContextManager(SSLEngineOptions sslEngineOptions, int cacheMaxSize) {
    54	    this.configMap = new LruCache<>(cacheMaxSize);
    55	    this.sslContextProviderMap = new LruCache<>(cacheMaxSize);
    56	    t  …(+9103 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba vertx-core/src/test/java/io/vertx/tests/tls/SslContextManagerTest.java | sed -n '145,200p'"`
```
   145	    assertEquals(new ArrayList<>(new HttpServerOptions(json).getEnabledSecureTransportProtocols()), expectedProtocols);
   146	  }
   147	
   148	  @Test
   149	  public void testCache() throws Exception {
   150	    ContextInternal ctx = (ContextInternal) vertx.getOrCreateContext();
   151	    SslContextManager helper = new SslContextManager(new JdkSSLEngineOptions(), 4);
   152	    SSLOptions options = new SSLOptions().setKeyCertOptions(Cert.SERVER_JKS.get());
   153	    SslContextProvi  …(+3377 more chars)
```
**Codex:** Implemented the remediation.

Changed [SslContextManager.java](/work/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java:51) so the `SslContextProvider` cache no longer keys only on cert/trust material. It now includes hostname verification, client auth, ALPN application protocols, cipher suite order, secure transport protocol order, and CRL paths/values. This prevents reusing a provider created with weaker or different certificate-validation settings.

Added regression coverage in [SslContextManagerTest.java](/work/vertx-core/src/test/java/io/vertx/tests/tls/SslContextManagerTest.java:164) to verify these provider-affecting options produce distinct cache entries while unchanged options still reuse the cache.

Verification:
- `git diff --check` passed.
- Maven test execution could not run because the parent POM `io.vertx:vertx5-parent:pom:12` is not cached locally and this environment cannot resolve `repo.maven.apache.org`.


---
*tokens — input 815707 (cached 737280), output 7013, reasoning 2053*
