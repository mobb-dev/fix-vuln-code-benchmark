**Codex:** I’ll read the vulnerability note and inspect the referenced code before changing anything, then keep the fix scoped to the affected source.

**→ shell:** `/bin/bash -lc 'cat FINDING.txt'`
```
Project: eclipse-vertx/vert.x
Vulnerability type: Allocation of Resources Without Limits or Throttling (CWE-770)

Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):

  vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java
    - lines 17-22
    - lines 36-41
    - lines 50-55   in: public class SslContextManager {
    - lines 109-118   in: public synchronized int sniEntrySize() {
    - lines 236-258   in: private Future<Config> buildConfig(S  …(+408 more chars)
```
**→ shell:** `/bin/bash -lc "pwd && rg --files -g 'FINDING.txt' -g '"'!node_modules'"' -g '"'!vendor'"'"`
```
/work
FINDING.txt

```
**→ shell:** `/bin/bash -lc 'git status --short'`
**Codex:** The finding points at SNI SSL context caching. I’m going to read those classes and the nearby tests so the remediation matches the existing cache/configuration patterns.

**→ shell:** `/bin/bash -lc "sed -n '1,220p' vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java"`
```
/*
 * Copyright (c) 2011-2022 Contributors to the Eclipse Foundation
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
 */
package io.vertx.core.internal.tls;

import io.netty.handler.ssl.SniHandler;
import   …(+7717 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,340p' vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java"`
```
/*
 * Copyright (c) 2011-2019 Contributors to the Eclipse Foundation
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
 */

package io.vertx.core.internal.tls;

import io.netty.handler.ssl.OpenSsl;
import io  …(+11489 more chars)
```
**→ shell:** `/bin/bash -lc "rg \"sniEntrySize|SslContextManager|SslContextProvider|serverName\" vertx-core/src/test/java vertx-core/src/main/java -g '*.java'"`
```
vertx-core/src/main/java/io/vertx/core/http/impl/HttpServerConnectionInitializer.java:import io.vertx.core.internal.tls.SslContextManager;
vertx-core/src/main/java/io/vertx/core/http/impl/HttpServerConnectionInitializer.java:  void configurePipeline(Channel ch, SslChannelProvider sslChannelProvider, SslContextManager sslContextManager) {
vertx-core/src/main/java/io/vertx/core/http/impl/HttpServerConnectionInitializer.java:  private void configureHttp1OrH2CUpgradeHandler(ChannelPipeline pipeline,  …(+29600 more chars)
```
**Codex:** The unbounded part is the per-server-name SSL context map inside each provider; the manager’s outer LRU is bounded already. I’m checking constructor call sites and tests now so I can thread the same configured cache limit into those per-SNI maps without changing public behavior.

**→ shell:** `/bin/bash -lc "sed -n '1,260p' vertx-core/src/test/java/io/vertx/tests/tls/SslContextManagerTest.java"`
```
/*
 * Copyright (c) 2011-2019 Contributors to the Eclipse Foundation
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
 */

package io.vertx.tests.tls;

import io.netty.buffer.ByteBufAllocator;
import io.net  …(+8690 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '220,520p' vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java"`
```
      SslContext context = factory.create();
      return new VertxSslContext(context) {
        @Override
        protected void initEngine(SSLEngine engine) {
          configureEngine(engine, enabledProtocols, serverName, false);
        }
      };
    } catch (Exception e) {
      throw new VertxException(e);
    }
  }

  public TrustManager[] defaultTrustManagers() {
    return trustManagerFactory != null ? trustManagerFactory.getTrustManagers() : null;
  }

  public TrustManagerFactory def  …(+4121 more chars)
```
**→ shell:** `/bin/bash -lc 'rg "class LruCache|LruCache<" -n vertx-core/src/main/java vertx-core/src/test/java'`
```
vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java:54:    this.configMap = new LruCache<>(cacheMaxSize);
vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java:55:    this.sslContextProviderMap = new LruCache<>(cacheMaxSize);
vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java:239:  private static class LruCache<K, V> extends LinkedHashMap<K, V> {

```
**→ shell:** `/bin/bash -lc "rg \"new SslContextProvider\\(|new SslContextManager\\(\" -n"`
```
vertx-core/src/main/java/io/vertx/core/net/impl/NetClientImpl.java:82:    this.sslContextManager = new SslContextManager(SslContextManager.resolveEngineOptions(options.getSslEngineOptions(), options.isUseAlpn()));
vertx-core/src/main/java/io/vertx/core/net/impl/NetServerImpl.java:454:          helper = new SslContextManager(SslContextManager.resolveEngineOptions(options.getSslEngineOptions(), options.isUseAlpn()));

```
**Codex:** I’ve got enough context. The change is to make the per-provider SNI context caches bounded using the existing manager cache size, then add a regression test that drives more unique SNI names than the limit and verifies the cache cannot grow past it.

**→ shell:** `/bin/bash -lc 'rg "maven-surefire|junit" pom.xml vertx-core/pom.xml && rg "SslContextManagerTest" -n pom.xml vertx-core/pom.xml'`
```
vertx-core/pom.xml:      <groupId>junit</groupId>
vertx-core/pom.xml:      <artifactId>junit</artifactId>
vertx-core/pom.xml:      <version>${junit.version}</version>
vertx-core/pom.xml:          <artifactId>maven-surefire-plugin</artifactId>
pom.xml:    <junit.version>4.13.2</junit.version>

```
**Codex:** I’m editing the TLS provider constructor and cache internals now. The key point is that SNI names still get cached, but the cache now evicts once it reaches the manager’s configured maximum.

**✎ files:** update `/work/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java`

**Codex:** I’m going to avoid leaning on the concrete map type in `SslContextManager`; a dedicated cache-size field keeps the constructor data flow explicit and less brittle.

**✎ files:** update `/work/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java`

**Codex:** Next I’m adding the bounded synchronized SNI cache in `SslContextProvider`, while keeping the existing constructor available so internal callers are the only ones that need the explicit size.

**✎ files:** update `/work/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java`

**Codex:** I’m adding a regression test in the existing TLS test class that exercises the SNI path directly. It uses the current configurable cache size rather than introducing a new option or API.

**✎ files:** update `/work/vertx-core/src/test/java/io/vertx/tests/tls/SslContextManagerTest.java`

**Codex:** The code and test are patched. I’m running the focused Maven test now to catch compile issues and confirm the cache limit behavior.

**→ shell:** `/bin/bash -lc './mvnw -pl vertx-core -Dtest=SslContextManagerTest test'`
```
/bin/bash: line 1: ./mvnw: No such file or directory

```
**Codex:** There’s no Maven wrapper in this checkout, so I’m checking the project root for the available build entry point before rerunning the focused test.

**→ shell:** `/bin/bash -lc 'ls -la'`
```
total 72
drwxrwxrwx 16 root root   512 Jul  2 14:22 .
drwxr-xr-x  1 root root  4096 Jul  2 14:22 ..
-rw-rw-rw-  1 root root  1372 Jul  2 14:10 BENCHMARKING.md
-rw-rw-rw-  1 root root   924 Jul  2 14:10 BUILDING.md
-rw-rw-rw-  1 root root  8014 Jul  2 14:10 CONTRIBUTING.md
-rw-rw-rw-  1 root root   191 Jul  2 14:10 .editorconfig
-rw-rw-rw-  1 root root   908 Jul  2 14:10 FINDING.txt
drwxrwxrwx 12 root root   384 Jul  2 14:22 .git
drwxrwxrwx  5 root root   160 Jul  2 14:10 .github
-rw-rw-rw-  1 ro  …(+365 more chars)
```
**→ shell:** `/bin/bash -lc 'git diff -- vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java vertx-core/src/test/ja  …(+49 more chars)`
```
diff --git a/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java b/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java
index 6fcd81d..ae9e00f 100755
--- a/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java
+++ b/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java
@@ -47,10 +47,12 @@ public class SslContextManager {
 
   private final Supplier<SslContextFactory> supplier;
   private final boolean useWorke  …(+5658 more chars)
```
**Codex:** The root is plain Maven, not wrapper-based. I’m running the same focused test through `mvn` now.

**→ shell:** `/bin/bash -lc 'mvn -pl vertx-core -Dtest=SslContextManagerTest test'`
```
[INFO] Scanning for projects...
Downloading from central: https://repo.maven.apache.org/maven2/io/vertx/vertx5-parent/12/vertx5-parent-12.pom
[ERROR] [ERROR] Some problems were encountered while processing the POMs:
[FATAL] Non-resolvable parent POM for io.vertx:vertx-core-aggregator:5.0.12-SNAPSHOT: The following artifacts could not be resolved: io.vertx:vertx5-parent:pom:12 (absent): Could not transfer artifact io.vertx:vertx5-parent:pom:12 from/to central (https://repo.maven.apache.org/maven2  …(+1276 more chars)
```
**Codex:** The focused Maven test can’t start because the parent POM isn’t resolvable from Maven Central in this environment due DNS failure. I’m still doing local sanity checks on the patch and tightening one implementation detail in the cache.

**✎ files:** update `/work/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java`

**Codex:** I’m running whitespace and source diff checks now, since full test execution is blocked before compilation by dependency resolution.

**→ shell:** `/bin/bash -lc 'git diff --check'`
**→ shell:** `/bin/bash -lc 'git diff --stat && git diff -- vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java ver  …(+68 more chars)`
```
 .../vertx/core/internal/tls/SslContextManager.java |  5 +-
 .../core/internal/tls/SslContextProvider.java      | 53 ++++++++++++++++++++--
 .../io/vertx/tests/tls/SslContextManagerTest.java  | 11 +++++
 3 files changed, 64 insertions(+), 5 deletions(-)
diff --git a/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java b/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java
index 6fcd81d..ae9e00f 100755
--- a/vertx-core/src/main/java/io/vertx/core/intern  …(+5918 more chars)
```
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java
 M vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java
 M vertx-core/src/test/java/io/vertx/tests/tls/SslContextManagerTest.java

```
**→ shell:** `/bin/bash -lc "awk 'length("'$0) > 120 { print FILENAME ":" FNR ":" length($0) ":" $0 }'"' vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java vertx-core/src/main/java/io/vertx  …(+113 more chars)`
```
vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java:69:129:    this(useWorkerPool, clientAuth, endpointIdentificationAlgorithm, applicationProtocols, enabledCipherSuites, enabledProtocols,
vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java:143:123:        return sslContextMaps[idx].computeIfAbsent(serverName, s -> createContext(server, kmf, trustManagers, s, useAlpn));
vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java:262  …(+6069 more chars)
```
**Codex:** A couple of added lines are longer than the nearby style usually wants, so I’m wrapping only those new lines to keep the patch clean.

**✎ files:** update `/work/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java`

**✎ files:** update `/work/vertx-core/src/test/java/io/vertx/tests/tls/SslContextManagerTest.java`

**Codex:** The patch is in its final shape. I’m rerunning diff checks and collecting the final changed line references.

**→ shell:** `/bin/bash -lc "nl -ba vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java | sed -n '48,104p;352,382p'"`
```
    48	  private final String endpointIdentificationAlgorithm;
    49	  private final KeyManagerFactory keyManagerFactory;
    50	  private final TrustManagerFactory trustManagerFactory;
    51	  private final Function<String, KeyManagerFactory> keyManagerFactoryMapper;
    52	  private final Function<String, TrustManager[]> trustManagerMapper;
    53	
    54	  private final SslContext[] sslContexts = new SslContext[2];
    55	  private final Map<String, SslContext>[] sslContextMaps;
    56	
     …(+3995 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java | sed -n '44,58p;160,176p'"`
```
    44	    CLIENT_AUTH_MAPPING.put(ClientAuth.REQUEST, io.netty.handler.ssl.ClientAuth.OPTIONAL);
    45	    CLIENT_AUTH_MAPPING.put(ClientAuth.NONE, io.netty.handler.ssl.ClientAuth.NONE);
    46	  }
    47	
    48	  private final Supplier<SslContextFactory> supplier;
    49	  private final boolean useWorkerPool;
    50	  private final int cacheMaxSize;
    51	  private final Map<ConfigKey, Future<Config>> configMap;
    52	  private final Map<ConfigKey, Future<SslContextProvider>> sslContextPro  …(+1053 more chars)
```
**→ shell:** `/bin/bash -lc 'git diff --check'`
**→ shell:** `/bin/bash -lc "nl -ba vertx-core/src/test/java/io/vertx/tests/tls/SslContextManagerTest.java | sed -n '162,176p'"`
```
   162	  }
   163	
   164	  @Test
   165	  public void testSniCacheMaxSize() throws Exception {
   166	    ContextInternal ctx = (ContextInternal) vertx.getOrCreateContext();
   167	    SslContextManager helper = new SslContextManager(new JdkSSLEngineOptions(), 4);
   168	    SslContextProvider provider = awaitFuture(
   169	      helper.resolveSslContextProvider(new SSLOptions(), "", ClientAuth.NONE, null, ctx));
   170	    for (int i = 0;i < 5;i++) {
   171	      provider.sslClientContext("hos  …(+133 more chars)
```
**Codex:** The whitespace check passes. Since Maven is blocked by the unresolved parent POM, I’m doing one last source-level review for concurrency and cache behavior before wrapping up.

**Codex:** The final review looks consistent: only the SNI context maps changed from unbounded concurrent maps to bounded synchronized LRU maps, and the manager passes through its existing cache size.

**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java
 M vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java
 M vertx-core/src/test/java/io/vertx/tests/tls/SslContextManagerTest.java

```
**→ shell:** `/bin/bash -lc 'git diff --check && git diff --stat'`
```
 .../vertx/core/internal/tls/SslContextManager.java |  5 +-
 .../core/internal/tls/SslContextProvider.java      | 54 ++++++++++++++++++++--
 .../io/vertx/tests/tls/SslContextManagerTest.java  | 12 +++++
 3 files changed, 66 insertions(+), 5 deletions(-)

```
**Codex:** Implemented the remediation.

Changed:
- [SslContextManager.java](/work/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java:50): keeps the configured cache max size and passes it into each `SslContextProvider`.
- [SslContextProvider.java](/work/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java:55): replaced unbounded per-SNI `ConcurrentHashMap` caches with bounded synchronized LRU caches.
- [SslContextManagerTest.java](/work/vertx-core/src/test/java/io/vertx/tests/tls/SslContextManagerTest.java:165): added a regression test proving SNI cache entries cannot exceed the configured limit.

Verification:
- `git diff --check` passes.
- Tried `mvn -pl vertx-core -Dtest=SslContextManagerTest test`, but Maven could not resolve the parent POM because `repo.maven.apache.org` DNS resolution failed in this environment.


---
*tokens — input 596716 (cached 497280), output 6532, reasoning 2260*
