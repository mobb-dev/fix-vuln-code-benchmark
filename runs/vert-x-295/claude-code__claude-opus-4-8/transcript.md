**Claude:** I'll start by reading the FINDING.txt file to understand the vulnerability.

**→ Read**(file_path=/work/FINDING.txt)
  ↳ *result:* 1	Project: eclipse-vertx/vert.x
2	Vulnerability type: Allocation of Resources Without Limits or Throttling (CWE-770)
3	
4	Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):
5	
6	  vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java
7	    - lines 17-22
8	    - lines 36-41
9	    - lines 50-55   …(+609 more chars)
**Claude:** Let me read the two files mentioned in the finding.

**→ Read**(file_path=/work/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java)
  ↳ *result:* 1	/*
2	 * Copyright (c) 2011-2019 Contributors to the Eclipse Foundation
3	 *
4	 * This program and the accompanying materials are made available under the
5	 * terms of the Eclipse Public License 2.0 which is available at
6	 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
7	 * which is available at https://www.apache.org  …(+12751 more chars)
**→ Read**(file_path=/work/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java)
  ↳ *result:* 1	/*
2	 * Copyright (c) 2011-2022 Contributors to the Eclipse Foundation
3	 *
4	 * This program and the accompanying materials are made available under the
5	 * terms of the Eclipse Public License 2.0 which is available at
6	 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
7	 * which is available at https://www.apache.org  …(+13691 more chars)
**Claude:** Now let me understand the vulnerability better. This is a classic SNI cache exhaustion (CWE-770). Let me look at how these classes are used and configured.

**→ Bash**(command=grep -rn "sniEntrySize\|sslContextMaps\|new SslContextManager\|SslContextProvider(" --include=*.java vertx-core/src/main | head -50)
  ↳ *result:* vertx-core/src/main/java/io/vertx/core/net/impl/NetSocketImpl.java:338:        f = sslContextManager.resolveSslContextProvider(
vertx-core/src/main/java/io/vertx/core/net/impl/NetSocketImpl.java:350:        f = sslContextManager.resolveSslContextProvider(
vertx-core/src/main/java/io/vertx/core/net/impl/NetServerImpl.java:321:  public int sniEntrySi  …(+3838 more chars)
**→ Bash**(command=grep -rn "sni\|Sni\|SNI\|CacheMaxSize\|cacheMaxSize\|MaxSize" vertx-core/src/main/java/io/vertx/core/net/SSLOptions.java vertx-core/src/main  …(+70 more chars))
  ↳ *result:* vertx-core/src/main/java/io/vertx/core/net/impl/NetServerImpl.java:237:        SslChannelProvider sslChannelProvider = new SslChannelProvider(vertx, sslContextProvider, sslOptions.isSni());
vertx-core/src/main/java/io/vertx/core/net/impl/NetServerImpl.java:321:  public int sniEntrySize() {
vertx-core/src/main/java/io/vertx/core/net/impl/NetServerIm  …(+56 more chars)
**→ Bash**(command=grep -rln "LruCache\|removeEldestEntry\|Collections.synchronizedMap" vertx-core/src/main/java | head; echo "---VERSION---"; grep -m1 "<versi  …(+132 more chars))
  ↳ *result:* vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java
---VERSION---
    <version>12</version>
**→ Bash**(command=git log --oneline -5; echo "---"; grep -rn "isSni\|setSni\|sni" vertx-core/src/main/java/io/vertx/core/net/ServerSSLOptions.java 2>/dev/null  …(+177 more chars))
  ↳ *result:* 5b230c7 baseline
---
vertx-core/src/main/java/io/vertx/core/net/ServerSSLOptions.java:41:  private boolean sni;
vertx-core/src/main/java/io/vertx/core/net/ServerSSLOptions.java:58:    sni = other.sni;
vertx-core/src/main/java/io/vertx/core/net/ServerSSLOptions.java:75:    this.sni = DEFAULT_SNI;
vertx-core/src/main/java/io/vertx/core/net/ServerSSLO  …(+347 more chars)
**Claude:** Let me check whether `SslContextProvider` is constructed anywhere else (e.g., tests) before changing its constructor signature.

**→ Bash**(command=grep -rn "new SslContextProvider(" vertx-core/src/ 2>/dev/null)
  ↳ *result:* vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java:161:    return new SslContextProvider(
**Claude:** Now I understand the vulnerability clearly. The SNI server-name → `SslContext` caches (`sslContextMaps`) in `SslContextProvider` are unbounded `ConcurrentHashMap`s keyed by the TLS SNI server name, which is attacker-controlled during the handshake. A malicious peer sending many distinct server names causes unbounded allocation of `SslContext` objects (native memory) that are never evicted — a memory-exhaustion DoS (CWE-770).

The remediation: bound these caches with LRU eviction, using a limit propagated from `SslContextManager` (which already carries `cacheMaxSize`, default 256). Caching behavior is preserved; only the retained-entry count is capped.

Let me apply the fix to `SslContextManager` first.

**→ Edit**(replace_all=false, file_path=/work/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java, old_string=  private final Supplier<SslContextFactory> supplier;
  private final boolean useWorkerPool;
  private final Map<ConfigKey, Future<Config>>   …(+414 more chars), new_string=  private final Supplier<SslContextFactory> supplier;
  private final boolean useWorkerPool;
  private final int sniContextMapMaxSize;
  pri  …(+502 more chars))
  ↳ *result:* The file /work/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java has been updated successfully. (file state is current in your context — no need to Read it back)
**→ Edit**(replace_all=false, file_path=/work/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java, old_string=      config.trustManagerFactory,
      config.trustManagerMapper,
      config.crls,
      supplier);
  }, new_string=      config.trustManagerFactory,
      config.trustManagerMapper,
      config.crls,
      supplier,
      sniContextMapMaxSize);
  })
  ↳ *result:* The file /work/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now update `SslContextProvider`: add the max-size parameter/field, bound the SNI caches, and add a bounded LRU cache class.

**→ Edit**(replace_all=false, file_path=/work/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java, old_string=  private final SslContext[] sslContexts = new SslContext[2];
  private final Map<String, SslContext>[] sslContextMaps = new Map[]{
    new   …(+822 more chars), new_string=  private final SslContext[] sslContexts = new SslContext[2];
  private final Map<String, SslContext>[] sslContextMaps;

  public SslContext  …(+802 more chars))
  ↳ *result:* The file /work/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java has been updated successfully. (file state is current in your context — no need to Read it back)
**→ Edit**(replace_all=false, file_path=/work/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java, old_string=    this.keyManagerFactoryMapper = keyManagerFactoryMapper;
    this.trustManagerMapper = trustManagerMapper;
    this.crls = crls;
  }, new_string=    this.keyManagerFactoryMapper = keyManagerFactoryMapper;
    this.trustManagerMapper = trustManagerMapper;
    this.crls = crls;
    // B  …(+460 more chars))
  ↳ *result:* The file /work/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now add the thread-safe bounded cache class. Let me add it near the end of the class:

**→ Edit**(replace_all=false, file_path=/work/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java, old_string=    if (serverName != null) {
      SSLParameters sslParameters = engine.getSSLParameters();
      sslParameters.setServerNames(Collections.  …(+102 more chars), new_string=    if (serverName != null) {
      SSLParameters sslParameters = engine.getSSLParameters();
      sslParameters.setServerNames(Collections.  …(+1089 more chars))
  ↳ *result:* The file /work/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now remove the now-unused `ConcurrentHashMap` import:

**→ Edit**(replace_all=false, file_path=/work/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java, old_string=import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;, new_string=import java.util.*;
import java.util.concurrent.Executor;)
  ↳ *result:* The file /work/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Let me verify the changes compile. I'll attempt a targeted compile of the module.

**→ Bash**(command=timeout 590 mvn -q -pl vertx-core compile -o 2>&1 | tail -30)
  ↳ *result:* [ERROR] [ERROR] Some problems were encountered while processing the POMs:
[FATAL] Non-resolvable parent POM for io.vertx:vertx-core-aggregator:5.0.12-SNAPSHOT: The following artifacts could not be resolved: io.vertx:vertx5-parent:pom:12 (absent): Cannot access central (https://repo.maven.apache.org/maven2) in offline mode and the artifact io.vertx:  …(+1189 more chars)
**Claude:** Maven can't build offline (missing parent POM in the sandbox). Let me do a careful manual review of the final state of both files instead.

**→ Read**(file_path=/work/vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextProvider.java, offset=54, limit=40)
  ↳ *result:* 54	  private final SslContext[] sslContexts = new SslContext[2];
55	  private final Map<String, SslContext>[] sslContextMaps;
56	
57	  public SslContextProvider(boolean useWorkerPool,
58	                            ClientAuth clientAuth,
59	                            String endpointIdentificationAlgorithm,
60	                            List<Strin  …(+1827 more chars)
**Claude:** The changes look consistent. Let me confirm there are no test-side constructions of `SslContextProvider` that would break with the new parameter, and verify the final `SslContextManager` build call.

**→ Bash**(command=grep -rn "new SslContextProvider(" vertx-core/ 2>/dev/null; echo "---manager build call---"; sed -n '161,176p' /work/vertx-core/src/main/jav  …(+51 more chars))
  ↳ *result:* vertx-core/src/main/java/io/vertx/core/internal/tls/SslContextManager.java:163:    return new SslContextProvider(
---manager build call---
        " verification algorithm");
    }
    return new SslContextProvider(
      useWorkerPool,
      clientAuth,
      hostnameVerificationAlgorithm,
      applicationProtocols,
      sslOptions.getEnabledCip  …(+268 more chars)
**Claude:** The remediation is complete. Here's a summary of what I did.

## Vulnerability

**CWE-770: Allocation of Resources Without Limits or Throttling** in the TLS/SNI layer.

`SslContextProvider` cached one Netty `SslContext` per SNI server name in two **unbounded** `ConcurrentHashMap`s (`sslContextMaps`):

```java
private final Map<String, SslContext>[] sslContextMaps = new Map[]{
  new ConcurrentHashMap<>(), new ConcurrentHashMap<>()
};
...
return sslContextMaps[idx].computeIfAbsent(serverName, s -> createContext(...));
```

The `serverName` key comes from the TLS **SNI extension**, which is supplied by the remote peer during the handshake. A malicious client (server-side SNI) or malicious server (client-side) could present an unbounded stream of distinct server names, each allocating and permanently retaining an `SslContext` (heap + native memory) — a memory-exhaustion denial of service. `SslContextManager`'s existing `cacheMaxSize` (default 256) only bounded the *provider* maps, never these per-provider SNI caches.

## Fix

Bounded the SNI caches with LRU eviction, using the limit already carried by `SslContextManager`:

- **`SslContextManager`**: stored `cacheMaxSize` in a new `sniContextMapMaxSize` field and passed it into the `SslContextProvider` constructor.
- **`SslContextProvider`**: added the `sniContextMapMaxSize` parameter and replaced the unbounded `ConcurrentHashMap`s with a new `BoundedSslContextCache` — a `LinkedHashMap` that evicts the eldest entry past `maxSize`. Its `size()` and `computeIfAbsent()` are `synchronized` to preserve thread safety (the map is populated from worker threads via `serverNameMapping`) and compute-once-per-key semantics. Removed the now-unused `ConcurrentHashMap` import.

## Behavior preserved

Caching still works exactly as before for the common bounded set of server names; the only change is that retained contexts are capped (default 256 per map), so the resource allocation is now throttled. No public API or configuration behavior changed — the constructor extended is internal (`io.vertx.core.internal.tls`) with a single call site.

Note: I couldn't run a full Maven compile because the sandbox is offline and the parent POM (`vertx5-parent:12`) isn't cached, but the edits are localized and consistent with the single construction site.


---
**Final (success):** The remediation is complete. Here's a summary of what I did.

## Vulnerability

**CWE-770: Allocation of Resources Without Limits or Throttling** in the TLS/SNI layer.

`SslContextProvider` cached one Netty `SslContext` per SNI server name in two **unbounded** `ConcurrentHashMap`s (`sslContextMaps`):

```java
private final Map<String, SslContext>[] sslContextMaps = new Map[]{
  new ConcurrentHashMap<>(), new ConcurrentHashMap<>()
};
...
return sslContextMaps[idx].computeIfAbsent(serverName, s -> createContext(...));
```

The `serverName` key comes from the TLS **SNI extension**, which is supplied by the remote peer during the handshake. A malicious client (server-side SNI) or malicious server (client-side) could present an unbounded stream of distinct server names, each allocating and permanently retaining an `SslContext` (heap + native memory) — a memory-exhaustion denial of service. `SslContextManager`'s existing `cacheMaxSize` (default 256) only bounded the *provider* maps, never these per-provider SNI caches.

## Fix

Bounded the SNI caches with LRU eviction, using the limit already carried by `SslContextManager`:

- **`SslContextManager`**: stored `cacheMaxSize` in a new `sniContextMapMaxSize` field and passed it into the `SslContextProvider` constructor.
- **`SslContextProvider`**: added the `sniContextMapMaxSize` parameter and replaced the unbounded `ConcurrentHashMap`s with a new `BoundedSslContextCache` — a `LinkedHashMap` that evicts the eldest entry past `maxSize`. Its `size()` and `computeIfAbsent()` are `synchronized` to preserve thread safety (the map is populated from worker threads via `serverNameMapping`) and compute-once-per-key semantics. Removed the now-unused `ConcurrentHashMap` import.

## Behavior preserved

Caching still works exactly as before for the common bounded set of server names; the only change is that retained contexts are capped (default 256 per map), so the resource allocation is now throttled. No public API or configuration behavior changed — the constructor extended is internal (`io.vertx.core.internal.tls`) with a single call site.

Note: I couldn't run a full Maven compile because the sandbox is offline and the parent POM (`vertx5-parent:12`) isn't cached, but the edits are localized and consistent with the single construction site.

*turns 18 · cost $0.995*
