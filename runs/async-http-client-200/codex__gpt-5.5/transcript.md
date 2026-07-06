**Codex:** I’ll read the finding and inspect the referenced code paths first, then patch only the local source needed to remove the vulnerability.

**→ shell:** `/bin/bash -lc "sed -n '1,220p' FINDING.txt"`
```
Project: AsyncHttpClient/async-http-client
Vulnerability type: Information Exposure (CWE-200)

Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):

  client/src/main/java/org/asynchttpclient/netty/handler/intercept/Redirect30xInterceptor.java
    - lines 41-46
    - lines 113-119   in: public boolean exitAfterHandlingRedirect(Channel channel, NettyResponseFuture<?>
    - lines 209-216   in: private static HttpHeaders propagatedHeaders(Request request, Realm real  …(+9 more chars)
```
**→ shell:** `/bin/bash -lc 'pwd && rg --files'`
```
/work
pom.xml
mvnw.cmd
LICENSES/LICENSE.zstd-jni.txt
FINDING.txt
LICENSE.txt
README.md
mvnw
client/pom.xml
client/src/main/java/org/asynchttpclient/Request.java
client/src/main/java/org/asynchttpclient/AsyncCompletionHandler.java
client/src/main/java/org/asynchttpclient/SignatureCalculator.java
client/src/main/java/org/asynchttpclient/ws/WebSocketUtils.java
client/src/main/java/org/asynchttpclient/ws/WebSocketUpgradeHandler.java
client/src/main/java/org/asynchttpclient/ws/WebSocket.java
client/s  …(+24642 more chars)
```
**Codex:** The finding points at redirect handling, especially header propagation. I’m going to inspect that interceptor and nearby tests around redirect credential behavior before editing.

**→ shell:** `/bin/bash -lc "nl -ba client/src/main/java/org/asynchttpclient/netty/handler/intercept/Redirect30xInterceptor.java | sed -n '1,280p'"`
```
     1	/*
     2	 *    Copyright (c) 2015-2023 AsyncHttpClient Project. All rights reserved.
     3	 *
     4	 *    Licensed under the Apache License, Version 2.0 (the "License");
     5	 *    you may not use this file except in compliance with the License.
     6	 *    You may obtain a copy of the License at
     7	 *
     8	 *        http://www.apache.org/licenses/LICENSE-2.0
     9	 *
    10	 *    Unless required by applicable law or agreed to in writing, software
    11	 *    distributed und  …(+12077 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba client/src/test/java/org/asynchttpclient/RedirectCredentialSecurityTest.java | sed -n '1,260p'"`
```
     1	/*
     2	 *    Copyright (c) 2015-2026 AsyncHttpClient Project. All rights reserved.
     3	 *
     4	 *    Licensed under the Apache License, Version 2.0 (the "License");
     5	 *    you may not use this file except in compliance with the License.
     6	 *    You may obtain a copy of the License at
     7	 *
     8	 *        http://www.apache.org/licenses/LICENSE-2.0
     9	 *
    10	 *    Unless required by applicable law or agreed to in writing, software
    11	 *    distributed und  …(+13012 more chars)
```
**→ shell:** `/bin/bash -lc 'rg -n "propagatedHeaders|Authorization|Proxy-Authorization|redirect|Redirect30xInterceptor|strip" client/src/main/java client/src/test/java'`
```
client/src/main/java/org/asynchttpclient/Request.java:170:     * @return if this request is to follow redirects. Non null values means "override config value".
client/src/test/java/org/asynchttpclient/BasicHttpTest.java:809:                            // max redirect is 1, so second redirect will fail
client/src/test/java/org/asynchttpclient/Head302Test.java:80:                // This will cause an infinite loop, which will error out once the maximum amount of redirects is hit (default 5).
clien  …(+45384 more chars)
```
**Codex:** The current code already has some credential stripping logic, so I’m checking whether the base-origin comparison is precise enough and whether generated auth can still reappear through request/future realms.

**→ shell:** `/bin/bash -lc "nl -ba client/src/main/java/org/asynchttpclient/uri/Uri.java | sed -n '1,260p'"`
```
     1	/*
     2	 *    Copyright (c) 2014-2024 AsyncHttpClient Project. All rights reserved.
     3	 *
     4	 *    Licensed under the Apache License, Version 2.0 (the "License");
     5	 *    you may not use this file except in compliance with the License.
     6	 *    You may obtain a copy of the License at
     7	 *
     8	 *        http://www.apache.org/licenses/LICENSE-2.0
     9	 *
    10	 *    Unless required by applicable law or agreed to in writing, software
    11	 *    distributed und  …(+9179 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba client/src/main/java/org/asynchttpclient/netty/NettyResponseFuture.java | sed -n '1,220p' && nl -ba client/src/main/java/org/asynchttpclient/netty/NettyResponseFuture.java | sed   …(+14 more chars)`
```
     1	/*
     2	 *    Copyright (c) 2014-2024 AsyncHttpClient Project. All rights reserved.
     3	 *
     4	 *    Licensed under the Apache License, Version 2.0 (the "License");
     5	 *    you may not use this file except in compliance with the License.
     6	 *    You may obtain a copy of the License at
     7	 *
     8	 *        http://www.apache.org/licenses/LICENSE-2.0
     9	 *
    10	 *    Unless required by applicable law or agreed to in writing, software
    11	 *    distributed und  …(+14202 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba client/src/test/java/org/asynchttpclient/StripAuthorizationOnRedirectHttpTest.java | sed -n '1,140p'"`
```
     1	package org.asynchttpclient;
     2	
     3	import com.sun.net.httpserver.HttpExchange;
     4	import com.sun.net.httpserver.HttpHandler;
     5	import com.sun.net.httpserver.HttpServer;
     6	import org.junit.jupiter.api.AfterAll;
     7	import org.junit.jupiter.api.BeforeAll;
     8	import org.junit.jupiter.api.Test;
     9	
    10	import java.net.InetSocketAddress;
    11	import java.util.concurrent.TimeUnit;
    12	
    13	import static org.junit.jupiter.api.Assertions.assertEquals;
  …(+3823 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba client/src/test/java/org/asynchttpclient/RedirectCredentialSecurityTest.java | sed -n '256,460p'"`
```
   256	    /**
   257	     * Realm-based BASIC auth credentials must NOT be propagated on cross-domain redirects.
   258	     * This tests that the Realm object is cleared, preventing credential regeneration
   259	     * via NettyRequestFactory.
   260	     */
   261	    @Test
   262	    void crossDomainRedirectDoesNotPropagateRealm() throws Exception {
   263	        DefaultAsyncHttpClientConfig config = new DefaultAsyncHttpClientConfig.Builder()
   264	                .setFollowRedirect(true)  …(+8713 more chars)
```
**Codex:** The sharp remaining issue is `Proxy-Authorization`: it is a proxy credential and should not be copied into the redirected origin request even when the redirect stays on the same origin. I’m going to add a focused regression test for that and make the interceptor always drop it while preserving normal `Authorization` behavior for same-origin redirects.

**→ shell:** `/bin/bash -lc "nl -ba client/src/main/java/org/asynchttpclient/AsyncHttpClientConfig.java | sed -n '430,480p'"`
```
   430	
   431	    KeepAliveStrategy getKeepAliveStrategy();
   432	
   433	    boolean isValidateResponseHeaders();
   434	
   435	    boolean isAggregateWebSocketFrameFragments();
   436	
   437	    boolean isEnableWebSocketCompression();
   438	
   439	    boolean isTcpNoDelay();
   440	
   441	    boolean isSoReuseAddress();
   442	
   443	    boolean isSoKeepAlive();
   444	
   445	    int getSoLinger();
   446	
   447	    int getSoSndBuf();
   448	
   449	    int getSoRcvBuf();
   450	
     …(+1235 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba client/src/main/java/org/asynchttpclient/DefaultAsyncHttpClientConfig.java | sed -n '880,920p' && nl -ba client/src/main/java/org/asynchttpclient/DefaultAsyncHttpClientConfig.jav  …(+24 more chars)`
```
   880	        private final List<RequestFilter> requestFilters = new LinkedList<>();
   881	        private final List<ResponseFilter> responseFilters = new LinkedList<>();
   882	        private final List<IOExceptionFilter> ioExceptionFilters = new LinkedList<>();
   883	        // http
   884	        private boolean followRedirect = defaultFollowRedirect();
   885	        private int maxRedirects = defaultMaxRedirects();
   886	        private boolean strict302Handling = defaultStrict302Hand  …(+3275 more chars)
```
**→ shell:** `/bin/bash -lc 'rg -n "Proxy-Authorization" client/src/test/java client/src/main/java/org/asynchttpclient/netty/handler/intercept'`
```
client/src/test/java/org/asynchttpclient/ScramAuthTest.java:384:     * Uses Proxy-Authorization/Proxy-Authenticate headers and 407 status codes.
client/src/test/java/org/asynchttpclient/ScramAuthTest.java:396:            String authz = request.getHeader("Proxy-Authorization");
client/src/test/java/org/asynchttpclient/RedirectCredentialSecurityTest.java:222:     * Cross-domain redirect must strip Proxy-Authorization header too.
client/src/test/java/org/asynchttpclient/RedirectCredentialSecurityTe  …(+945 more chars)
```
**Codex:** I’m editing the redirect header propagation now: `Authorization` will still be conditional, but `Proxy-Authorization` will be treated as non-propagatable redirect state. I’ll add the same-origin regression test where the bug is easiest to observe.

**✎ files:** update `/work/client/src/main/java/org/asynchttpclient/netty/handler/intercept/Redirect30xInterceptor.java`

**Codex:** The production change is small and scoped. I’m adding the regression assertion so a future redirect refactor cannot reintroduce proxy credential forwarding.

**✎ files:** update `/work/client/src/test/java/org/asynchttpclient/StripAuthorizationOnRedirectHttpTest.java`

**Codex:** The code and regression test are in place. I’m running the redirect credential tests now, then I’ll inspect the diff for any accidental churn.

**→ shell:** `/bin/bash -lc 'git diff -- client/src/main/java/org/asynchttpclient/netty/handler/intercept/Redirect30xInterceptor.java client/src/test/java/org/asynchttpclient/StripAuthorizationOnRedirectHttpTest.ja  …(+3 more chars)`
```
diff --git a/client/src/main/java/org/asynchttpclient/netty/handler/intercept/Redirect30xInterceptor.java b/client/src/main/java/org/asynchttpclient/netty/handler/intercept/Redirect30xInterceptor.java
index 70cf6c1..308ab52 100644
--- a/client/src/main/java/org/asynchttpclient/netty/handler/intercept/Redirect30xInterceptor.java
+++ b/client/src/main/java/org/asynchttpclient/netty/handler/intercept/Redirect30xInterceptor.java
@@ -209,10 +209,11 @@ public class Redirect30xInterceptor {
             …(+3056 more chars)
```
**→ shell:** `/bin/bash -lc './mvnw -pl client -Dtest=StripAuthorizationOnRedirectHttpTest,RedirectCredentialSecurityTest test'`
```
Exception in thread "main" java.net.UnknownHostException: repo.maven.apache.org
	at java.base/sun.nio.ch.NioSocketImpl.connect(NioSocketImpl.java:567)
	at java.base/java.net.SocksSocketImpl.connect(SocksSocketImpl.java:327)
	at java.base/java.net.Socket.connect(Socket.java:751)
	at java.base/sun.security.ssl.SSLSocketImpl.connect(SSLSocketImpl.java:304)
	at java.base/sun.security.ssl.BaseSSLSocketImpl.connect(BaseSSLSocketImpl.java:181)
	at java.base/sun.net.NetworkClient.doConnect(NetworkClient  …(+1505 more chars)
```
**Codex:** The Maven wrapper could not download Maven because DNS resolution for `repo.maven.apache.org` failed in this environment. I’m checking whether a local Maven install or cached wrapper is available so I can still run the focused tests.

**→ shell:** `/bin/bash -lc 'command -v mvn || true'`
```
/usr/bin/mvn

```
**→ shell:** `/bin/bash -lc 'ls -la ~/.m2/wrapper/dists 2>/dev/null || true'`
```
total 12
drwxr-xr-x 3 root root 4096 Jun 30 18:58 .
drwxr-xr-x 3 root root 4096 Jun 30 18:58 ..
drwxr-xr-x 3 root root 4096 Jun 30 18:58 apache-maven-3.9.6-bin

```
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M client/src/main/java/org/asynchttpclient/netty/handler/intercept/Redirect30xInterceptor.java
 M client/src/test/java/org/asynchttpclient/StripAuthorizationOnRedirectHttpTest.java

```
**Codex:** A system Maven is installed, so I’m using that instead of the wrapper. If dependencies are already cached locally, this should verify the focused tests without network access.

**→ shell:** `/bin/bash -lc 'mvn -pl client -Dtest=StripAuthorizationOnRedirectHttpTest,RedirectCredentialSecurityTest test'`
```
[INFO] Scanning for projects...
Downloading from central: https://repo.maven.apache.org/maven2/org/sonatype/central/central-publishing-maven-plugin/0.10.0/central-publishing-maven-plugin-0.10.0.pom
Downloading from central: https://repo.maven.apache.org/maven2/org/junit/junit-bom/6.0.3/junit-bom-6.0.3.pom
[ERROR] [ERROR] Some problems were encountered while processing the POMs:
[ERROR] Unresolveable build extension: Plugin org.sonatype.central:central-publishing-maven-plugin:0.10.0 or one of its  …(+1782 more chars)
```
**Codex:** Both Maven paths are blocked by missing remote artifacts because DNS resolution to Maven Central fails. I’m doing a final local diff/status check and will call out the test limitation explicitly.

**→ shell:** `/bin/bash -lc 'git diff --stat && git diff --check'`
```
 .../handler/intercept/Redirect30xInterceptor.java      |  5 +++--
 .../StripAuthorizationOnRedirectHttpTest.java          | 18 ++++++++++++++++++
 2 files changed, 21 insertions(+), 2 deletions(-)

```
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M client/src/main/java/org/asynchttpclient/netty/handler/intercept/Redirect30xInterceptor.java
 M client/src/test/java/org/asynchttpclient/StripAuthorizationOnRedirectHttpTest.java

```
**Codex:** `git diff --check` reported no whitespace issues. The remaining changed files are only the interceptor and its focused redirect test.

**Codex:** Remediated the redirect credential exposure.

Changed [Redirect30xInterceptor.java](/work/client/src/main/java/org/asynchttpclient/netty/handler/intercept/Redirect30xInterceptor.java:203) so redirected requests always remove `Proxy-Authorization`, while preserving existing conditional behavior for `Authorization`.

Added a regression test in [StripAuthorizationOnRedirectHttpTest.java](/work/client/src/test/java/org/asynchttpclient/StripAuthorizationOnRedirectHttpTest.java:99) to verify `Proxy-Authorization` is not propagated even on same-origin redirects.

Verification:
`git diff --check` passed.

I could not run the Maven tests because both `./mvnw` and system `mvn` failed resolving Maven Central artifacts due `Unknown host repo.maven.apache.org`.


---
*tokens — input 428323 (cached 348288), output 3384, reasoning 883*
