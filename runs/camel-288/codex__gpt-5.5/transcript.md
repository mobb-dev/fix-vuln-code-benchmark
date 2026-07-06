**Codex:** I’ll inspect the finding and the affected source before editing, then run the narrowest relevant verification I can identify.

**→ shell:** `/bin/bash -lc "pwd && rg --files -g 'FINDING.txt' -g 'pom.xml'"`
```
FINDING.txt
dsl/camel-jbang/camel-jbang-plugin-test/pom.xml
test-infra/camel-test-infra-hashicorp-vault/pom.xml
dsl/camel-jbang/camel-launcher/pom.xml
test-infra/camel-test-infra-messaging-common/pom.xml
dsl/camel-jbang/camel-jbang-plugin-generate/pom.xml
test-infra/camel-test-infra-jetty/pom.xml
dsl/camel-jbang/camel-jbang-plugin-route-parser/pom.xml
dsl/camel-jbang/camel-jbang-mcp/pom.xml
test-infra/camel-test-infra-xmpp/pom.xml
dsl/camel-jbang/camel-jbang-main/pom.xml
test-infra/camel-test-in  …(+15846 more chars)
```
**→ shell:** `/bin/bash -lc 'git status --short'`
**Codex:** The repository is large enough that my first broad file listing was noisy, so I stopped it and will read the finding directly, then target only the mentioned files.

**→ shell:** `/bin/bash -lc "sed -n '1,220p' FINDING.txt"`
```
Project: apache/camel
Vulnerability type: Authentication Bypass Using an Alternate Path or Channel (CWE-288)

Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):

  components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/BasicAuthenticationConfigurer.java
    - lines 26-32
    - lines 35-46   in: public void configureAuthentication(
    - lines 64-75   in: public void configureAuthentication(

  components/c  …(+449 more chars)
```
**Codex:** The finding points to the platform-http-main authentication configurers. I’m reading those classes and nearby tests/usages to see how requests are authorized and where an alternate route can bypass checks.

**→ shell:** `/bin/bash -lc "sed -n '1,180p' components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/MainAuthenticationConfigurer.java"`
```
/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by   …(+981 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,220p' components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/JWTAuthenticationConfigurer.java"`
```
/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by   …(+4528 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,220p' components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/BasicAuthenticationConfigurer.java"`
```
/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by   …(+3902 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"MainAuthenticationConfigurer|BasicAuthenticationConfigurer|JWTAuthenticationConfigurer|configureAuthentication\\(\" components/camel-platform-http-main/src -S"`
```
components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/MainAuthenticationConfigurer.java:26:public interface MainAuthenticationConfigurer {
components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/MainAuthenticationConfigurer.java:28:    void configureAuthentication(AuthenticationConfig authenticationConfig, HttpServerConfigurationProperties properties);
components/camel-platform-http-ma  …(+4491 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,210p' components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/DefaultMainHttpServerFactory.java"`
```
/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by   …(+6096 more chars)
```
**→ shell:** `/bin/bash -lc 'rg -n "authenticationPath|basicPropertiesFile|jwtKeystore|platform-http-main|BasicAuth|JWTAuth|401|Authorization" components/camel-platform-http-main/src/test components/camel-platform-  …(+20 more chars)`
```
rg: components/camel-platform-http-main/src/it: No such file or directory (os error 2)
components/camel-platform-http-main/src/test/resources/log4j2.properties:19:appender.file.fileName = target/camel-platform-http-main-test.log
components/camel-platform-http-main/src/test/resources/incomplete-auth.properties:20:camel.server.authenticationPath=/*
components/camel-platform-http-main/src/test/resources/incomplete-auth.properties:21:camel.server.jwtKeystoreType=jks
components/camel-platform-http-ma  …(+3748 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,180p' components/camel-platform-http-main/src/test/java/org/apache/camel/component/platform/http/main/authentication/AuthenticationConfigurationMainHttpServerTest.java"`
```
/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by   …(+1363 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '180,380p' components/camel-platform-http-vertx/src/main/java/org/apache/camel/component/platform/http/vertx/VertxPlatformHttpServer.java"`
```
            if (vertx == null) {
                LOGGER.debug("Creating new Vert.x instance");
                vertx = createVertxInstance();
                localVertx = true;
            }
        }

        this.router = Router.router(vertx);
        this.subRouter = Router.router(vertx);

        if (configuration.getCors().isEnabled()) {
            subRouter.route().handler(createCorsHandler(configuration));
        }

        if (configuration.getSessionConfig().isEnabled()) {
             …(+6613 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,140p' components/camel-platform-http-vertx/src/main/java/org/apache/camel/component/platform/http/vertx/auth/AuthenticationConfig.java"`
```
/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by   …(+3002 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,140p' components/camel-platform-http-main/src/test/java/org/apache/camel/component/platform/http/main/authentication/BasicAuthenticationMainHttpServerTest.java && sed -n '1,12  …(+156 more chars)`
```
/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by   …(+5866 more chars)
```
**→ shell:** `/bin/bash -lc "find components/camel-platform-http-main/src/test/resources -maxdepth 1 -type f -print -exec sed -n '1,80p' {} \\;"`
```
components/camel-platform-http-main/src/test/resources/jwt-auth.properties
## ---------------------------------------------------------------------------
## Licensed to the Apache Software Foundation (ASF) under one or more
## contributor license agreements.  See the NOTICE file distributed with
## this work for additional information regarding copyright ownership.
## The ASF licenses this file to You under the Apache License, Version 2.0
## (the "License"); you may not use this file except in c  …(+8433 more chars)
```
**→ shell:** `/bin/bash -lc 'rg -n "authenticationPath|authentication path|authentication-path|Authentication Path" -S .'`
**→ shell:** `/bin/bash -lc "rg -n \"class HttpServerConfigurationProperties|interface HttpServerConfigurationProperties|authenticationPath|basicPropertiesFile\" core components dsl -g '*.java' -S"`
```
core/camel-main/src/main/java/org/apache/camel/main/HttpServerConfigurationProperties.java:27:public class HttpServerConfigurationProperties implements BootstrapCloseable {
core/camel-main/src/main/java/org/apache/camel/main/HttpServerConfigurationProperties.java:56:    private String authenticationPath;
core/camel-main/src/main/java/org/apache/camel/main/HttpServerConfigurationProperties.java:60:    private String basicPropertiesFile;
core/camel-main/src/main/java/org/apache/camel/main/HttpServ  …(+6280 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"class AuthenticationConfig|AuthenticationConfigEntry|getEntries\\(|setPath\\(|AuthenticationHandlerFactory|authenticationConfig\" components/camel-platform-http-main components/  …(+52 more chars)`
```
components/camel-platform-http-vertx/src/main/java/org/apache/camel/component/platform/http/vertx/VertxPlatformHttpServerConfiguration.java:50:    private AuthenticationConfig authenticationConfig = new AuthenticationConfig();
components/camel-platform-http-vertx/src/main/java/org/apache/camel/component/platform/http/vertx/VertxPlatformHttpServerConfiguration.java:89:    public void setPath(String path) {
components/camel-platform-http-vertx/src/main/java/org/apache/camel/component/platform/http  …(+32225 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '50,100p' core/camel-main/src/main/java/org/apache/camel/main/HttpManagementServerConfigurationProperties.java && sed -n '285,335p' core/camel-main/src/main/java/org/apache/camel  …(+55 more chars)`
```
    private boolean metricsEnabled;
    private boolean uploadEnabled;
    private String uploadSourceDir;
    private boolean downloadEnabled;
    private boolean sendEnabled;

    @Metadata(label = "security")
    private boolean useGlobalSslContextParameters;
    @Metadata(label = "security")
    private boolean authenticationEnabled;
    @Metadata(label = "security")
    private String authenticationPath;
    @Metadata(label = "security")
    private String authenticationRealm;
    @Metadata  …(+2339 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '40,95p' core/camel-main/src/main/java/org/apache/camel/main/HttpServerConfigurationProperties.java && sed -n '210,260p' core/camel-main/src/main/java/org/apache/camel/main/HttpS  …(+34 more chars)`
```
    private boolean staticEnabled;
    private String staticSourceDir;
    @Metadata(defaultValue = "/")
    private String staticContextPath = "/";
    @Metadata(label = "advanced", defaultValue = "true")
    private boolean fileUploadEnabled = true;
    @Metadata(label = "advanced")
    private String fileUploadDirectory;
    @Metadata(label = "advanced")
    private Long maxBodySize;

    @Metadata(label = "security")
    private boolean useGlobalSslContextParameters;
    @Metadata(label = "s  …(+2542 more chars)
```
**→ shell:** `/bin/bash -lc 'git status --short --untracked-files=no'`
**→ shell:** `/bin/bash -lc "find . -path '*/target' -prune -o -type f \\( -name '*.adoc' -o -name '*.json' -o -name '*.properties' \\) -print | xargs rg -n \"authenticationPath|authentication path\""`
```
./core/camel-main/src/generated/resources/META-INF/camel-main-configuration-metadata.json:198:    { "name": "camel.management.authenticationPath", "required": false, "description": "Set HTTP url path of embedded server that is protected by authentication configuration.", "sourceType": "org.apache.camel.main.HttpManagementServerConfigurationProperties", "type": "string", "javaType": "java.lang.String", "secret": false },
./core/camel-main/src/generated/resources/META-INF/camel-main-configuration-  …(+334 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,210p' components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/MainHttpServer.java"`
```
/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by   …(+7007 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,360p' components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/ManagementHttpServer.java"`
```
/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by   …(+11945 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"camel\\.server\\.path|camel\\.management\\.path|getPath\\(\\)|@Metadata\\(.*defaultValue = \\\"/\\\"\" core/camel-main/src/main/java/org/apache/camel/main/HttpServerConfiguratio  …(+118 more chars)`
```
core/camel-main/src/main/java/org/apache/camel/main/HttpManagementServerConfigurationProperties.java:37:    @Metadata(defaultValue = "/")
core/camel-main/src/main/java/org/apache/camel/main/HttpManagementServerConfigurationProperties.java:119:    public String getPath() {
core/camel-main/src/main/java/org/apache/camel/main/HttpServerConfigurationProperties.java:37:    @Metadata(defaultValue = "/")
core/camel-main/src/main/java/org/apache/camel/main/HttpServerConfigurationProperties.java:42:    @  …(+154 more chars)
```
**Codex:** The weak point is the auth handler is registered on a single Vert.x route path. For a non-wildcard base such as `/api`, descendants like `/api/foo` can be served by the HTTP server without hitting that auth handler, so I’m going to centralize path expansion and register both the exact path and its child wildcard where needed.

**Codex:** I’m about to edit the three flagged auth configurer files and add focused tests that assert non-wildcard authentication paths cover both the configured path and descendants for Basic and JWT.

**✎ files:** update `/work/components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/MainAuthenticationConfigurer.java`

**Codex:** The shared helper now expands paths once. I’m replacing the duplicated configurer code so Basic and JWT both use the same path handling.

**✎ files:** update `/work/components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/BasicAuthenticationConfigurer.java`

**Codex:** Basic auth now uses the common expansion. I’m applying the same change to JWT so both auth modes have identical coverage.

**✎ files:** update `/work/components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/JWTAuthenticationConfigurer.java`

**→ shell:** `/bin/bash -lc "sed -n '1,45p' core/camel-main/src/main/java/org/apache/camel/main/HttpServerConfigurationProperties.java && sed -n '1,42p' core/camel-main/src/main/java/org/apache/camel/main/HttpManag  …(+40 more chars)`
```
/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by   …(+2934 more chars)
```
**Codex:** I’m adding unit coverage at the configurer layer. That keeps the test fast and directly verifies the vulnerable mapping logic without needing to boot the full HTTP server.

**✎ files:** add `/work/components/camel-platform-http-main/src/test/java/org/apache/camel/component/platform/http/main/authentication/AuthenticationConfigurerPathTest.java`

**Codex:** The source and tests are in place. I’m running the targeted Maven test now; if it exposes a style or compile issue, I’ll correct it locally.

**→ shell:** `/bin/bash -lc 'mvn -pl components/camel-platform-http-main -Dtest=AuthenticationConfigurerPathTest test'`
```
Downloading from central: https://repo.maven.apache.org/maven2/org/l2x6/cq/cq-alias-fastinstall-quickly-extension/4.21.0/cq-alias-fastinstall-quickly-extension-4.21.0.pom
[ERROR] Error executing Maven.
[ERROR] Extension org.l2x6.cq:cq-alias-fastinstall-quickly-extension:4.21.0 or one of its dependencies could not be resolved: Plugin org.l2x6.cq:cq-alias-fastinstall-quickly-extension:4.21.0 or one of its dependencies could not be resolved:
	Failed to read artifact descriptor for org.l2x6.cq:cq-al  …(+283 more chars)
```
**Codex:** The targeted Maven run failed before compiling the module because Maven could not resolve the configured quick-build extension from Central. I’m checking the local Maven setup and will still run any feasible compile/test path after that.

**→ shell:** `/bin/bash -lc 'find .mvn -maxdepth 3 -type f -print'`
```
.mvn/wrapper/maven-wrapper.properties
.mvn/wrapper/maven-wrapper.jar
.mvn/maven.config
.mvn/rrf/groupId-B_shibboleth.txt
.mvn/rrf/groupId-atlassian.txt
.mvn/develocity.xml
.mvn/jvm.config
.mvn/extensions.xml

```
**→ shell:** `/bin/bash -lc 'git diff -- components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/BasicAuthenticationConfigurer.java components/camel-platform-h  …(+411 more chars)`
```
diff --git a/components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/BasicAuthenticationConfigurer.java b/components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/BasicAuthenticationConfigurer.java
index bef37925..6251ef8c 100644
--- a/components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/BasicAuthenticationConfigurer.java
+++ b/com  …(+15079 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,120p' .mvn/extensions.xml 2>/dev/null || true && sed -n '1,120p' .mvn/maven.config 2>/dev/null || true"`
```
<?xml version="1.0" encoding="UTF-8"?>
<extensions>
    <extension>
        <groupId>org.l2x6.cq</groupId>
        <artifactId>cq-alias-fastinstall-quickly-extension</artifactId>
        <version>4.21.0</version>
    </extension>
    <extension>
        <groupId>eu.maveniverse.maven.nisse</groupId>
        <artifactId>extension</artifactId>
        <version>0.7.0</version>
    </extension>
    <extension>
        <groupId>com.gradle</groupId>
        <artifactId>develocity-maven-extension</artif  …(+376 more chars)
```
**Codex:** The diff looks mechanically correct. Maven is blocked before project code loads by `.mvn/extensions.xml`; I’m checking whether the artifact is reachable or whether this environment’s Maven extension resolution is the blocker.

**→ shell:** `/bin/bash -lc "sed -n '1,220p' components/camel-platform-http-main/src/test/java/org/apache/camel/component/platform/http/main/authentication/AuthenticationConfigurerPathTest.java"`
```
/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by   …(+3801 more chars)
```
**→ shell:** `/bin/bash -lc 'curl -I --max-time 20 https://repo.maven.apache.org/maven2/org/l2x6/cq/cq-alias-fastinstall-quickly-extension/4.21.0/cq-alias-fastinstall-quickly-extension-4.21.0.pom'`
```
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
HTTP/1.1 403 blocked by egress allowlist
Server: BaseHTTP/0.6 Python/3.11.15
Date: Tue, 30 Jun 2026 19:28:08 GMT
Connection: close
Content-Type: text/html;charset=utf-8
Content-Length:   …(+52 more chars)
```
**→ shell:** `/bin/bash -lc 'git diff --check -- components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/BasicAuthenticationConfigurer.java components/camel-pl  …(+419 more chars)`
**Codex:** One more edge case is worth closing: an explicit child wildcard like `/secure/*` should also protect `/secure`, otherwise the base path remains an alternate unauthenticated path. I’m tightening that case while keeping the root wildcard as a single catch-all.

**✎ files:** update `/work/components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/MainAuthenticationConfigurer.java`

**Codex:** I’m updating the test expectations to cover that explicit child-wildcard case as well.

**✎ files:** update `/work/components/camel-platform-http-main/src/test/java/org/apache/camel/component/platform/http/main/authentication/AuthenticationConfigurerPathTest.java`

**Codex:** The local syntax check is clean so far. I’m trying Maven from the module directory next; that may avoid loading the root `.mvn/extensions.xml` that the network allowlist blocks.

**→ shell:** `/bin/bash -lc 'git diff --check -- components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/BasicAuthenticationConfigurer.java components/camel-pl  …(+419 more chars)`
**→ shell:** `/bin/bash -lc 'mvn -Dtest=AuthenticationConfigurerPathTest test'`
```
Downloading from central: https://repo.maven.apache.org/maven2/org/l2x6/cq/cq-alias-fastinstall-quickly-extension/4.21.0/cq-alias-fastinstall-quickly-extension-4.21.0.pom
[ERROR] Error executing Maven.
[ERROR] Extension org.l2x6.cq:cq-alias-fastinstall-quickly-extension:4.21.0 or one of its dependencies could not be resolved: Plugin org.l2x6.cq:cq-alias-fastinstall-quickly-extension:4.21.0 or one of its dependencies could not be resolved:
	Failed to read artifact descriptor for org.l2x6.cq:cq-al  …(+283 more chars)
```
**Codex:** Maven still loads the root extensions from the module directory, and the same egress block prevents resolution. I’m doing a final source review and checking the local repository/cache state so the verification note is precise.

**→ shell:** `/bin/bash -lc 'ls -R ~/.m2/repository/org/l2x6/cq/cq-alias-fastinstall-quickly-extension/4.21.0 2>/dev/null || true'`
```
/root/.m2/repository/org/l2x6/cq/cq-alias-fastinstall-quickly-extension/4.21.0:
cq-alias-fastinstall-quickly-extension-4.21.0.pom.lastUpdated

```
**→ shell:** `/bin/bash -lc 'git diff --stat -- components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/BasicAuthenticationConfigurer.java components/camel-pla  …(+727 more chars)`
```
 .../BasicAuthenticationConfigurer.java             | 60 +++++----------
 .../JWTAuthenticationConfigurer.java               | 87 ++++++++--------------
 .../MainAuthenticationConfigurer.java              | 41 ++++++++++
 3 files changed, 91 insertions(+), 97 deletions(-)
diff --git a/components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/MainAuthenticationConfigurer.java b/components/camel-platform-http-main/src/main/java/org/apache/camel/  …(+2970 more chars)
```
**→ shell:** `/bin/bash -lc 'git ls-files --others --exclude-standard components/camel-platform-http-main/src/test/java/org/apache/camel/component/platform/http/main/authentication/AuthenticationConfigurerPathTest.  …(+5 more chars)`
```
components/camel-platform-http-main/src/test/java/org/apache/camel/component/platform/http/main/authentication/AuthenticationConfigurerPathTest.java

```
**Codex:** The only cached copy of the blocked Maven extension is a `.lastUpdated` marker, so offline Maven cannot work here either. I’ll do one last status/diff check and then summarize the change and the verification blocker.

**→ shell:** `/bin/bash -lc 'git diff --no-index /dev/null components/camel-platform-http-main/src/test/java/org/apache/camel/component/platform/http/main/authentication/AuthenticationConfigurerPathTest.java'`
```
diff --git a/components/camel-platform-http-main/src/test/java/org/apache/camel/component/platform/http/main/authentication/AuthenticationConfigurerPathTest.java b/components/camel-platform-http-main/src/test/java/org/apache/camel/component/platform/http/main/authentication/AuthenticationConfigurerPathTest.java
new file mode 100644
index 00000000..d60da662
--- /dev/null
+++ b/components/camel-platform-http-main/src/test/java/org/apache/camel/component/platform/http/main/authentication/Authentica  …(+5099 more chars)
```
**→ shell:** `/bin/bash -lc 'git diff -- components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/BasicAuthenticationConfigurer.java components/camel-platform-h  …(+117 more chars)`
```
diff --git a/components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/BasicAuthenticationConfigurer.java b/components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/BasicAuthenticationConfigurer.java
index bef37925..6251ef8c 100644
--- a/components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/BasicAuthenticationConfigurer.java
+++ b/com  …(+12017 more chars)
```
**→ shell:** `/bin/bash -lc 'git status --short -- components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/BasicAuthenticationConfigurer.java components/camel-  …(+421 more chars)`
```
 M components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/BasicAuthenticationConfigurer.java
 M components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/JWTAuthenticationConfigurer.java
 M components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/MainAuthenticationConfigurer.java
?? components/camel-platform-http-main/src/test/java/org  …(+96 more chars)
```
**Codex:** Implemented the remediation in the platform HTTP main authentication configurers.

Changed:
- [MainAuthenticationConfigurer.java](/work/components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/MainAuthenticationConfigurer.java): centralizes auth path expansion so non-wildcard paths protect both the exact path and descendants, and `/secure/*` also protects `/secure`.
- [BasicAuthenticationConfigurer.java](/work/components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/BasicAuthenticationConfigurer.java) and [JWTAuthenticationConfigurer.java](/work/components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/JWTAuthenticationConfigurer.java): now use the shared secure path registration logic.
- Added [AuthenticationConfigurerPathTest.java](/work/components/camel-platform-http-main/src/test/java/org/apache/camel/component/platform/http/main/authentication/AuthenticationConfigurerPathTest.java) covering Basic, JWT, management paths, root wildcard, and child wildcard behavior.

Verification:
- `git diff --check` passed.
- Targeted Maven test could not run because Maven fails before project compilation while resolving `.mvn/extensions.xml`; the required `org.l2x6.cq:cq-alias-fastinstall-quickly-extension:4.21.0` artifact is blocked by the environment’s egress allowlist, and only a `.lastUpdated` marker exists locally.


---
*tokens — input 1108412 (cached 1001472), output 11073, reasoning 2557*
