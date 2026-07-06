# Security finding

> A code-security scan flagged the vulnerability below. No remediation is included; produce the fix yourself.

**Type:** CWE-288 — CWE-288
**Project:** `apache/camel`
**Primary location:** `components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/BasicAuthenticationConfigurer.java`
**Other files possibly involved:** `components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/JWTAuthenticationConfigurer.java`, `components/camel-platform-http-main/src/main/java/org/apache/camel/component/platform/http/main/authentication/MainAuthenticationConfigurer.java`

## Details

When authentication is enabled on the Apache Camel embedded HTTP server or embedded management server (camel-platform-http-main) and a non-root context path such as /api or /admin is configured via camel.server.path or camel.management.path, the BasicAuthenticationConfigurer and JWTAuthenticationConfigurer classes derive the authentication path from properties.getPath() when camel.server.authenticationPath / camel.management.authenticationPath is not explicitly set. Combined with the Vert.x sub-router mounting model - the sub-router is mounted at _path_* and the authentication handler is registered inside the sub-router at the resolved path - this causes the authentication handler to match only the exact configured context path, not its subpaths. Unauthenticated requests to subpaths such as /api/_route_ or /admin/observe/info therefore reach protected business routes and management endpoints without being challenged for credentials. The /observe/info endpoint can disclose runtime metadata such as the user, working directory, home directory, process ID, JVM and operating system information.
