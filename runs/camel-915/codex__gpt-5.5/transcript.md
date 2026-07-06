**Codex:** I’ll inspect the finding and the nearby code first, then make the narrowest source change that removes the vulnerability without changing intended behavior.

**Codex:** The initial repository scan is taking longer than expected, likely because this is a large Camel checkout. I’m polling those commands and will switch to direct file reads if needed.

**→ shell:** `/bin/bash -lc "pwd && rg --files -g 'FINDING.txt' -g 'AGENTS.md'"`
```
AGENTS.md
FINDING.txt

```
**Codex:** Those broad commands are still not returning useful output, so I’m going straight to the vulnerability report and then the specific files it names.

**→ shell:** `/bin/bash -lc "sed -n '1,220p' FINDING.txt"`
```
Project: apache/camel
Vulnerability type: Object Attribute Modification (CWE-915)

Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):

  components/camel-coap/src/main/java/org/apache/camel/coap/CamelCoapResource.java
    - lines 22-27
    - lines 99-111   in: public void handleRequest(Exchange exchange) {

  components/camel-coap/src/main/java/org/apache/camel/coap/CoAPComponent.java
    - lines 32-37
    - lines 59-72
    - lines 156-165   in: private static   …(+310 more chars)
```
**→ shell:** `/bin/bash -lc 'git status --short'`
**→ shell:** `/bin/bash -lc 'find .. -name AGENTS.md -print'`
```
../seed/.tmp/plugins/plugins/build-web-apps/skills/react-best-practices/AGENTS.md
../seed/.tmp/plugins/plugins/build-web-apps/skills/supabase-best-practices/AGENTS.md
../seed/.tmp/plugins/plugins/zoom/AGENTS.md
../work/AGENTS.md

```
**Codex:** The report points to `camel-coap` and object-attribute exposure around mutable CoAP objects. I’m reading those classes now to see exactly which references are being exposed or accepted.

**→ shell:** `/bin/bash -lc "nl -ba components/camel-coap/src/main/java/org/apache/camel/coap/CamelCoapResource.java | sed -n '1,170p'"`
```
     1	/*
     2	 * Licensed to the Apache Software Foundation (ASF) under one or more
     3	 * contributor license agreements.  See the NOTICE file distributed with
     4	 * this work for additional information regarding copyright ownership.
     5	 * The ASF licenses this file to You under the Apache License, Version 2.0
     6	 * (the "License"); you may not use this file except in compliance with
     7	 * the License.  You may obtain a copy of the License at
     8	 *
     9	 *      http:  …(+7370 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba components/camel-coap/src/main/java/org/apache/camel/coap/CoAPEndpoint.java | sed -n '1,340p'"`
```
     1	/*
     2	 * Licensed to the Apache Software Foundation (ASF) under one or more
     3	 * contributor license agreements.  See the NOTICE file distributed with
     4	 * this work for additional information regarding copyright ownership.
     5	 * The ASF licenses this file to You under the Apache License, Version 2.0
     6	 * (the "License"); you may not use this file except in compliance with
     7	 * the License.  You may obtain a copy of the License at
     8	 *
     9	 *      http:  …(+14101 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba components/camel-coap/src/main/java/org/apache/camel/coap/CoAPComponent.java | sed -n '1,230p'"`
```
     1	/*
     2	 * Licensed to the Apache Software Foundation (ASF) under one or more
     3	 * contributor license agreements.  See the NOTICE file distributed with
     4	 * this work for additional information regarding copyright ownership.
     5	 * The ASF licenses this file to You under the Apache License, Version 2.0
     6	 * (the "License"); you may not use this file except in compliance with
     7	 * the License.  You may obtain a copy of the License at
     8	 *
     9	 *      http:  …(+10396 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba components/camel-coap/src/main/java/org/apache/camel/coap/CoAPEndpoint.java | sed -n '340,760p'"`
```
   340	    /**
   341	     * Set the configured public key for use with Raw Public Key.
   342	     */
   343	    public void setPublicKey(PublicKey publicKey) {
   344	        this.publicKey = publicKey;
   345	    }
   346	
   347	    /**
   348	     * Gets the cipherSuites String. This is a comma separated String of ciphersuites to configure. If it is not
   349	     * specified, then it falls back to getting the ciphersuites from the sslContextParameters object.
   350	     */
   351	    pub  …(+12895 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"getClient\\(|setClient\\(|CoapClient|createDTLSConnector|setETag|getPayload\\(|getUriQuery\\(|getUriPath\\(\" components/camel-coap/src -S"`
```
components/camel-coap/src/main/java/org/apache/camel/coap/CamelCoapResource.java:103:            for (String s : options.getUriQuery()) {
components/camel-coap/src/main/java/org/apache/camel/coap/CamelCoapResource.java:117:            List<String> path = exchange.getRequest().getOptions().getUriPath();
components/camel-coap/src/main/java/org/apache/camel/coap/CamelCoapResource.java:137:            byte[] bytes = exchange.getRequest().getPayload();
components/camel-coap/src/main/java/org/apache/c  …(+13400 more chars)
```
**Codex:** The risky surface appears to be public endpoint/component binding of a mutable `CoapClient`, plus request query names being copied verbatim into Camel headers. I’m checking producer usage before deciding whether the fix should make the shared client internal-only, defensively copy request values, or both.

**→ shell:** `/bin/bash -lc "nl -ba components/camel-coap/src/main/java/org/apache/camel/coap/CoAPProducer.java | sed -n '1,180p'"`
```
     1	/*
     2	 * Licensed to the Apache Software Foundation (ASF) under one or more
     3	 * contributor license agreements.  See the NOTICE file distributed with
     4	 * this work for additional information regarding copyright ownership.
     5	 * The ASF licenses this file to You under the Apache License, Version 2.0
     6	 * (the "License"); you may not use this file except in compliance with
     7	 * the License.  You may obtain a copy of the License at
     8	 *
     9	 *      http:  …(+3939 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba components/camel-coap/src/main/java/org/apache/camel/coap/CoAPHelper.java | sed -n '1,130p'"`
```
     1	/*
     2	 * Licensed to the Apache Software Foundation (ASF) under one or more
     3	 * contributor license agreements.  See the NOTICE file distributed with
     4	 * this work for additional information regarding copyright ownership.
     5	 * The ASF licenses this file to You under the Apache License, Version 2.0
     6	 * (the "License"); you may not use this file except in compliance with
     7	 * the License.  You may obtain a copy of the License at
     8	 *
     9	 *      http:  …(+3480 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"skipRequestHeaders|HeaderFilter|setHeader\\(|getIn\\(\\).*Header|UriQuery|COAP_\" components/camel-coap/src/main/java components/camel-coap/src/test/java -S"`
```
components/camel-coap/src/test/java/org/apache/camel/coap/CoAPComponentTest.java:55:        mock.expectedHeaderReceived(CoAPConstants.COAP_RESPONSE_CODE, CoAP.ResponseCode.CONTENT.toString());
components/camel-coap/src/test/java/org/apache/camel/coap/CoAPComponentTest.java:67:        mock.expectedHeaderReceived(CoAPConstants.COAP_RESPONSE_CODE, CoAP.ResponseCode.CONTENT.toString());
components/camel-coap/src/main/java/org/apache/camel/coap/CamelCoapResource.java:103:            for (String s : o  …(+7796 more chars)
```
**Codex:** There are two concrete mutable-reference issues in the reported ranges: byte arrays are passed through by reference, and the mutable `CoapClient` is exposed through endpoint metadata/configurers. I’m going to patch those sources and keep the existing programmatic sharing behavior intact where possible.

**→ shell:** `/bin/bash -lc "nl -ba components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPComponentConfigurer.java | sed -n '1,130p'"`
```
     1	/* Generated by camel build tools - do NOT edit this file! */
     2	package org.apache.camel.coap;
     3	
     4	import javax.annotation.processing.Generated;
     5	import java.util.Map;
     6	
     7	import org.apache.camel.CamelContext;
     8	import org.apache.camel.spi.ExtendedPropertyConfigurerGetter;
     9	import org.apache.camel.spi.PropertyConfigurerGetter;
    10	import org.apache.camel.spi.ConfigurerStrategy;
    11	import org.apache.camel.spi.GeneratedPropertyConfigurer;
   …(+3269 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba components/camel-coap/src/main/java/org/apache/camel/coap/CoAPComponent.java | sed -n '230,300p'"`
```
   230	        // configure consumer properties
   231	        Consumer consumer = endpoint.createConsumer(processor);
   232	        if (config.getConsumerProperties() != null && !config.getConsumerProperties().isEmpty()) {
   233	            setProperties(camelContext, consumer, config.getConsumerProperties());
   234	        }
   235	        return consumer;
   236	    }
   237	
   238	    private static String doGetHost(RestConfiguration config) throws UnknownHostException {
   239	        S  …(+1876 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPEndpointConfigurer.java | sed -n '1,150p'"`
```
     1	/* Generated by camel build tools - do NOT edit this file! */
     2	package org.apache.camel.coap;
     3	
     4	import javax.annotation.processing.Generated;
     5	import java.util.Map;
     6	
     7	import org.apache.camel.CamelContext;
     8	import org.apache.camel.spi.ExtendedPropertyConfigurerGetter;
     9	import org.apache.camel.spi.PropertyConfigurerGetter;
    10	import org.apache.camel.spi.ConfigurerStrategy;
    11	import org.apache.camel.spi.GeneratedPropertyConfigurer;
   …(+8389 more chars)
```
**Codex:** Before editing, I’m narrowing the header filtering to Camel CoAP internal headers so ordinary URI query parameters still arrive as route headers, which existing REST tests depend on. The shared client setter remains available for Java configuration, but I’ll remove it from URI/property binding metadata.

**→ shell:** `/bin/bash -lc "nl -ba components/camel-coap/src/main/java/org/apache/camel/coap/CoAPConstants.java | sed -n '1,100p'"`
```
     1	/*
     2	 * Licensed to the Apache Software Foundation (ASF) under one or more
     3	 * contributor license agreements.  See the NOTICE file distributed with
     4	 * this work for additional information regarding copyright ownership.
     5	 * The ASF licenses this file to You under the Apache License, Version 2.0
     6	 * (the "License"); you may not use this file except in compliance with
     7	 * the License.  You may obtain a copy of the License at
     8	 *
     9	 *      http:  …(+2253 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n '\"client\"|client' components/camel-coap/src/main/docs components/camel-coap/src/generated/resources/META-INF/org/apache/camel/coap -S"`
```
components/camel-coap/src/main/docs/coap-component.adoc:262:# On the client side used to select the default cipher-suites, on the
components/camel-coap/src/main/docs/coap-component.adoc:263:# server side to negotiate the client's certificate.
components/camel-coap/src/main/docs/coap-component.adoc:415:# [CLIENT_ONLY, SERVER_ONLY, BOTH].
components/camel-coap/src/main/docs/coap-component.adoc:449:# DTLS truncate client certificate path.
components/camel-coap/src/main/docs/coap-component.adoc:451:  …(+13203 more chars)
```
**Codex:** I’m applying the source patch now: remove generated binding for `client`, prevent external CoAP query strings from setting Camel’s internal CoAP headers, and copy byte arrays at the component boundary.

**✎ files:** update `/work/components/camel-coap/src/main/java/org/apache/camel/coap/CamelCoapResource.java`

**Codex:** The request-boundary patch is in place. Next I’m removing the mutable `CoapClient` from URI/component property binding while leaving the Java setters available for existing programmatic users.

**✎ files:** update `/work/components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPComponentConfigurer.java`, update `/work/components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPEndpointConfigurer.java`, update `/work/components/camel-coap/src/main/java/org/apache/camel/coap/CoAPComponent.java`, update `/work/components/camel-coap/src/main/java/org/apache/camel/coap/CoAPEndpoint.java`

**Codex:** The Java configurers no longer accept `client` as a bound option. I’m checking generated descriptors and tests so the checked-in metadata stays consistent with the source annotations.

**→ shell:** `/bin/bash -lc "rg -n '\"client\"|Client|shared client|client for the producers' components/camel-coap/src/generated/resources/META-INF/org/apache/camel/coap components/camel-coap/src/main/docs/coap-co  …(+16 more chars)`
```
components/camel-coap/src/generated/resources/META-INF/org/apache/camel/coap/coap+tcp.json:31:    "client": { "index": 3, "kind": "property", "displayName": "Client", "group": "producer (advanced)", "label": "producer,advanced", "required": false, "type": "object", "javaType": "org.eclipse.californium.core.CoapClient", "deprecated": false, "autowired": false, "secret": false, "description": "To use a shared client for the producers" },
components/camel-coap/src/generated/resources/META-INF/org/a  …(+8980 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n 'client' components/camel-coap/src/test/java/org/apache/camel/coap -S"`
```
components/camel-coap/src/test/java/org/apache/camel/coap/CoAPComponentTest.java:24:import org.eclipse.californium.core.CoapClient;
components/camel-coap/src/test/java/org/apache/camel/coap/CoAPComponentTest.java:46:        CoapClient client = createClient("/TestResource");
components/camel-coap/src/test/java/org/apache/camel/coap/CoAPComponentTest.java:47:        CoapResponse response = client.post("Camel", MediaTypeRegistry.TEXT_PLAIN);
components/camel-coap/src/test/java/org/apache/camel/coap  …(+26493 more chars)
```
**→ shell:** `/bin/bash -lc 'git diff -- components/camel-coap/src/main/java/org/apache/camel/coap/CamelCoapResource.java components/camel-coap/src/main/java/org/apache/camel/coap/CoAPComponent.java components/came  …(+244 more chars)`
```
diff --git a/components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPComponentConfigurer.java b/components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPComponentConfigurer.java
index aa4a8a79..4ab0af19 100644
--- a/components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPComponentConfigurer.java
+++ b/components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPComponentConfigurer.java
@@ -27,7 +27,6 @@ public class CoAPComponentConfigurer extends PropertyCo  …(+7775 more chars)
```
**Codex:** The checked-in JSON descriptors still list `client`, so I’m updating those generated metadata files as well. This keeps the runtime configurers and catalog metadata aligned.

**→ shell:** `/bin/bash -lc "sed -n '1,75p' components/camel-coap/src/generated/resources/META-INF/org/apache/camel/coap/coap.json"`
```
{
  "component": {
    "kind": "component",
    "name": "coap",
    "title": "CoAP",
    "description": "Send and receive messages to\/from CoAP (Constrained Application Protocol) capable devices.",
    "deprecated": false,
    "firstVersion": "2.16.0",
    "label": "iot",
    "javaType": "org.apache.camel.coap.CoAPComponent",
    "supportLevel": "Stable",
    "groupId": "org.apache.camel",
    "artifactId": "camel-coap",
    "version": "4.19.0-SNAPSHOT",
    "scheme": "coap",
    "extendsScheme  …(+15232 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,75p' components/camel-coap/src/generated/resources/META-INF/org/apache/camel/coap/coaps.json"`
```
{
  "component": {
    "kind": "component",
    "name": "coaps",
    "title": "CoAP (Secure)",
    "description": "Send and receive messages to\/from CoAP (Constrained Application Protocol) capable devices.",
    "deprecated": false,
    "firstVersion": "2.16.0",
    "label": "iot",
    "javaType": "org.apache.camel.coap.CoAPComponent",
    "supportLevel": "Stable",
    "groupId": "org.apache.camel",
    "artifactId": "camel-coap",
    "version": "4.19.0-SNAPSHOT",
    "scheme": "coaps",
    "ex  …(+15244 more chars)
```
**Codex:** I’m removing only the `client` entries from each CoAP scheme descriptor. The remaining option indices can stay as generated metadata; Camel descriptors commonly preserve generated indices without requiring compaction.

**✎ files:** update `/work/components/camel-coap/src/generated/resources/META-INF/org/apache/camel/coap/coap+tcp.json`, update `/work/components/camel-coap/src/generated/resources/META-INF/org/apache/camel/coap/coap.json`, update `/work/components/camel-coap/src/generated/resources/META-INF/org/apache/camel/coap/coaps+tcp.json`, update `/work/components/camel-coap/src/generated/resources/META-INF/org/apache/camel/coap/coaps.json`

**Codex:** With metadata aligned, I’m adding a focused test for the request query hardening so the vulnerable path is covered directly.

**→ shell:** `/bin/bash -lc "nl -ba components/camel-coap/src/test/java/org/apache/camel/coap/CoAPComponentTest.java | sed -n '1,140p'"`
```
     1	/*
     2	 * Licensed to the Apache Software Foundation (ASF) under one or more
     3	 * contributor license agreements.  See the NOTICE file distributed with
     4	 * this work for additional information regarding copyright ownership.
     5	 * The ASF licenses this file to You under the Apache License, Version 2.0
     6	 * (the "License"); you may not use this file except in compliance with
     7	 * the License.  You may obtain a copy of the License at
     8	 *
     9	 *      http:  …(+3988 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba components/camel-coap/src/test/java/org/apache/camel/coap/CoAPTestSupport.java | sed -n '1,100p'"`
```
     1	/*
     2	 * Licensed to the Apache Software Foundation (ASF) under one or more
     3	 * contributor license agreements.  See the NOTICE file distributed with
     4	 * this work for additional information regarding copyright ownership.
     5	 * The ASF licenses this file to You under the Apache License, Version 2.0
     6	 * (the "License"); you may not use this file except in compliance with
     7	 * the License.  You may obtain a copy of the License at
     8	 *
     9	 *      http:  …(+1535 more chars)
```
**✎ files:** update `/work/components/camel-coap/src/test/java/org/apache/camel/coap/CoAPComponentTest.java`

**Codex:** The focused test is added. I’m stopping the earlier broad scans that were still running, then I’ll run the `camel-coap` module tests.

**Codex:** The stale scans are stopped. I’m running the CoAP module test class now to catch compile issues and the new regression test.

**→ shell:** `/bin/bash -lc 'mvn -pl components/camel-coap -Dtest=CoAPComponentTest test'`
```
Downloading from central: https://repo.maven.apache.org/maven2/org/l2x6/cq/cq-alias-fastinstall-quickly-extension/4.21.0/cq-alias-fastinstall-quickly-extension-4.21.0.pom
[ERROR] Error executing Maven.
[ERROR] Extension org.l2x6.cq:cq-alias-fastinstall-quickly-extension:4.21.0 or one of its dependencies could not be resolved: Plugin org.l2x6.cq:cq-alias-fastinstall-quickly-extension:4.21.0 or one of its dependencies could not be resolved:
	Failed to read artifact descriptor for org.l2x6.cq:cq-al  …(+283 more chars)
```
**Codex:** The test command failed before compilation because Maven could not resolve the workspace’s configured build extension from Central. I’m checking the Maven extension setup to see if there’s a local toggle for this repo.

**→ shell:** `/bin/bash -lc "sed -n '1,160p' .mvn/extensions.xml"`
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
        <artifactId>develocity-maven-extension</artif  …(+248 more chars)
```
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
**→ shell:** `/bin/bash -lc "sed -n '1,160p' .mvn/maven.config"`
```
-Daether.remoteRepositoryFilter.groupId=true
-Daether.remoteRepositoryFilter.groupId.basedir=${session.rootDirectory}/.mvn/rrf/

```
**Codex:** The failure is tied to root `.mvn/extensions.xml`. I’m trying the module build from the component directory so Maven does not load the root extension file, while still using the module’s parent POM chain.

**→ shell:** `/bin/bash -lc 'mvn -Dtest=CoAPComponentTest test'`
```
Downloading from central: https://repo.maven.apache.org/maven2/org/l2x6/cq/cq-alias-fastinstall-quickly-extension/4.21.0/cq-alias-fastinstall-quickly-extension-4.21.0.pom
[ERROR] Error executing Maven.
[ERROR] Extension org.l2x6.cq:cq-alias-fastinstall-quickly-extension:4.21.0 or one of its dependencies could not be resolved: Plugin org.l2x6.cq:cq-alias-fastinstall-quickly-extension:4.21.0 or one of its dependencies could not be resolved:
	Failed to read artifact descriptor for org.l2x6.cq:cq-al  …(+283 more chars)
```
**Codex:** Maven still discovers the root extension from the module directory. I’m forcing Maven’s multi-module directory to `components/camel-coap` to see if that bypasses root extension discovery without changing repository files.

**→ shell:** `/bin/bash -lc 'mvn -Dmaven.multiModuleProjectDirectory=/work/components/camel-coap -Dtest=CoAPComponentTest test'`
```
Downloading from central: https://repo.maven.apache.org/maven2/org/l2x6/cq/cq-alias-fastinstall-quickly-extension/4.21.0/cq-alias-fastinstall-quickly-extension-4.21.0.pom
[ERROR] Error executing Maven.
[ERROR] Extension org.l2x6.cq:cq-alias-fastinstall-quickly-extension:4.21.0 or one of its dependencies could not be resolved: Plugin org.l2x6.cq:cq-alias-fastinstall-quickly-extension:4.21.0 or one of its dependencies could not be resolved:
	Failed to read artifact descriptor for org.l2x6.cq:cq-al  …(+283 more chars)
```
**Codex:** The Maven workaround did not bypass extension resolution, so I’m doing static checks now. I’m also checking Camel’s existing header filtering patterns to avoid inventing a component-specific rule if there is a standard reserved-header helper.

**→ shell:** `/bin/bash -lc "rg -n '\"client\"|setClient\\(property\\(|getClient\\(\\)|@UriParam\\(label = \"producer,advanced\"\\)\\s*\\n\\s*private CoapClient|@Metadata\\(label = \"producer,advanced\"\\)\\s*\\n\\  …(+97 more chars)`
```
rg: the literal "\n" is not allowed in a regex

Consider enabling multiline mode with the --multiline flag (or -U for short).
When multiline mode is enabled, new line characters can be matched.

```
**→ shell:** `/bin/bash -lc 'git diff --stat && git diff --check -- components/camel-coap'`
```
 .../apache/camel/coap/CoAPComponentConfigurer.java  |  4 ----
 .../apache/camel/coap/CoAPEndpointConfigurer.java   |  4 ----
 .../META-INF/org/apache/camel/coap/coap+tcp.json    |  2 --
 .../META-INF/org/apache/camel/coap/coap.json        |  2 --
 .../META-INF/org/apache/camel/coap/coaps+tcp.json   |  2 --
 .../META-INF/org/apache/camel/coap/coaps.json       |  2 --
 .../org/apache/camel/coap/CamelCoapResource.java    | 21 +++++++++++++++++----
 .../java/org/apache/camel/coap/CoAPComponent.java  …(+198 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"isCamel.*Header|HeaderFilterStrategy|skip.*Header|setQueryHeader|Exchange\\.[A-Z_]+\\.equals|startsWith\\(\\\"Camel\" components/camel-* core -S | head -200"`
```
components/camel-activemq/src/generated/resources/META-INF/org/apache/camel/component/activemq/activemq.json:128:    "headerFilterStrategy": { "index": 101, "kind": "property", "displayName": "Header Filter Strategy", "group": "filter", "label": "filter", "required": false, "type": "object", "javaType": "org.apache.camel.spi.HeaderFilterStrategy", "deprecated": false, "autowired": false, "secret": false, "description": "To use a custom org.apache.camel.spi.HeaderFilterStrategy to filter header t  …(+134190 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n '\"client\"|setClient\\(property\\(|org\\.eclipse\\.californium\\.core\\.CoapClient' components/camel-coap/src/generated components/camel-coap/src/main/java -S"`
```
components/camel-coap/src/main/java/org/apache/camel/coap/CoAPHelper.java:25:import org.eclipse.californium.core.CoapClient;
components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPEndpointUriFactory.java:33:        props.add("client");
components/camel-coap/src/main/java/org/apache/camel/coap/CoAPObserver.java:24:import org.eclipse.californium.core.CoapClient;
components/camel-coap/src/main/java/org/apache/camel/coap/CoAPComponent.java:46:import org.eclipse.californium.core.CoapClien  …(+257 more chars)
```
**→ shell:** `/bin/bash -lc 'rg -n "CAMEL_FILTER_STARTS_WITH|class DefaultHeaderFilterStrategy" core components/camel-support -S'`
```
core/camel-support/src/main/java/org/apache/camel/support/DefaultHeaderFilterStrategy.java:42:public class DefaultHeaderFilterStrategy implements HeaderFilterStrategy {
core/camel-support/src/main/java/org/apache/camel/support/DefaultHeaderFilterStrategy.java:47:     * @deprecated use {@link #CAMEL_FILTER_STARTS_WITH}
core/camel-support/src/main/java/org/apache/camel/support/DefaultHeaderFilterStrategy.java:55:    public static final String[] CAMEL_FILTER_STARTS_WITH = new String[] { "Camel", "c  …(+1122 more chars)
```
**Codex:** One generated URI factory still advertises `client`, and Camel’s standard header filter blocks names starting with `Camel`. I’m folding that standard rule into the CoAP query filter and updating the URI factory.

**→ shell:** `/bin/bash -lc "nl -ba components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPEndpointUriFactory.java | sed -n '1,100p'"`
```
     1	/* Generated by camel build tools - do NOT edit this file! */
     2	package org.apache.camel.coap;
     3	
     4	import javax.annotation.processing.Generated;
     5	import java.net.URISyntaxException;
     6	import java.util.Collections;
     7	import java.util.HashMap;
     8	import java.util.HashSet;
     9	import java.util.Map;
    10	import java.util.Set;
    11	
    12	import org.apache.camel.spi.EndpointUriFactory;
    13	
    14	/**
    15	 * Generated by camel build tools - do   …(+3222 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '42,70p' core/camel-support/src/main/java/org/apache/camel/support/DefaultHeaderFilterStrategy.java"`
```
public class DefaultHeaderFilterStrategy implements HeaderFilterStrategy {

    /**
     * A filter pattern that only accepts keys starting with <tt>Camel</tt>.
     *
     * @deprecated use {@link #CAMEL_FILTER_STARTS_WITH}
     */
    @Deprecated(since = "3.9.0")
    public static final Pattern CAMEL_FILTER_PATTERN = Pattern.compile("(?i)Camel[.a-zA-z0-9]*");

    /**
     * A filter pattern for keys starting with <tt>Camel</tt>, or <tt>camel</tt>.
     */
    public static final String[] CAME  …(+850 more chars)
```
**Codex:** I’m extending the query filter from CoAP-only names to Camel’s standard reserved-header prefix and `Content-Type`, because those are the exchange attributes an external query string should not be able to overwrite.

**✎ files:** update `/work/components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPEndpointUriFactory.java`, update `/work/components/camel-coap/src/main/java/org/apache/camel/coap/CamelCoapResource.java`

**Codex:** The URI factory is aligned now. I’m doing another local consistency pass for leftover generated `client` option entries and patch formatting.

**→ shell:** `/bin/bash -lc "rg -n '\"client\"|props\\.add\\(\"client\"\\)|setClient\\(property\\(|case \"client\":|client for the producers|@UriParam\\(label = \"producer,advanced\"\\)|@Metadata\\(label = \"produc  …(+149 more chars)`
```
components/camel-coap/src/main/java/org/apache/camel/coap/CoAPComponent.java:268:     * To use a shared client for the producers
components/camel-coap/src/main/java/org/apache/camel/coap/CoAPEndpoint.java:268:     * To use a shared client for the producers

```
**→ shell:** `/bin/bash -lc 'git diff --check -- components/camel-coap && git diff -- components/camel-coap/src/main/java/org/apache/camel/coap/CamelCoapResource.java components/camel-coap/src/generated/java/org/ap  …(+125 more chars)`
```
diff --git a/components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPEndpointUriFactory.java b/components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPEndpointUriFactory.java
index 38524be0..eeffda70 100644
--- a/components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPEndpointUriFactory.java
+++ b/components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPEndpointUriFactory.java
@@ -24,13 +24,12 @@ public class CoAPEndpointUriFactory extends org.apache.ca  …(+4864 more chars)
```
**Codex:** Static consistency checks no longer show bindable `client` metadata; only the JavaDoc on programmatic setters remains. I’m checking the full diff and then I’ll make one more test attempt only if a Maven path is available without the missing extension.

**→ shell:** `/bin/bash -lc "find ~/.m2/repository -path '*cq-alias-fastinstall-quickly-extension*4.21.0*' -print | head -50"`
```
/root/.m2/repository/org/l2x6/cq/cq-alias-fastinstall-quickly-extension/4.21.0
/root/.m2/repository/org/l2x6/cq/cq-alias-fastinstall-quickly-extension/4.21.0/cq-alias-fastinstall-quickly-extension-4.21.0.pom.lastUpdated

```
**→ shell:** `/bin/bash -lc "git diff -- components/camel-coap | sed -n '1,260p'"`
```
diff --git a/components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPComponentConfigurer.java b/components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPComponentConfigurer.java
index aa4a8a79..4ab0af19 100644
--- a/components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPComponentConfigurer.java
+++ b/components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPComponentConfigurer.java
@@ -27,7 +27,6 @@ public class CoAPComponentConfigurer extends PropertyCo  …(+39214 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n 'cq-alias-fastinstall|maven.*extension|extensions.xml|quickly' . -g '"'!**/target/**'"' -S | head -200"`
```
Dquickly
./docs/main/modules/contributing/pages/building.adoc:77:mvn clean install -Dquickly
./docs/user-manual/modules/ROOT/pages/java-dsl.adoc:85:you may want to quickly define a few routes.
./docs/user-manual/modules/ROOT/pages/camel-jbang.adoc:308:You can create Camel integrations that makes it possible for the user to quickly enter placeholder values from command prompt.
./docs/user-manual/modules/ROOT/pages/camel-jbang.adoc:366:You may want to use this for Camel prototypes where you want t  …(+6547 more chars)
```
**Codex:** The remaining diff includes a few generated-file trailing blank-line removals from patching. I’m putting those back to keep the generated files as mechanically close as possible.

**✎ files:** update `/work/components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPComponentConfigurer.java`, update `/work/components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPEndpointConfigurer.java`, update `/work/components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPEndpointUriFactory.java`

**Codex:** The generated-file whitespace is restored. I’m doing the final checks: no leftover bindable `client` entries, patch formatting, and a concise Maven failure capture for the verification note.

**→ shell:** `/bin/bash -lc "rg -n '\"client\"|props\\.add\\(\"client\"\\)|setClient\\(property\\(|case \"client\":|client for the producers|@UriParam\\(label = \"producer,advanced\"\\)|@Metadata\\(label = \"produc  …(+149 more chars)`
```
components/camel-coap/src/main/java/org/apache/camel/coap/CoAPComponent.java:268:     * To use a shared client for the producers
components/camel-coap/src/main/java/org/apache/camel/coap/CoAPEndpoint.java:268:     * To use a shared client for the producers

```
**→ shell:** `/bin/bash -lc 'git diff --check -- components/camel-coap'`
**→ shell:** `/bin/bash -lc 'mvn -pl components/camel-coap -Dtest=CoAPComponentTest test -e'`
```
Downloading from central: https://repo.maven.apache.org/maven2/org/l2x6/cq/cq-alias-fastinstall-quickly-extension/4.21.0/cq-alias-fastinstall-quickly-extension-4.21.0.pom
[ERROR] Error executing Maven.
org.apache.maven.cli.internal.ExtensionResolutionException: Extension org.l2x6.cq:cq-alias-fastinstall-quickly-extension:4.21.0 or one of its dependencies could not be resolved: Plugin org.l2x6.cq:cq-alias-fastinstall-quickly-extension:4.21.0 or one of its dependencies could not be resolved:
	Fail  …(+2971 more chars)
```
**Codex:** Maven still fails before project compilation because the core extension artifact cannot be resolved. I’m validating the modified JSON descriptors directly and collecting the final changed-file list.

**→ shell:** `/bin/bash -lc 'for f in components/camel-coap/src/generated/resources/META-INF/org/apache/camel/coap/coap.json components/camel-coap/src/generated/resources/META-INF/org/apache/camel/coap/coaps.json c  …(+216 more chars)`
```
/bin/bash: line 1: jq: command not found

```
**→ shell:** `/bin/bash -lc 'git diff --name-only -- components/camel-coap'`
```
components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPComponentConfigurer.java
components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPEndpointConfigurer.java
components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPEndpointUriFactory.java
components/camel-coap/src/generated/resources/META-INF/org/apache/camel/coap/coap+tcp.json
components/camel-coap/src/generated/resources/META-INF/org/apache/camel/coap/coap.json
components/camel-coap/src/generated/resources/ME  …(+447 more chars)
```
**→ shell:** `/bin/bash -lc 'git diff --stat -- components/camel-coap'`
```
 .../apache/camel/coap/CoAPComponentConfigurer.java   |  4 ----
 .../apache/camel/coap/CoAPEndpointConfigurer.java    |  4 ----
 .../apache/camel/coap/CoAPEndpointUriFactory.java    |  4 +---
 .../META-INF/org/apache/camel/coap/coap+tcp.json     |  2 --
 .../META-INF/org/apache/camel/coap/coap.json         |  2 --
 .../META-INF/org/apache/camel/coap/coaps+tcp.json    |  2 --
 .../META-INF/org/apache/camel/coap/coaps.json        |  2 --
 .../org/apache/camel/coap/CamelCoapResource.java     | 20 +  …(+271 more chars)
```
**Codex:** `jq` is not installed, so I’m using Ruby’s JSON parser for the descriptor validation instead. No source files are being changed by that check.

**→ shell:** `/bin/bash -lc "ruby -rjson -e 'ARGV.each { |f| JSON.parse(File.read(f)) }' components/camel-coap/src/generated/resources/META-INF/org/apache/camel/coap/coap.json components/camel-coap/src/generated/re  …(+233 more chars)`
```
/bin/bash: line 1: ruby: command not found

```
**Codex:** Ruby is not installed either; I’m checking whether Node is available for the same parse-only validation.

**→ shell:** `/bin/bash -lc "node -e 'const fs=require(\"fs\"); for (const f of process.argv.slice(1)) JSON.parse(fs.readFileSync(f, \"utf8\"));' components/camel-coap/src/generated/resources/META-INF/org/apache/ca  …(+290 more chars)`
**Codex:** The JSON descriptors parse successfully with Node. I’m doing one last status check to make sure there are no running commands and no unrelated surprises in the touched area.

**→ shell:** `/bin/bash -lc 'ps -o pid=,stat=,cmd= -p 34738,22400,55265,62467 2>/dev/null || true'`
**→ shell:** `/bin/bash -lc 'git status --short -- components/camel-coap FINDING.txt AGENTS.md'`
```
 M components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPComponentConfigurer.java
 M components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPEndpointConfigurer.java
 M components/camel-coap/src/generated/java/org/apache/camel/coap/CoAPEndpointUriFactory.java
 M components/camel-coap/src/generated/resources/META-INF/org/apache/camel/coap/coap+tcp.json
 M components/camel-coap/src/generated/resources/META-INF/org/apache/camel/coap/coap.json
 M components/camel-coap/src/gene  …(+480 more chars)
```
**Codex:** Implemented the CoAP vulnerability remediation.

Changed:
- Filter CoAP URI query parameters before turning them into Camel headers, blocking reserved `Camel*`/`camel*` headers and `Content-Type`.
- Defensively copy request payload and response ETag byte arrays at the CoAP boundary.
- Removed mutable `CoapClient` from endpoint/component URI/property binding metadata and generated configurers, while leaving Java setters for programmatic use.
- Added a regression test covering blocked internal-header injection.

Validation:
- `git diff --check -- components/camel-coap` passed.
- Generated CoAP JSON descriptors parse successfully via Node.
- `mvn -pl components/camel-coap -Dtest=CoAPComponentTest test` could not run because Maven fails before compilation resolving `org.l2x6.cq:cq-alias-fastinstall-quickly-extension:4.21.0` from the root `.mvn/extensions.xml`.


---
*tokens — input 2204565 (cached 2063232), output 12655, reasoning 2840*
