# Security finding

> A code-security scan flagged the vulnerability below. No remediation is included; produce the fix yourself.

**Type:** Object Attribute Modification — CWE-915
**Project:** `apache/camel`
**Primary location:** `components/camel-coap/src/main/java/org/apache/camel/coap/CamelCoapResource.java`
**Other files possibly involved:** `components/camel-coap/src/main/java/org/apache/camel/coap/CoAPComponent.java`, `components/camel-coap/src/main/java/org/apache/camel/coap/CoAPEndpoint.java`, `components/camel-coap/src/main/java/org/apache/camel/coap/CoAPHeaderFilterStrategy.java`

## Details

Apache Camel's camel-coap component is vulnerable to header injection because it maps CoAP request URI query parameters directly into Camel message headers without applying a HeaderFilterStrategy. An unauthenticated attacker can send a crafted CoAP request to inject arbitrary Camel internal headers into the exchange.

When a vulnerable route forwards that exchange to a header-sensitive downstream producer, the attacker may be able to control producer behavior. For example, in routes using camel-exec, injected headers can override the configured executable and arguments, which can result in arbitrary command execution with the privileges of the Camel process. Command output may be returned to the attacker in the CoAP response.
