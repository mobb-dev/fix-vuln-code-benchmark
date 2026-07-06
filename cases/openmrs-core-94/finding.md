# Security finding

> A code-security scan flagged the vulnerability below. No remediation is included; produce the fix yourself.

**Type:** Code Injection — CWE-94
**Project:** `openmrs/openmrs-core`
**Primary location:** `api/src/main/java/org/openmrs/util/ConceptReferenceRangeUtility.java`

## Details

### Impact

The `ConceptReferenceRangeUtility.evaluateCriteria()` method in OpenMRS Core
evaluates database-stored criteria strings as Apache Velocity templates without any sandbox configuration. The `VelocityEngine` is initialized with only logging properties and no`SecureUberspector`, leaving the default `UberspectImpl` in place, which allows
unrestricted Java reflection through template expressions.

A user with the `Manage Concepts` privilege can store a malicious Velocity template
expression in a concept's reference range criteria field. This payload is then executed
automatically whenever a user or API call validates an observation against the affected
concept. The Velocity context exposes `$patient` (the `Person` / `Patient` object), `$obs` (the `Obs` object), and `$fn` (the `ConceptReferenceRangeUtility` instance with access to the full OpenMRS service layer).

**Persistent Remote Code Execution**: The payload persists in the concept_reference_range database table (VARCHAR 65535). A single compromised concept for a common clinical measurement executes the payload on every subsequent observation validation across all users, API clients, and integrations in the facility.

**Privilege Escalation**: The Manage Concepts privilege is a content-management function, defined as "Able to add/edit/delete concept entries", not an administrative privilege. Multiple non-admin staff per facility typically hold this privilege. The attacker escalates from concept dictionary management to arbitrary code execution as the Tomcat application server process.

**PHI Exfiltration**: The Velocity context objects directly expose patient data without requiring OS-level RCE.

### Resources
https://www.machinespirits.com/advisory/1e8430/
