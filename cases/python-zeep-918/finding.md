# Security finding

> A code-security scan flagged the vulnerability below. No remediation is included; produce the fix yourself.

**Type:** Server-Side Request Forgery — CWE-918
**Project:** `mvantellingen/python-zeep`
**Primary location:** `src/zeep/exceptions.py`
**Other files possibly involved:** `src/zeep/loader.py`, `src/zeep/settings.py`, `src/zeep/wsdl/wsdl.py`, `src/zeep/xsd/schema.py`

## Details

## Summary

When parsing a WSDL or XSD document, python-zeep follows transitive references — xsd:import, xsd:include, wsdl:import, and lxml entity/DTD resolution — and will fetch http/https URLs found in those references. The Settings.forbid_external option, intended to disable this transitive remote fetching, was defined but not wired to any logic from version 4.0.0 through 4.3.2 (a regression introduced when zeep moved off defusedxml in 4.0). As a result, setting `forbid_external=True` had no effect, and applications that processed untrusted or attacker-influenced WSDL/XSD documents could be coerced into making server-side requests to arbitrary URLs (SSRF).

## Impact

Server-Side Request Forgery (SSRF), CWE-918.

An attacker who can supply or influence the contents of a WSDL/XSD that an application loads with zeep can embed an import/include reference (e.g. `<xsd:import schemaLocation="http://169.254.169.254/...">`) pointing at an internal or otherwise sensitive endpoint. When zeep parses the document it transitively fetches that URL using the configured transport, causing the application to issue outbound requests to attacker-chosen destinations. This can be used to reach internal-only services, cloud metadata endpoints, or other hosts not directly reachable by the attacker, and may disclose response timing/behaviour.

Impacted users are those who:

- load WSDL/XSD documents that are untrusted or whose import targets an attacker can control, and/or
- relied on `forbid_external=True` as a security control — in 4.0.0–4.3.2 that setting silently did nothing, so the protection users believed they had was not in effect.

Note the default was (and remains) `forbid_external=False`, i.e. transitive remote fetching is permitted by default; the security defect is specifically that the opt-out control was non-functional.
