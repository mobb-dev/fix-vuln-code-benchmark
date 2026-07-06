# Security finding

> **Source:** GitHub Security Advisory **GHSA-xq3r-2qv5-vqqm** / CVE-2026-23734 (CWE-23), published 2026-05-26.
> https://github.com/xwiki/xwiki-commons/security/advisories/GHSA-xq3r-2qv5-vqqm
>
> This is the **detection report** handed to the agent — what an upstream scanner / advisory tells you.
> The advisory's remediation guidance (patched versions / workarounds) has been withheld: the agent must
> produce the fix itself. Nothing below prescribes a fix.

**Type:** Relative Path Traversal — CWE-23
**Location:** `xwiki-commons-core/xwiki-commons-classloader/xwiki-commons-classloader-api/src/main/java/org/xwiki/classloader/internal/ClassLoaderUtils.java` — resource-name resolution used by `getResource` / `getResourceAsStream`

## Summary

Path traversal via the `resource` parameter in the `ssx` and `jsx` endpoints **when using a leading slash**. The directory-confinement check on the resolved resource name can be bypassed, so a resource path that escapes the intended root location is accepted instead of rejected.

## Impact

It is possible to read configuration files by using URLs such as:

```
http://localhost:8080/bin/ssx/Main/WebHome?resource=/../../WEB-INF/xwiki.cfg&minify=false
```

This is reproducible on Tomcat instances.
