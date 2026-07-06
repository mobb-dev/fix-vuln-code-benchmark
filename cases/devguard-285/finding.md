# Security finding

> A code-security scan flagged the vulnerability below. No remediation is included; produce the fix yourself.

**Type:** Improper Authorization — CWE-285
**Project:** `l3montree-dev/devguard`
**Primary location:** `middlewares/access_control_middlewares.go`
**Other files possibly involved:** `router/artifact_router.go`, `router/asset_router.go`, `router/asset_version_router.go`, `router/dependency_vuln_router.go`, `router/external_reference_router.go`

## Details

### Impact

On a DevGuard API instance with one or more **public assets**, any authenticated user — including users from a different organization with no membership or role in the affected org/project — can create, update, reapply, and delete **VEX rules** on those public assets. The same flaw affects the other vulnerability-triage write endpoints exposed under a public asset, including:

- VEX rule create / update / reapply / delete
- Dependency-vuln event creation (accept / reject / mitigate decisions), batch event creation, vuln sync, and mitigation
- License risk creation
- External reference writes
- Artifact creation and license refresh

The attacker needs a valid account on the instance, but no membership in the victim organization, project, or asset is required.

**Security impact** is primarily to **integrity** of the vulnerability picture of public assets: an attacker can mark CVEs as false-positive, silence vulnerabilities, attach misleading justifications, or delete legitimate triage rules — undermining the trustworthiness of every consumer of the affected asset's VEX/SBOM output. Because public assets are by definition consumed by third parties (downstream users, supply-chain consumers, the published vex.json/sbom.json), the blast radius extends to anyone relying on that data.

Private assets are **not affected** by this advisory: the public-read exemption that enables the bypass does not apply to them, and access remains correctly gated by organization/project membership. The private setting is only relevant in DevGuard itself —  there is no impact given when you have an open-source project on e.g. GitLab/GitHub and a private DevGuard asset connected.

### Resources
