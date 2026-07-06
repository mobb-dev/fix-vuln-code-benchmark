# Security finding

> A code-security scan flagged the vulnerability below. No remediation is included; produce the fix yourself.

**Type:** Path Traversal — CWE-22
**Project:** `pdm-project/pdm`
**Primary location:** `src/pdm/installers/installers.py`

## Details

InstallDestination.write_to_fs() in src/pdm/installers/installers.py overrides the base class to add symlink/hardlink support but replaces the safe _path_with_destdir() (which validates via Path.resolve() + is_relative_to()) with a bare os.path.join() that performs no path validation. A malicious wheel with traversal entries can write arbitrary files. Same class as Poetry CVE-2026-34591. Fix ready at: https://github.com/pdm-project/pdm/pull/3787.
