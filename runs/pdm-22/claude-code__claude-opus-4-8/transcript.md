**Claude:** I'll start by reading the FINDING.txt file to understand the vulnerability.

**→ Read**(file_path=/work/FINDING.txt)
  ↳ *result:* 1	Project: pdm-project/pdm
2	Vulnerability type: Path Traversal (CWE-22)
3	
4	Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):
5	
6	  src/pdm/installers/installers.py
7	    - lines 9-15
8	    - lines 18-28
9	    - lines 47-53   in: def __init__(self, package: CachedPackage) -> None:
10	    - lines 110-116   in:   …(+188 more chars)
**Claude:** I'll read the vulnerable file now.

**→ Read**(file_path=/work/src/pdm/installers/installers.py)
  ↳ *result:* 1	from __future__ import annotations
2	
3	import json
4	import os
5	import stat
6	from functools import cached_property
7	from pathlib import Path
8	from typing import TYPE_CHECKING, Iterator
9	
10	from installer import install as _install
11	from installer._core import _process_WHEEL_file
12	from installer.destinations import SchemeDictionaryDesti  …(+9466 more chars)
**Claude:** Now I understand the vulnerability. Let me analyze the path traversal sink.

The core issue is in `write_to_fs` (line 138): `target_path = os.path.join(self.scheme_dict[scheme], path)`. The `path` comes from the wheel's file entries / RECORD, which an attacker controls. A malicious wheel can include entries like `../../../etc/...` or absolute paths, causing `os.path.join` to escape the installation scheme directory and write files anywhere on the filesystem.

Let me look at how `dist_info_dir` and `dist_info` are derived, since those also feed paths.

**→ Read**(file_path=/work/src/pdm/models/cached_package.py)
  ↳ *result:* 1	from __future__ import annotations
2	
3	import os
4	import shutil
5	from functools import cached_property
6	from pathlib import Path
7	from typing import Any, ClassVar, ContextManager
8	
9	from pdm.termui import logger
10	
11	
12	class CachedPackage:
13	    """A package cached in the central package store.
14	    The directory name is similar to   …(+2916 more chars)
**Claude:** The vulnerability is clear. The fix is to validate that the resolved `target_path` stays within the destination scheme directory in `write_to_fs`, which is the single sink where all wheel-controlled paths get written to disk. Let me add a path-traversal guard.

**→ Edit**(replace_all=false, file_path=/work/src/pdm/installers/installers.py, old_string=    def write_to_fs(self, scheme: Scheme, path: str, stream: BinaryIO, is_executable: bool) -> RecordEntry:
        from installer.records i  …(+179 more chars), new_string=    def write_to_fs(self, scheme: Scheme, path: str, stream: BinaryIO, is_executable: bool) -> RecordEntry:
        from installer.records i  …(+790 more chars))
  ↳ *result:* The file /work/src/pdm/installers/installers.py has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** The fix is in place. `InvalidWheelSource` is already imported (line 13), so the exception type is appropriate—it signals a malformed/malicious wheel source.

Let me verify the edit reads correctly in context:

**→ Read**(file_path=/work/src/pdm/installers/installers.py, offset=134, limit=22)
  ↳ *result:* 134	    def write_to_fs(self, scheme: Scheme, path: str, stream: BinaryIO, is_executable: bool) -> RecordEntry:
135	        from installer.records import Hash
136	        from installer.utils import copyfileobj_with_hashing
137	
138	        target_dir = self.scheme_dict[scheme]
139	        target_path = os.path.join(target_dir, path)
140	        #   …(+1040 more chars)
**Claude:** The remediation is complete. Here's a summary of what I did.

## Vulnerability

**Path Traversal (CWE-22)** in `src/pdm/installers/installers.py`.

When PDM installs a wheel, the file entries (paths) come from inside the wheel archive (its contents and `RECORD` file), which are attacker-controllable for a malicious/untrusted package. Every file ultimately gets written through `InstallDestination.write_to_fs`, where the target was computed as:

```python
target_path = os.path.join(self.scheme_dict[scheme], path)
```

`os.path.join` does **not** contain traversal: a wheel entry like `../../../../etc/cron.d/evil` or an absolute path (`/etc/...`) causes the resolved `target_path` to escape the intended scheme/site-packages directory, letting a malicious wheel write arbitrary files anywhere the process can write — leading to remote code execution. This is the single sink that all wheel-controlled file writes (regular files, the `RECORD` file via `finalize_installation`, and symlink/hardlink targets) funnel through.

## Fix

Added a containment check in `write_to_fs`: after joining, the path is normalized and verified to be the destination directory itself or strictly inside it (`normalized_dir + os.sep`). Anything that escapes raises `InvalidWheelSource` (already imported in the module), which correctly signals a bad wheel.

This:
- Blocks both `../`-style traversal and absolute-path escapes.
- Covers all write paths since they all route through `write_to_fs`.
- Leaves legitimate installs unaffected (valid relative paths within the scheme dir pass the check unchanged), so intended behavior is preserved.

No files were committed, pushed, or otherwise pushed outward — only the local source edit was made.


---
**Final (success):** The remediation is complete. Here's a summary of what I did.

## Vulnerability

**Path Traversal (CWE-22)** in `src/pdm/installers/installers.py`.

When PDM installs a wheel, the file entries (paths) come from inside the wheel archive (its contents and `RECORD` file), which are attacker-controllable for a malicious/untrusted package. Every file ultimately gets written through `InstallDestination.write_to_fs`, where the target was computed as:

```python
target_path = os.path.join(self.scheme_dict[scheme], path)
```

`os.path.join` does **not** contain traversal: a wheel entry like `../../../../etc/cron.d/evil` or an absolute path (`/etc/...`) causes the resolved `target_path` to escape the intended scheme/site-packages directory, letting a malicious wheel write arbitrary files anywhere the process can write — leading to remote code execution. This is the single sink that all wheel-controlled file writes (regular files, the `RECORD` file via `finalize_installation`, and symlink/hardlink targets) funnel through.

## Fix

Added a containment check in `write_to_fs`: after joining, the path is normalized and verified to be the destination directory itself or strictly inside it (`normalized_dir + os.sep`). Anything that escapes raises `InvalidWheelSource` (already imported in the module), which correctly signals a bad wheel.

This:
- Blocks both `../`-style traversal and absolute-path escapes.
- Covers all write paths since they all route through `write_to_fs`.
- Leaves legitimate installs unaffected (valid relative paths within the scheme dir pass the check unchanged), so intended behavior is preserved.

No files were committed, pushed, or otherwise pushed outward — only the local source edit was made.

*turns 6 · cost $0.347*
