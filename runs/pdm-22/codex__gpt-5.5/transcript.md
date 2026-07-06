**Codex:** I’ll read the vulnerability note and inspect the referenced code paths before making a narrow fix. After that I’ll run the most relevant tests I can identify locally.

**→ shell:** `/bin/bash -lc "sed -n '1,220p' FINDING.txt"`
```
Project: pdm-project/pdm
Vulnerability type: Path Traversal (CWE-22)

Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):

  src/pdm/installers/installers.py
    - lines 9-15
    - lines 18-28
    - lines 47-53   in: def __init__(self, package: CachedPackage) -> None:
    - lines 110-116   in: def finalize_installation(
    - lines 135-150   in: def write_to_fs(self, scheme: Scheme, path: str, stream: BinaryIO, is_executable
    - lines 226-232   in: def install  …(+8 more chars)
```
**→ shell:** `/bin/bash -lc "pwd && rg --files -g 'FINDING.txt' -g 'AGENTS.md' -g 'pyproject.toml'"`
```
/work
pyproject.toml
FINDING.txt
AGENTS.md
src/pdm/cli/templates/minimal/pyproject.toml
tests/fixtures/pyproject.toml
src/pdm/cli/templates/default/pyproject.toml
tests/fixtures/projects/demo-parent-package/package-b/pyproject.toml
tests/fixtures/projects/demo-package/pyproject.toml
tests/fixtures/projects/demo-package-has-dep-with-extras/pyproject.toml
tests/fixtures/projects/poetry-with-circular-dep/packages/child/pyproject.toml
tests/fixtures/projects/flit-demo/pyproject.toml
tests/fixtures/p  …(+722 more chars)
```
**Codex:** The finding points at wheel installation and cached package path handling. I’m opening that module and nearby tests now so the fix matches PDM’s existing install semantics instead of adding a broad behavioral change.

**→ shell:** `/bin/bash -lc "nl -ba src/pdm/installers/installers.py | sed -n '1,280p'"`
```
     1	from __future__ import annotations
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
    12	from installer.destinations import SchemeDictionaryDestination, WheelDestination
    13	from installer.exceptions import InvalidWheelSource
    14	fr  …(+10134 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"install_wheel|PackageWheelSource|write_to_fs|CachedPackage|installers\" tests src/pdm -g '*.py'"`
```
src/pdm/installers/base.py:13:from pdm.installers.manager import InstallManager
src/pdm/installers/manager.py:8:from pdm.installers.installers import install_wheel
src/pdm/installers/manager.py:9:from pdm.installers.uninstallers import BaseRemovePaths, StashedRemovePaths
src/pdm/installers/manager.py:29:        dist_info = install_wheel(
src/pdm/installers/uv.py:10:from pdm.installers.base import BaseSynchronizer
src/pdm/installers/installers.py:18:from pdm.models.cached_package import CachedPac  …(+4157 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba src/pdm/models/cached_package.py | sed -n '1,220p'"`
```
     1	from __future__ import annotations
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
    14	    The directory name is similar to wheel's filename:
    15	
    16	        $PACKAGE_ROOT/<checksum[:2]>/<dist_name>-<ve  …(+3104 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba src/pdm/models/caches.py | sed -n '250,320p'"`
```
   250	                logger.debug("Ignoring invalid cached wheel %s", candidate.name)
   251	                continue
   252	            if canonical_name != canonicalize_name(name):
   253	                logger.debug(
   254	                    "Ignoring cached wheel %s with invalid project name %s, expected: %s",
   255	                    candidate.name,
   256	                    name,
   257	                    canonical_name,
   258	                )
   259	                continue
   2  …(+2452 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba tests/test_installer.py | sed -n '1,360p'"`
```
     1	from __future__ import annotations
     2	
     3	import logging
     4	import os
     5	import venv
     6	from pathlib import Path
     7	from typing import Callable
     8	
     9	import pytest
    10	from unearth import Link
    11	
    12	from pdm import utils
    13	from pdm.core import Core
    14	from pdm.environments.base import BaseEnvironment
    15	from pdm.environments.local import PythonLocalEnvironment
    16	from pdm.environments.python import PythonEnvironment
    17	from  …(+14022 more chars)
```
**Codex:** The vulnerable sink is `InstallDestination.write_to_fs`: it trusts archive/RECORD paths when forming install targets. I’m also checking the cache extraction path because cached installs feed file paths back into the same installer flow.

**→ shell:** `/bin/bash -lc "python - <<'PY'
import inspect
from installer.destinations import SchemeDictionaryDestination
from installer.sources import WheelSource, WheelFile
print(inspect.getsource(SchemeDictiona  …(+212 more chars)`
```
Traceback (most recent call last):
  File "<stdin>", line 2, in <module>
ModuleNotFoundError: No module named 'installer'

```
**→ shell:** `/bin/bash -lc "python - <<'PY'
import inspect
import installer._core as c
print(inspect.getsource(c.install))
PY"`
```
Traceback (most recent call last):
  File "<stdin>", line 2, in <module>
ModuleNotFoundError: No module named 'installer'

```
**→ shell:** `/bin/bash -lc "rg -n \"ZipFile|writestr|wheel|RECORD|\\.dist-info\" tests -g '*.py'"`
```
tests/resolver/test_resolve.py:153:    ids=["sdist", "wheel"],
tests/models/test_candidates.py:78:    assert prepared.link.is_wheel
tests/models/test_candidates.py:90:    assert prepared.link.is_wheel
tests/models/test_candidates.py:203:def test_sdist_candidate_with_wheel_cache(project, mocker):
tests/models/test_candidates.py:206:    wheel_cache = project.make_wheel_cache()
tests/models/test_candidates.py:207:    cache_path = wheel_cache.get_path_for_link(file_link, project.environment.spec)
te  …(+5404 more chars)
```
**Codex:** The base `installer` package is only available through the project environment here, so I’m using `pdm run` for introspection and tests. Next edit will add containment checks at the filesystem boundary and reject invalid cached wheel paths early.

**→ shell:** `/bin/bash -lc "pdm run python - <<'PY'
import inspect
from installer.destinations import SchemeDictionaryDestination
from installer.sources import WheelSource
import installer._core as c
print(inspect  …(+216 more chars)`
```
/bin/bash: line 1: pdm: command not found

```
**→ shell:** `/bin/bash -lc "pdm run python - <<'PY'
import inspect
from installer.sources import WheelFile
print(inspect.getsource(WheelFile.get_contents))
print('--- dist info')
print(inspect.getsource(WheelFile.  …(+24 more chars)`
```
/bin/bash: line 1: pdm: command not found

```
**Codex:** `pdm` is not on PATH in this container, so I’m proceeding from the source and tests directly. The vulnerable pattern is clear enough: untrusted wheel paths must be normalized as relative paths and kept under their destination root.

**→ shell:** `/bin/bash -lc "rg -n \"installer\" pyproject.toml pdm.lock requirements* setup.cfg tox.ini -g '*'"`
```
rg: requirements*: No such file or directory (os error 2)
rg: setup.cfg: No such file or directory (os error 2)
pyproject.toml:31:    "installer>=0.7",
pyproject.toml:36:    "pbs-installer>=2025.10.7",
pdm.lock:1051:name = "installer"
pdm.lock:1058:    {file = "installer-1.0.0-py3-none-any.whl", hash = "sha256:7b46327ded20d8544bfe2d8561618bbcd12d88e7e3645333af1ed141d8bc1bfe"},
pdm.lock:1059:    {file = "installer-1.0.0.tar.gz", hash = "sha256:c6d691331621cf3fec4822f5c6f83cab3705f79b316225dc45412  …(+757 more chars)
```
**→ shell:** `/bin/bash -lc "python - <<'PY'
import zipfile, inspect
print(inspect.getsource(zipfile.ZipFile._extract_member))
PY"`
```
    def _extract_member(self, member, targetpath, pwd):
        """Extract the ZipInfo object 'member' to a physical
           file on the path targetpath.
        """
        if not isinstance(member, ZipInfo):
            member = self.getinfo(member)

        # build the destination pathname, replacing
        # forward slashes to platform specific separators.
        arcname = member.filename.replace('/', os.path.sep)

        if os.path.altsep:
            arcname = arcname.replace(os.path  …(+1190 more chars)
```
**→ shell:** `/bin/bash -lc 'git status --short'`
**Codex:** I’m going to keep the remediation at the trust boundary: validate wheel/cache member names as relative POSIX paths, resolve the final target, and refuse writes outside the selected install scheme. I’ll also add regression tests that exercise direct and cached installs with malicious paths.

**→ shell:** `/bin/bash -lc "python - <<'PY'
from pathlib import PurePosixPath
for s in ['a//b','a/./b','../x','/x','a/../b','']:
 print(repr(s), PurePosixPath(s).parts)
PY"`
```
'a//b' ('a', 'b')
'a/./b' ('a', 'b')
'../x' ('..', 'x')
'/x' ('/', 'x')
'a/../b' ('a', '..', 'b')
'' ()

```
**→ shell:** `/bin/bash -lc "python - <<'PY'
from pathlib import Path
import inspect
print(inspect.signature(Path.resolve))
PY"`
```
(self, strict=False)

```
**Codex:** The implementation will reject invalid wheel member paths with `InvalidWheelSource`, which is consistent with how installer failures are represented elsewhere in this module. Valid relative paths, Windows RECORD rewriting, and `.pth` renaming keep their current flow.

**✎ files:** update `/work/src/pdm/installers/installers.py`

**Codex:** I’ve patched the installer path handling. I’m adding focused tests now: one for a malicious destination path and one for a tampered cached package that tries to expose a file outside the cache directory.

**✎ files:** update `/work/tests/test_installer.py`

**Codex:** The regression tests are in place. I’m going to run the narrow test file first; if the project environment is unavailable, I’ll at least run syntax checks against the edited files and report that limitation.

**→ shell:** `/bin/bash -lc 'python -m pytest tests/test_installer.py -q'`
```
/usr/local/bin/python: No module named pytest

```
**→ shell:** `/bin/bash -lc 'python -m compileall -q src/pdm/installers/installers.py tests/test_installer.py'`
**Codex:** `pytest` is not installed in the ambient Python, but the edited files compile cleanly. I’m doing one more local pass for style/type issues introduced by the patch, especially around `Path` versus `str` calls.

**→ shell:** `/bin/bash -lc 'command -v uv || true; command -v pdm || true; command -v hatch || true; command -v tox || true'`
```
/usr/local/bin/uv

```
**→ shell:** `/bin/bash -lc "nl -ba tests/test_installer.py | sed -n '270,340p'"`
```
   270	    installer = InstallManager(project.environment, use_install_cache=use_install_cache)
   271	    installer.install(candidate)
   272	    bin_path = os.path.join(project.environment.get_paths()["scripts"], "jp.py")
   273	    assert os.path.isfile(bin_path)
   274	    if os.name != "nt":
   275	        assert os.stat(bin_path).st_mode & 0o100
   276	
   277	    dist = project.environment.get_working_set()["jmespath"]
   278	    installer.uninstall(dist)
   279	    assert not os.path.exi  …(+2567 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba src/pdm/installers/installers.py | sed -n '1,190p'"`
```
     1	from __future__ import annotations
     2	
     3	import json
     4	import ntpath
     5	import os
     6	import stat
     7	from functools import cached_property
     8	from pathlib import Path, PurePosixPath
     9	from typing import TYPE_CHECKING, Iterator
    10	
    11	from installer import install as _install
    12	from installer._core import _process_WHEEL_file
    13	from installer.destinations import SchemeDictionaryDestination, WheelDestination
    14	from installer.exceptions  …(+8109 more chars)
```
**→ shell:** `/bin/bash -lc 'git diff -- src/pdm/installers/installers.py tests/test_installer.py'`
```
diff --git a/src/pdm/installers/installers.py b/src/pdm/installers/installers.py
index c6a9806..6d9913d 100644
--- a/src/pdm/installers/installers.py
+++ b/src/pdm/installers/installers.py
@@ -1,10 +1,11 @@
 from __future__ import annotations
 
 import json
+import ntpath
 import os
 import stat
 from functools import cached_property
-from pathlib import Path
+from pathlib import Path, PurePosixPath
 from typing import TYPE_CHECKING, Iterator
 
 from installer import install as _install
@@ -40,6  …(+6437 more chars)
```
**Codex:** `uv` is available, so I’m using it to run the targeted tests without relying on a globally installed `pdm` or `pytest`. If dependency setup is too slow or blocked, I’ll fall back to the compile result.

**→ shell:** `/bin/bash -lc 'uv run pytest tests/test_installer.py -q'`
```
  × Failed to build `pdm @ file:///work`
  ├─▶ Failed to resolve requirements from `build-system.requires`
  ├─▶ No solution found when resolving: `pdm-backend`, `pdm-build-locked`
  ├─▶ Request failed after 3 retries in 10.0s
  ├─▶ Failed to fetch: `https://pypi.org/simple/pdm-build-locked/`
  ├─▶ error sending request for url (https://pypi.org/simple/pdm-build-locked/)
  ├─▶ client error (Connect)
  ╰─▶ tunnel error: unsuccessful

```
**Codex:** `uv run` could not fetch build dependencies due a PyPI tunnel error and created a local `.venv` before failing. I’ll remove that generated environment and then do a final diff/status check.

**→ shell:** `/bin/bash -lc 'rm -rf .venv'`
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M src/pdm/installers/installers.py
 M tests/test_installer.py

```
**Codex:** I found one place to tighten the patch: the first version rejected harmless oddities like `./` segments. I’m narrowing validation to traversal and absolute/drive paths, while still resolving and containing the actual filesystem target.

**✎ files:** update `/work/src/pdm/installers/installers.py`

**Codex:** The validation is now focused on actual escape vectors: absolute paths, Windows drives/UNC paths, and `..` components. I’m re-running syntax checks and a small helper-level smoke test without project dependencies.

**→ shell:** `/bin/bash -lc "python - <<'PY'
import os
from pathlib import Path
print(os.path.normcase(Path('/tmp/demo')))
PY"`
```
/tmp/demo

```
**→ shell:** `/bin/bash -lc 'python -m compileall -q src/pdm/installers/installers.py tests/test_installer.py'`
**→ shell:** `/bin/bash -lc 'git diff -- src/pdm/installers/installers.py tests/test_installer.py'`
```
diff --git a/src/pdm/installers/installers.py b/src/pdm/installers/installers.py
index c6a9806..2a0a7a0 100644
--- a/src/pdm/installers/installers.py
+++ b/src/pdm/installers/installers.py
@@ -1,10 +1,11 @@
 from __future__ import annotations
 
 import json
+import ntpath
 import os
 import stat
 from functools import cached_property
-from pathlib import Path
+from pathlib import Path, PurePosixPath
 from typing import TYPE_CHECKING, Iterator
 
 from installer import install as _install
@@ -40,6  …(+6562 more chars)
```
**Codex:** The syntax check passes. I’m making the cached-package regression portable by skipping its symlink setup on Windows, where creating symlinks often requires elevated privileges in CI.

**✎ files:** update `/work/tests/test_installer.py`

**Codex:** I’m doing the final verification pass now: compile the edited files again, confirm the worktree only contains the intended source and test edits, and capture the exact test command failure reason.

**→ shell:** `/bin/bash -lc 'git diff --stat && git diff --check'`
```
 src/pdm/installers/installers.py | 58 +++++++++++++++++++++++++++++++---------
 tests/test_installer.py          | 35 ++++++++++++++++++++++++
 2 files changed, 81 insertions(+), 12 deletions(-)

```
**→ shell:** `/bin/bash -lc 'python -m compileall -q src/pdm/installers/installers.py tests/test_installer.py'`
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M src/pdm/installers/installers.py
 M tests/test_installer.py

```
**Codex:** Implemented the path traversal remediation.

Changed [installers.py](/work/src/pdm/installers/installers.py:44) to validate wheel/cache paths before filesystem writes:
- Rejects absolute paths, Windows drive/UNC paths, and `..` traversal components.
- Resolves install targets and ensures they remain inside the selected scheme directory.
- Validates cached package dist-info reads and cached file iteration so symlink escapes are refused.

Added regression coverage in [test_installer.py](/work/tests/test_installer.py:307):
- `InstallDestination.write_to_fs()` rejects `../escape.py`.
- Cached package sources reject symlinked files that resolve outside the cache package directory.

Verification:
- `python -m compileall -q src/pdm/installers/installers.py tests/test_installer.py` passed.
- `uv run pytest tests/test_installer.py -q` could not run because `uv` failed to fetch build dependencies from PyPI due a tunnel/connect error.


---
*tokens — input 531657 (cached 462592), output 9072, reasoning 3991*
