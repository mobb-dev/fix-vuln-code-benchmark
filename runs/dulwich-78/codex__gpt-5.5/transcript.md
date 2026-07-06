**Codex:** I’ll inspect the finding and the relevant project files first, then patch only the vulnerable code path and run focused checks if the project provides them.

**→ shell:** `/bin/bash -lc ls`
```
CODE_OF_CONDUCT.md
CONTRIBUTING.rst
COPYING
Cargo.lock
Cargo.toml
FINDING.txt
MANIFEST.in
Makefile
NEWS
README.rst
SECURITY.md
TODO
bin
contrib
crates
devscripts
disperse.toml
docs
dulwich
dulwich.cfg
examples
fuzzing
inquest.toml
limmat.toml
property_tests
pyproject.toml
requirements.txt
setup.py
status.yaml
testdata
tests
tox.ini

```
**→ shell:** `/bin/bash -lc "pwd && rg --files -g 'FINDING.txt' -g '"'!*node_modules*'"' -g '"'!*.git*'"'"`
```
/work
FINDING.txt

```
**Codex:** I found a mixed Rust/Python repository. Next I’m reading the vulnerability note alongside the likely target files so the fix can stay tightly scoped.

**→ shell:** `/bin/bash -lc "sed -n '1,220p' FINDING.txt"`
```
Project: jelmer/dulwich
Vulnerability type: OS Command Injection (CWE-78)

Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):

  dulwich/merge_drivers.py
    - lines 29-35
    - lines 64-69   in: def merge(
    - lines 110-123   in: def merge(

```
**→ shell:** `/bin/bash -lc "rg -n \"TODO|FIXME|unsafe|path|archive|tar|zip|extract|clone|checkout|http|submodule|ssh|shell|subprocess|eval|pickle|yaml\" dulwich crates tests -g '"'!target'"'"`
```
dulwich/bundle_uri.py:17:# <http://www.gnu.org/licenses/> for a copy of the GNU General Public License
dulwich/bundle_uri.py:18:# and <http://www.apache.org/licenses/LICENSE-2.0> for a copy of the Apache
dulwich/bundle_uri.py:22:"""Bundle URI support for faster clones and fetches.
dulwich/bundle_uri.py:25:https://git-scm.com/docs/bundle-uri
dulwich/bundle_uri.py:28:download pre-computed bundles to speed up clones and fetches.
dulwich/bundle_uri.py:64:        filter: Object filter (e.g., "blob:no  …(+1047982 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba dulwich/merge_drivers.py | sed -n '1,180p'"`
```
     1	# merge_drivers.py -- Merge driver support for dulwich
     2	# Copyright (C) 2025 Jelmer Vernooij <jelmer@jelmer.uk>
     3	#
     4	# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
     5	# Dulwich is dual-licensed under the Apache License, Version 2.0 and the GNU
     6	# General Public License as published by the Free Software Foundation; version 2.0
     7	# or (at your option) any later version. You can redistribute it and/or
     8	# modify it under the terms of either of   …(+6656 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"merge_drivers|MergeDriver|BaseMergeDriver|subprocess|shell=True|Popen\" tests dulwich -g '"'!target'"'"`
```
dulwich/filters.py:37:import subprocess
dulwich/filters.py:150:        self._process: subprocess.Popen[bytes] | None = None
dulwich/filters.py:162:                self._process = subprocess.Popen(
dulwich/filters.py:164:                    shell=True,
dulwich/filters.py:165:                    stdin=subprocess.PIPE,
dulwich/filters.py:166:                    stdout=subprocess.PIPE,
dulwich/filters.py:167:                    stderr=subprocess.PIPE,
dulwich/filters.py:234:                subproces  …(+14874 more chars)
```
**Codex:** The vulnerable spot is the custom merge driver command expansion: it builds one shell string with unquoted placeholders and runs it with `shell=True`. I’m checking the existing tests now so I can preserve Git-style custom merge driver behavior while removing shell interpretation.

**→ shell:** `/bin/bash -lc "nl -ba tests/test_merge_drivers.py | sed -n '1,260p'"`
```
     1	# test_merge_drivers.py -- Tests for merge driver support
     2	# Copyright (C) 2025 Jelmer Vernooij <jelmer@jelmer.uk>
     3	#
     4	# Dulwich is dual-licensed under the Apache License, Version 2.0 and the GNU
     5	# General Public License as published by the Free Software Foundation; version 2.0
     6	# or (at your option) any later version. You can redistribute it and/or
     7	# modify it under the terms of either of these two licenses.
     8	#
     9	# Unless required by appli  …(+10249 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba dulwich/merge_drivers.py | sed -n '180,280p'"`
```
   180	            factory: Factory function that returns a MergeDriver
   181	        """
   182	        self._factories[name] = factory
   183	
   184	    def get_driver(self, name: str) -> MergeDriver | None:
   185	        """Get a merge driver by name.
   186	
   187	        Args:
   188	            name: Name of the merge driver
   189	
   190	        Returns:
   191	            MergeDriver instance or None if not found
   192	        """
   193	        # First check registered drivers
     …(+2174 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"shlex|split\\(|subprocess.run\\(\\[|ProcessMergeDriver\\(\" dulwich tests/test_merge_drivers.py"`
```
tests/test_merge_drivers.py:133:        driver = ProcessMergeDriver(command, "echo_driver")
tests/test_merge_drivers.py:153:        driver = ProcessMergeDriver(command, "cat_driver")
tests/test_merge_drivers.py:168:        driver = ProcessMergeDriver(command, "fail_driver")
tests/test_merge_drivers.py:180:        driver = ProcessMergeDriver(command, "marker_driver")
tests/test_merge_drivers.py:196:        driver = ProcessMergeDriver(command, "path_driver")
dulwich/whitespace.py:73:    parts = va  …(+15101 more chars)
```
**Codex:** I’m going to replace the implicit shell execution with argument parsing plus direct `subprocess.run(argv, ...)`. To keep current behavior for the existing merge-driver tests, I’ll implement simple stdout redirection tokens (`>` and `>>`) locally instead of depending on a shell for them.

**✎ files:** update `/work/dulwich/merge_drivers.py`

**Codex:** The code path now avoids `shell=True` and treats placeholders as argument data. I’m adding a regression test with a malicious `%P` value to prove it is passed literally and cannot create a second shell command.

**✎ files:** update `/work/tests/test_merge_drivers.py`

**Codex:** The regression test is in place. I’m running the merge driver test module now, then I’ll run a style/type-adjacent check if the first pass exposes project expectations.

**→ shell:** `/bin/bash -lc 'python -m unittest tests.test_merge_drivers'`
```
..sssss..........
----------------------------------------------------------------------
Ran 17 tests in 0.010s

OK (skipped=5)

```
**Codex:** The focused unit tests pass. I’m doing a quick repository diff and checking the touched code for formatting issues before I wrap this up.

**→ shell:** `/bin/bash -lc 'git diff -- dulwich/merge_drivers.py tests/test_merge_drivers.py'`
```
diff --git a/dulwich/merge_drivers.py b/dulwich/merge_drivers.py
index 0e327ea..a992705 100644
--- a/dulwich/merge_drivers.py
+++ b/dulwich/merge_drivers.py
@@ -29,6 +29,7 @@ __all__ = [
 ]
 
 import os
+import shlex
 import subprocess
 import tempfile
 from collections.abc import Callable
@@ -77,6 +78,55 @@ class ProcessMergeDriver:
         self.command = command
         self.name = name
 
+    def _command_args(
+        self,
+        ancestor_path: str,
+        ours_path: str,
+        th  …(+4855 more chars)
```
**→ shell:** `/bin/bash -lc 'rg -n "ruff|black|mypy|typing|line-length|format" pyproject.toml tox.ini setup.py'`
```
pyproject.toml:28:    'typing_extensions >=4.6.0 ; python_version < "3.12"',
pyproject.toml:46:    "ruff==0.15.12",
pyproject.toml:47:    "mypy==1.20.2",
pyproject.toml:60:[tool.mypy]
pyproject.toml:74:[[tool.mypy.overrides]]
pyproject.toml:78:[[tool.mypy.overrides]]
pyproject.toml:85:[[tool.mypy.overrides]]
pyproject.toml:92:[[tool.mypy.overrides]]
pyproject.toml:99:[[tool.mypy.overrides]]
pyproject.toml:105:[[tool.mypy.overrides]]
pyproject.toml:129:[tool.ruff.lint]
pyproject.toml:153:[tool.ru  …(+73 more chars)
```
**Codex:** The diff is narrow and the unit test covers the injection case. I noticed one formatting shape that may not match the repo formatter, so I’m running Ruff on the touched files and will adjust if needed.

**→ shell:** `/bin/bash -lc 'python -m ruff check dulwich/merge_drivers.py tests/test_merge_drivers.py'`
```
/usr/local/bin/python: No module named ruff

```
**Codex:** Ruff is configured but not installed in this environment, so I can’t run it here. I’m running Python’s compile check on the touched files and the focused tests once more after a small formatting cleanup.

**✎ files:** update `/work/dulwich/merge_drivers.py`

**→ shell:** `/bin/bash -lc 'python -m py_compile dulwich/merge_drivers.py tests/test_merge_drivers.py'`
**→ shell:** `/bin/bash -lc 'python -m unittest tests.test_merge_drivers'`
```
..sssss..........
----------------------------------------------------------------------
Ran 17 tests in 0.018s

OK (skipped=5)

```
**→ shell:** `/bin/bash -lc 'git diff --check -- dulwich/merge_drivers.py tests/test_merge_drivers.py'`
**Codex:** The compile check, whitespace check, and focused merge-driver tests all pass. I’m grabbing final line references now so the summary points at the exact changes.

**→ shell:** `/bin/bash -lc "nl -ba dulwich/merge_drivers.py | sed -n '24,210p'"`
```
    24	__all__ = [
    25	    "MergeDriver",
    26	    "MergeDriverRegistry",
    27	    "ProcessMergeDriver",
    28	    "get_merge_driver_registry",
    29	]
    30	
    31	import os
    32	import shlex
    33	import subprocess
    34	import tempfile
    35	from collections.abc import Callable
    36	from typing import Protocol
    37	
    38	from .config import Config
    39	
    40	
    41	class MergeDriver(Protocol):
    42	    """Protocol for merge drivers."""
    43	
    44	    def merge  …(+6725 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba tests/test_merge_drivers.py | sed -n '20,225p'"`
```
    20	
    21	"""Tests for merge driver support."""
    22	
    23	import importlib.util
    24	import os
    25	import sys
    26	import unittest
    27	
    28	from dulwich.attrs import GitAttributes, Pattern
    29	from dulwich.config import ConfigDict
    30	from dulwich.merge import merge_blobs
    31	from dulwich.merge_drivers import (
    32	    MergeDriverRegistry,
    33	    ProcessMergeDriver,
    34	    get_merge_driver_registry,
    35	)
    36	from dulwich.objects import Blob
    3  …(+7725 more chars)
```
**Codex:** Implemented the remediation for the OS command injection in [dulwich/merge_drivers.py](/work/dulwich/merge_drivers.py:81).

What changed:
- Removed `shell=True` execution for merge drivers.
- Parse the configured command with `shlex.split`, expand placeholders as argument data, and call `subprocess.run()` with an argv list.
- Added local handling for simple `>` and `>>` stdout redirection so existing merge-driver behavior still works.
- Added a regression test in [tests/test_merge_drivers.py](/work/tests/test_merge_drivers.py:209) proving injected shell syntax is treated literally and not executed.

Verification run:
- `python -m unittest tests.test_merge_drivers` passes: 17 tests, 5 skipped.
- `python -m py_compile dulwich/merge_drivers.py tests/test_merge_drivers.py` passes.
- `git diff --check -- dulwich/merge_drivers.py tests/test_merge_drivers.py` passes.

I could not run Ruff because it is not installed in this environment: `No module named ruff`.


---
*tokens — input 428088 (cached 360832), output 4088, reasoning 1052*
