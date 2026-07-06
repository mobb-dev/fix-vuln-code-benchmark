**Claude:** I'll start by reading the FINDING.txt file to understand the vulnerability.

**→ Read**(file_path=/work/FINDING.txt)
  ↳ *result:* 1	Project: jelmer/dulwich
2	Vulnerability type: OS Command Injection (CWE-78)
3	
4	Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):
5	
6	  dulwich/merge_drivers.py
7	    - lines 29-35
8	    - lines 64-69   in: def merge(
9	    - lines 110-123   in: def merge(
10	
**Claude:** I'll read the vulnerable file to understand the issue.

**→ Read**(file_path=/work/dulwich/merge_drivers.py)
  ↳ *result:* 1	# merge_drivers.py -- Merge driver support for dulwich
2	# Copyright (C) 2025 Jelmer Vernooij <jelmer@jelmer.uk>
3	#
4	# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
5	# Dulwich is dual-licensed under the Apache License, Version 2.0 and the GNU
6	# General Public License as published by the Free Software Foundation; version 2.0
7	# or   …(+8542 more chars)
**Claude:** Now I understand the vulnerability. The `ProcessMergeDriver.merge` method builds a shell command by substituting placeholders (`%O`, `%A`, `%B`, `%L`, `%P`) directly into a command string that is then executed with `shell=True`. The `%P` value (the file path being merged) — and potentially the temp paths — are inserted unescaped, allowing shell command injection if a value contains shell metacharacters.

Git's own merge-driver design intentionally runs the command via the shell, but it shell-quotes the substituted values. I'll do the same using `shlex.quote()`, which preserves intended behavior while preventing injection.

**→ Edit**(replace_all=false, file_path=/work/dulwich/merge_drivers.py, old_string=import os
import subprocess
import tempfile, new_string=import os
import shlex
import subprocess
import tempfile)
  ↳ *result:* The file /work/dulwich/merge_drivers.py has been updated successfully. (file state is current in your context — no need to Read it back)
**→ Edit**(replace_all=false, file_path=/work/dulwich/merge_drivers.py, old_string=            # Prepare command with placeholders
            cmd = self.command
            cmd = cmd.replace("%O", ancestor_path)
            …(+206 more chars), new_string=            # Prepare command with placeholders. The substituted values are
            # shell-quoted so that paths containing shell metach  …(+523 more chars))
  ↳ *result:* The file /work/dulwich/merge_drivers.py has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Let me verify there are no tests that depend on the unquoted substitution behavior.

**→ Bash**(command=grep -rln "ProcessMergeDriver\|merge_driver" tests/ 2>/dev/null; ls tests/ 2>/dev/null | grep -i merge)
  ↳ *result:* tests/test_merge_drivers.py
tests/__init__.py
test_merge.py
test_merge_drivers.py
**→ Bash**(command=grep -n "%P\|%A\|%O\|%B\|%L\|command=\|ProcessMergeDriver(" tests/test_merge_drivers.py)
  ↳ *result:* 116:        config.set((b"merge", b"xmlmerge"), b"driver", b"xmlmerge %O %A %B")
123:        self.assertEqual(driver.command, "xmlmerge %O %A %B")
132:        command = "echo merged > %A"
133:        driver = ProcessMergeDriver(command, "echo_driver")
152:        command = "cat %O %B >> %A"
153:        driver = ProcessMergeDriver(command, "cat_driv  …(+382 more chars)
**Claude:** The tests use the placeholders in straightforward ways. `shlex.quote()` leaves normal paths/values unchanged, so behavior is preserved. Let me run the tests to confirm.

**→ Bash**(command=python -m pytest tests/test_merge_drivers.py -q 2>&1 | tail -20)
  ↳ *result:* /usr/local/bin/python: No module named pytest
**→ Bash**(command=python -m unittest tests.test_merge_drivers -v 2>&1 | tail -30)
  ↳ *result:* Test merge_blobs with custom merge driver. ... skipped 'Dependency merge3 missing'
test_merge_blobs_with_process_driver (tests.test_merge_drivers.MergeBlobsWithDriversTests.test_merge_blobs_with_process_driver)
Test merge_blobs with process-based merge driver. ... skipped 'Dependency merge3 missing'
test_merge_blobs_with_text_driver (tests.test_mer  …(+1769 more chars)
**Claude:** All tests pass (5 skipped only due to an unrelated missing `merge3` dependency). Let me verify the fix actually blocks an injection attempt via the `%P` placeholder.

**→ Bash**(command=python -c "
import os, tempfile
from dulwich.merge_drivers import ProcessMergeDriver

# Malicious file path containing shell metacharacters
  …(+386 more chars))
  ↳ *result:* injection file created: False
**Claude:** The injection is blocked. The malicious path is now treated as a single quoted shell argument rather than being interpreted as separate commands.

## Summary

**Vulnerability:** OS Command Injection (CWE-78) in `dulwich/merge_drivers.py`, in `ProcessMergeDriver.merge()`.

The method built a shell command by substituting placeholders (`%O`, `%A`, `%B`, `%L`, `%P`) directly into a command string and executing it with `subprocess.run(cmd, shell=True, ...)`. The `%P` value is the repository-controlled path of the file being merged, so a file path containing shell metacharacters (e.g. `x; rm -rf ~`) would be interpreted by the shell, allowing arbitrary command execution.

**Fix:** 
- Added `import shlex`.
- Wrapped every substituted value in `shlex.quote()` before inserting it into the command template.

This mirrors how Git itself handles merge-driver placeholder expansion: the configured driver command is still run via the shell (preserving the intended behavior — the merge command template is meant to be a shell command), but the substituted *values* are shell-escaped so they can't break out of their argument and inject additional commands.

I did not change the driver's interface, its placeholder semantics, or the `shell=True` execution model (which is intentional and required for the feature). All 16 existing tests pass (the 5 skips are due to the unrelated missing `merge3` dependency), and an injection proof-of-concept confirms the attack no longer succeeds.


---
**Final (success):** The injection is blocked. The malicious path is now treated as a single quoted shell argument rather than being interpreted as separate commands.

## Summary

**Vulnerability:** OS Command Injection (CWE-78) in `dulwich/merge_drivers.py`, in `ProcessMergeDriver.merge()`.

The method built a shell command by substituting placeholders (`%O`, `%A`, `%B`, `%L`, `%P`) directly into a command string and executing it with `subprocess.run(cmd, shell=True, ...)`. The `%P` value is the repository-controlled path of the file being merged, so a file path containing shell metacharacters (e.g. `x; rm -rf ~`) would be interpreted by the shell, allowing arbitrary command execution.

**Fix:** 
- Added `import shlex`.
- Wrapped every substituted value in `shlex.quote()` before inserting it into the command template.

This mirrors how Git itself handles merge-driver placeholder expansion: the configured driver command is still run via the shell (preserving the intended behavior — the merge command template is meant to be a shell command), but the substituted *values* are shell-escaped so they can't break out of their argument and inject additional commands.

I did not change the driver's interface, its placeholder semantics, or the `shell=True` execution model (which is intentional and required for the feature). All 16 existing tests pass (the 5 skips are due to the unrelated missing `merge3` dependency), and an injection proof-of-concept confirms the attack no longer succeeds.

*turns 10 · cost $0.327*
