# Security finding

> A code-security scan flagged the vulnerability below. No remediation is included; produce the fix yourself.

**Type:** Information Exposure — CWE-200
**Project:** `yt-dlp/yt-dlp`
**Primary location:** `yt_dlp/downloader/external.py`
**Other files possibly involved:** `yt_dlp/utils/_utils.py`

## Details

### Summary
If curl is used an external downloader for yt-dlp, cookies may be leaked to an unintended host upon HTTP redirect or when the host for download fragments differs from their parent manifest's.

This is the equivalent to [GHSA-v8mc-9377-rwjj](<https://github.com/yt-dlp/yt-dlp/security/advisories/GHSA-v8mc-9377-rwjj>) for the `curl` downloader. The vulnerable behavior is present in [yt-dlp](https://github.com/yt-dlp/yt-dlp) released since 2023.09.24.

### Details
At the file download stage, the cookies are passed by yt-dlp to the file downloader via `--cookie`. However, unless these are loaded from a file, this operation does not activate the cookie engine. As a result, `curl` will send cookies with requests to domains or paths for which the cookies are not scoped.

An example of a potential attack scenario exploiting this vulnerability:
1. an attacker has crafted a malicious website with an embedded URL designed to be detected by yt-dlp as a video download. This embedded URL has the domain of a trusted site that the user has loaded cookies for, and conducts an [unvalidated redirect](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html) to a target URL.
2. yt-dlp extracts this URL and calculates the cookies which are then passed to `curl`.
3. the download URL redirects to a server controlled by the attacker, to which `curl` forwards the user's sensitive cookie information.
