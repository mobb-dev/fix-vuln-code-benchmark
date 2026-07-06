# Security finding

> A code-security scan flagged the vulnerability below. No remediation is included; produce the fix yourself.

**Type:** Cross-site Scripting — CWE-79
**Project:** `jupyter-server/jupyter_server`
**Primary location:** `jupyter_server/nbconvert/handlers.py`
**Other files possibly involved:** `jupyter_server/serverapp.py`

## Details

The nbconvert HTTP handlers in jupyter_server render user-authored notebook HTML under the Jupyter origin without a sandbox directive in their `Content-Security-Policy`. 

Combined with `nbconvert.HTMLExporter`'s default non-sanitizing behavior, a notebook carrying an HTML payload in a display_data output triggers stored XSS with cookie access, full /api/* authority, and kernel RCE.

### Impact

An authenticated victim who navigates to `/nbconvert/html/<path>` containing attacker-authored output can have their token exfiltrated to another domain because it is executed in the Jupyter origin.
