**Codex:** I’ll read the vulnerability note and inspect the referenced code paths before editing, then keep the patch narrowly scoped to the reported issue.

**→ shell:** `/bin/bash -lc "sed -n '1,220p' FINDING.txt"`
```
Project: appium/appium-mcp
Vulnerability type: Cross-site Scripting (CWE-79)

Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):

  src/ui/mcp-ui-utils.ts
    - lines 720-743   in: export function createLocatorGeneratorUI(
    - lines 895-900   in: export function createLocatorGeneratorUI(
    - lines 1633-1635   in: export function addUIResourceToResponse(

```
**→ shell:** `/bin/bash -lc 'pwd && rg --files'`
```
/work
src/server.ts
src/persistence.ts
src/command.ts
src/telemetry/attributes.ts
src/telemetry/wrapOperations.ts
src/telemetry/init.ts
src/telemetry/tracer.ts
src/index.ts
src/session-store.ts
src/schema.ts
eslint.config.js
tsconfig.json
src/ai-finder/vision-finder.ts
src/ai-finder/types.ts
src/policy.ts
src/core.ts
src/logger.ts
scripts/sync-version.mjs
scripts/verify-names.mjs
src/devicemanager/ios-manager.ts
src/devicemanager/adb-manager.ts
examples/android-todo-app.md
examples/android-gmail  …(+5141 more chars)
```
**Codex:** The finding points to UI HTML/resource generation in `src/ui/mcp-ui-utils.ts`. I’m reading those sections plus nearby helpers to see how values are currently escaped and transported into the UI.

**→ shell:** `/bin/bash -lc "sed -n '1580,1665p' src/ui/mcp-ui-utils.ts"`
```
  </div>
  <script>
    function copyToClipboard() {
      const text = document.getElementById('codeContent').textContent;
      navigator.clipboard.writeText(text).then(() => {
        alert('Code copied to clipboard!');
      });
    }

    function downloadCode() {
      const text = document.getElementById('codeContent').textContent;
      const blob = new Blob([text], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.  …(+1129 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '660,930p' src/ui/mcp-ui-utils.ts"`
```
        }
      }, '*');
    }

    function generateLocators() {
      window.parent.postMessage({
        type: 'tool',
        payload: {
          toolName: 'generate_locators',
          params: {}
        }
      }, '*');
    }

    function getContexts() {
      window.parent.postMessage({
        type: 'tool',
        payload: {
          toolName: 'appium_context',
          params: { action: 'list' }
        }
      }, '*');
    }

    function deleteSession() {
      if (confirm('Are   …(+6012 more chars)
```
**→ shell:** `/bin/bash -lc 'rg -n "escape|sanitize|html|script|innerHTML|JSON.stringify|createLocatorGeneratorUI|addUIResourceToResponse" src/ui src/tests'`
```
src/ui/mcp-ui-utils.ts:13: * @param htmlContent - HTML string to render in the iframe
src/ui/mcp-ui-utils.ts:18:  htmlContent: string
src/ui/mcp-ui-utils.ts:23:    mimeType: 'text/html';
src/ui/mcp-ui-utils.ts:31:      mimeType: 'text/html',
src/ui/mcp-ui-utils.ts:32:      text: htmlContent,
src/ui/mcp-ui-utils.ts:82:<!DOCTYPE html>
src/ui/mcp-ui-utils.ts:83:<html lang="en">
src/ui/mcp-ui-utils.ts:210:  <script>
src/ui/mcp-ui-utils.ts:234:  </script>
src/ui/mcp-ui-utils.ts:236:</html>
src/ui/mcp  …(+9408 more chars)
```
**Codex:** The vulnerable output is direct interpolation of locator metadata into HTML and an inline event handler. I’m checking the resource wrapper as well, since the finding calls out response attachment and that may need a boundary check rather than just escaping individual fields.

**→ shell:** `/bin/bash -lc "sed -n '1,90p' src/ui/mcp-ui-utils.ts"`
```
/**
 * MCP-UI Utility Functions
 *
 * This module provides utilities for creating UI resources using MCP-UI protocol.
 * It enables interactive UI components to be returned alongside text responses.
 *
 * Reference: https://mcpui.dev/guide/introduction
 */

/**
 * Creates a UIResource object following MCP-UI protocol
 * @param uri - Unique identifier using ui:// scheme (e.g., 'ui://appium-mcp/device-picker')
 * @param htmlContent - HTML string to render in the iframe
 * @returns UIResource objec  …(+1952 more chars)
```
**→ shell:** `/bin/bash -lc 'cat package.json'`
```
{
  "name": "appium-mcp",
  "mcpName": "io.github.appium/appium-mcp",
  "version": "1.85.9",
  "type": "module",
  "repository": {
    "type": "git",
    "url": "git+https://github.com/appium/appium-mcp.git"
  },
  "bugs": {
    "url": "https://github.com/appium/appium-mcp/issues"
  },
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "exports": {
    ".": {
      "types": "./dist/index.d.ts",
      "import": "./dist/index.js"
    },
    "./core": {
      "types": "./dist/core.d.ts",
    …(+3640 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"createLocatorGeneratorUI|createUIResource|addUIResourceToResponse\" src tests . --glob '"'!node_modules'"'"`
```
rg: tests: No such file or directory (os error 2)
src/tests/screenshot.test.ts:80:    // Return text response (UI resource is added by addUIResourceToResponse in actual implementation)
./src/tests/screenshot.test.ts:80:    // Return text response (UI resource is added by addUIResourceToResponse in actual implementation)
src/tests/tools/session/session.test.ts:83:  createUIResource: jest.fn(() => ({})),
src/tests/tools/session/session.test.ts:85:  addUIResourceToResponse: jest.fn((_result: any, _  …(+6147 more chars)
```
**Codex:** There is no shared HTML escaping helper in this file; page-source and code views do local escaping. I’m going to add small context-specific encoders and remove inline JavaScript argument interpolation from the locator rows by using `data-*` attributes and a delegated click handler.

**→ shell:** `/bin/bash -lc "sed -n '1,160p' src/tests/generate-all-locators.test.ts"`
```
import { describe, test, expect } from '@jest/globals';
import { generateAllElementLocators } from '../locators/generate-all-locators.js';

describe('generateAllElementLocators', () => {
  // Sample XML for testing
  const sampleXML = `
    <hierarchy>
      <android.widget.FrameLayout resource-id="android:id/content">
        <android.widget.LinearLayout>
          <android.widget.TextView text="Hello World" resource-id="com.example:id/text_view" clickable="true" enabled="true" displayed="true"  …(+5263 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,140p' src/tools/test-generation/locators.ts"`
```
/**
 * Tool to get page source from the Android session
 *
 * TOOL EXTENSION GUIDE:
 * This tool demonstrates the traditional approach where metadata is defined inline.
 *
 * ALTERNATIVE APPROACH: You can also use YAML metadata files for better separation.
 * See src/tools/metadata/ for examples and src/tools/scroll-with-yaml.example.ts
 *
 * For detailed documentation on adding tools, see docs/CONTRIBUTING.md
 */
import { z } from 'zod';
import {
  isAndroidUiautomator2DriverSession,
  isXCUITe  …(+2893 more chars)
```
**→ shell:** `/bin/bash -lc 'git status --short'`
**Codex:** I found the main exploitable path: untrusted page-source attributes become locator fields, then render as raw HTML and inline handler arguments. The patch will keep the visible UI and tool call the same, but encode displayed values and move selector data out of executable JavaScript.

**→ shell:** `/bin/bash -lc "sed -n '1,80p' src/tests/sensitive.test.ts && sed -n '1,80p' src/tests/utils/paths.test.ts"`
```
import { describe, expect, test } from '@jest/globals';

import { isSensitiveKey } from '../utils/sensitive.js';

describe('sensitive key matching', () => {
  test('matches common secret key variants', () => {
    expect(isSensitiveKey('apiKey')).toBe(true);
    expect(isSensitiveKey('api_key')).toBe(true);
    expect(isSensitiveKey('client-secret')).toBe(true);
    expect(isSensitiveKey('remoteServerUrl')).toBe(true);
    expect(isSensitiveKey('Authorization')).toBe(true);
  });

  test('does n  …(+1332 more chars)
```
**Codex:** I’m applying the fix in the UI utility module and adding regression tests that use payloads like closing tags, inline event attributes, backticks, and script tags so the vulnerable interpolation pattern is covered directly.

**✎ files:** add `/work/src/tests/ui-mcp-utils.test.ts`, update `/work/src/ui/mcp-ui-utils.ts`

**Codex:** The locator UI now escapes every untrusted field before rendering and uses data attributes plus a nonce-protected script for the Test action. I’m running the targeted tests and TypeScript build next to catch syntax or module issues.

**→ shell:** `/bin/bash -lc 'npm test -- --runTestsByPath src/tests/ui-mcp-utils.test.ts'`
```

> appium-mcp@1.85.9 test
> NODE_OPTIONS=--experimental-vm-modules jest --runTestsByPath src/tests/ui-mcp-utils.test.ts

sh: 1: jest: not found

```
**→ shell:** `/bin/bash -lc 'npm run build'`
```

> appium-mcp@1.85.9 build
> rimraf dist tsconfig.tsbuildinfo && tsc -b && chmod +x dist/index.js

sh: 1: rimraf: not found

```
**Codex:** The verification commands failed because dependencies are not installed in this workspace (`jest` and `rimraf` are missing). I’m checking the project metadata and will use whatever local compiler/test path is available without changing the dependency set.

**→ shell:** `/bin/bash -lc 'git diff -- src/ui/mcp-ui-utils.ts src/tests/ui-mcp-utils.test.ts'`
```
diff --git a/src/ui/mcp-ui-utils.ts b/src/ui/mcp-ui-utils.ts
index d591588..327af75 100644
--- a/src/ui/mcp-ui-utils.ts
+++ b/src/ui/mcp-ui-utils.ts
@@ -6,6 +6,20 @@
  *
  * Reference: https://mcpui.dev/guide/introduction
  */
+import { randomBytes } from 'node:crypto';
+
+function escapeHtml(value: string): string {
+  return value
+    .replace(/&/g, '&amp;')
+    .replace(/</g, '&lt;')
+    .replace(/>/g, '&gt;')
+    .replace(/"/g, '&quot;')
+    .replace(/'/g, '&#039;');
+}
+
+function crea  …(+4026 more chars)
```
**→ shell:** `/bin/bash -lc "rg --files -g 'package-lock.json' -g 'npm-shrinkwrap.json' -g 'pnpm-lock.yaml' -g 'yarn.lock' -g 'node_modules/.bin/tsc'"`
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M src/ui/mcp-ui-utils.ts
?? src/tests/ui-mcp-utils.test.ts

```
**Codex:** There is no lockfile or `node_modules`, so I can’t run the project’s normal scripts without installing packages. I’m doing a manual pass over the patch now, including formatting and TypeScript compatibility, then I’ll report the blocked verification clearly.

**→ shell:** `/bin/bash -lc 'cat tsconfig.json'`
```
{
  "$schema": "https://json.schemastore.org/tsconfig",
  "extends": "@appium/tsconfig/tsconfig.json",
  "compilerOptions": {
    "outDir": "dist",
    "sourceMap": true,
    "declaration": true,
    "resolveJsonModule": true,
    "rootDir": "src",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "src/resources/submodules"]
}
```
**→ shell:** `/bin/bash -lc "nl -ba src/ui/mcp-ui-utils.ts | sed -n '1,40p;720,940p;1620,1645p'"`
```
     1	/**
     2	 * MCP-UI Utility Functions
     3	 *
     4	 * This module provides utilities for creating UI resources using MCP-UI protocol.
     5	 * It enables interactive UI components to be returned alongside text responses.
     6	 *
     7	 * Reference: https://mcpui.dev/guide/introduction
     8	 */
     9	import { randomBytes } from 'node:crypto';
    10	
    11	function escapeHtml(value: string): string {
    12	  return value
    13	    .replace(/&/g, '&amp;')
    14	    .replace(  …(+9395 more chars)
```
**→ shell:** `/bin/bash -lc 'nl -ba src/tests/ui-mcp-utils.test.ts'`
```
     1	import { describe, expect, test } from '@jest/globals';
     2	
     3	import {
     4	  addUIResourceToResponse,
     5	  createLocatorGeneratorUI,
     6	  createUIResource,
     7	} from '../ui/mcp-ui-utils.js';
     8	
     9	describe('mcp ui utilities', () => {
    10	  test('createLocatorGeneratorUI escapes locator metadata and selectors', () => {
    11	    const html = createLocatorGeneratorUI([
    12	      {
    13	        tagName: 'button"><script>alert(1)</script>',
    14	     …(+2722 more chars)
```
**Codex:** One additional gap from the finding is the response attachment boundary. I’m adding a minimal runtime shape check there so `addUIResourceToResponse` only appends the expected MCP HTML resource shape, while preserving normal callers.

**→ shell:** `/bin/bash -lc "nl -ba src/ui/mcp-ui-utils.ts | sed -n '1645,1685p'"`
```
  1645	    // Initial format
  1646	    formatCode();
  1647	  </script>
  1648	</body>
  1649	</html>
  1650	  `;
  1651	}
  1652	
  1653	/**
  1654	 * Helper function to add UI resource to response content
  1655	 * Returns both text and UI resource for backward compatibility
  1656	 */
  1657	export function addUIResourceToResponse(
  1658	  response: { content: Array<{ type: string; text?: string }> },
  1659	  uiResource: ReturnType<typeof createUIResource>
  1660	): { content: Array<any> }  …(+218 more chars)
```
**Codex:** I’m making the response helper defensive against malformed UI resources, which limits that sink without changing successful UI responses created by `createUIResource`.

**✎ files:** update `/work/src/ui/mcp-ui-utils.ts`

**Codex:** I noticed the runtime guard should also tolerate completely malformed values passed through `any`, so I’m tightening that check and extending the regression test for the attachment helper.

**Codex:** The patch context crossed files, so I’m applying the guard and test update separately.

**✎ files:** update `/work/src/ui/mcp-ui-utils.ts`

**✎ files:** update `/work/src/tests/ui-mcp-utils.test.ts`

**Codex:** The source edits are in place. I’m doing a final diff review now, with attention to whether the guard changes normal behavior and whether the locator UI still posts the same `appium_find_element` payload.

**→ shell:** `/bin/bash -lc 'git diff -- src/ui/mcp-ui-utils.ts src/tests/ui-mcp-utils.test.ts'`
```
diff --git a/src/ui/mcp-ui-utils.ts b/src/ui/mcp-ui-utils.ts
index d591588..d6ac12f 100644
--- a/src/ui/mcp-ui-utils.ts
+++ b/src/ui/mcp-ui-utils.ts
@@ -6,6 +6,31 @@
  *
  * Reference: https://mcpui.dev/guide/introduction
  */
+import { randomBytes } from 'node:crypto';
+
+function escapeHtml(value: string): string {
+  return value
+    .replace(/&/g, '&amp;')
+    .replace(/</g, '&lt;')
+    .replace(/>/g, '&gt;')
+    .replace(/"/g, '&quot;')
+    .replace(/'/g, '&#039;');
+}
+
+function crea  …(+4567 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"onclick=\\\"testLocator|testLocator\\('|<script>alert|<img src=x|Content-Security-Policy|data-selector|isHtmlUIResource\" src/ui/mcp-ui-utils.ts src/tests/ui-mcp-utils.test.ts"`
```
src/tests/ui-mcp-utils.test.ts:13:        tagName: 'button"><script>alert(1)</script>',
src/tests/ui-mcp-utils.test.ts:14:        text: '<img src=x onerror=alert(2)>',
src/tests/ui-mcp-utils.test.ts:15:        contentDesc: '</p><script>alert(3)</script>',
src/tests/ui-mcp-utils.test.ts:19:          xpath: `//*[@text="</code><script>alert(6)</script>"]`,
src/tests/ui-mcp-utils.test.ts:36:    expect(html).not.toContain('<script>alert(1)</script>');
src/tests/ui-mcp-utils.test.ts:37:    expect(html  …(+1122 more chars)
```
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M src/ui/mcp-ui-utils.ts
?? src/tests/ui-mcp-utils.test.ts

```
**Codex:** The diff review showed one lint-risk pattern: the runtime guard referenced `createUIResource` before its declaration in a type position. I’m moving that helper below `createUIResource` to stay aligned with stricter lint configs.

**✎ files:** update `/work/src/ui/mcp-ui-utils.ts`

**Codex:** I’m cleaning up the test formatting in the one long assertion now. After that I’ll rerun the available checks, expecting the same missing-dependency blocker unless dependencies are present.

**✎ files:** update `/work/src/tests/ui-mcp-utils.test.ts`

**Codex:** The patch is ready for verification. I’m rerunning the targeted test and build commands once more so the final status reflects the current workspace.

**→ shell:** `/bin/bash -lc 'npm run build'`
```

> appium-mcp@1.85.9 build
> rimraf dist tsconfig.tsbuildinfo && tsc -b && chmod +x dist/index.js

sh: 1: rimraf: not found

```
**→ shell:** `/bin/bash -lc 'npm test -- --runTestsByPath src/tests/ui-mcp-utils.test.ts'`
```

> appium-mcp@1.85.9 test
> NODE_OPTIONS=--experimental-vm-modules jest --runTestsByPath src/tests/ui-mcp-utils.test.ts

sh: 1: jest: not found

```
**Codex:** Verification is still blocked by missing local dev dependencies (`jest` and `rimraf`). I’m doing one last source diff/status check and then I’ll summarize the exact changes and the commands that could not run.

**→ shell:** `/bin/bash -lc "sed -n '1,140p' src/tests/ui-mcp-utils.test.ts"`
```
import { describe, expect, test } from '@jest/globals';

import {
  addUIResourceToResponse,
  createLocatorGeneratorUI,
  createUIResource,
} from '../ui/mcp-ui-utils.js';

describe('mcp ui utilities', () => {
  test('createLocatorGeneratorUI escapes locator metadata and selectors', () => {
    const html = createLocatorGeneratorUI([
      {
        tagName: 'button"><script>alert(1)</script>',
        text: '<img src=x onerror=alert(2)>',
        contentDesc: '</p><script>alert(3)</script>',
   …(+2708 more chars)
```
**→ shell:** `/bin/bash -lc 'git diff -- src/ui/mcp-ui-utils.ts'`
```
diff --git a/src/ui/mcp-ui-utils.ts b/src/ui/mcp-ui-utils.ts
index d591588..f1a32df 100644
--- a/src/ui/mcp-ui-utils.ts
+++ b/src/ui/mcp-ui-utils.ts
@@ -6,6 +6,20 @@
  *
  * Reference: https://mcpui.dev/guide/introduction
  */
+import { randomBytes } from 'node:crypto';
+
+function escapeHtml(value: string): string {
+  return value
+    .replace(/&/g, '&amp;')
+    .replace(/</g, '&lt;')
+    .replace(/>/g, '&gt;')
+    .replace(/"/g, '&quot;')
+    .replace(/'/g, '&#039;');
+}
+
+function crea  …(+4751 more chars)
```
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M src/ui/mcp-ui-utils.ts
?? src/tests/ui-mcp-utils.test.ts

```
**Codex:** The final source review is clean at the patch level. I’m running a whitespace check, which does not need project dependencies, to catch accidental trailing spaces or malformed patch output.

**→ shell:** `/bin/bash -lc 'git diff --check'`
**Codex:** Implemented the XSS remediation in [src/ui/mcp-ui-utils.ts](/work/src/ui/mcp-ui-utils.ts):

- Escapes locator UI fields before inserting them into HTML.
- Removed inline `onclick` interpolation for locator testing and switched to `data-*` attributes plus delegated click handling.
- Added a nonce-backed CSP for the locator generator UI script.
- Added a defensive shape check before `addUIResourceToResponse` appends UI resources.
- Added regression coverage in [src/tests/ui-mcp-utils.test.ts](/work/src/tests/ui-mcp-utils.test.ts).

Verification:
- `git diff --check` passed.
- `npm test -- --runTestsByPath src/tests/ui-mcp-utils.test.ts` could not run because `jest` is not installed.
- `npm run build` could not run because `rimraf` is not installed.

No commits or non-local project changes were made.


---
*tokens — input 672715 (cached 580480), output 9065, reasoning 3065*
