**Claude:** I'll start by reading the FINDING.txt file to understand the vulnerability.

**→ Read**(file_path=/work/FINDING.txt)
  ↳ *result:* 1	Project: appium/appium-mcp
2	Vulnerability type: Cross-site Scripting (CWE-79)
3	
4	Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):
5	
6	  src/ui/mcp-ui-utils.ts
7	    - lines 720-743   in: export function createLocatorGeneratorUI(
8	    - lines 895-900   in: export function createLocatorGeneratorUI(
9	    -   …(+66 more chars)
**Claude:** I'll read the relevant file to understand the vulnerability.

**→ Read**(file_path=/work/src/ui/mcp-ui-utils.ts, limit=60)
  ↳ *result:* 1	/**
2	 * MCP-UI Utility Functions
3	 *
4	 * This module provides utilities for creating UI resources using MCP-UI protocol.
5	 * It enables interactive UI components to be returned alongside text responses.
6	 *
7	 * Reference: https://mcpui.dev/guide/introduction
8	 */
9	
10	/**
11	 * Creates a UIResource object following MCP-UI protocol
12	 * @  …(+1335 more chars)
**Claude:** Let me look at the specific vulnerable areas and the function signatures.

**→ Read**(file_path=/work/src/ui/mcp-ui-utils.ts, offset=680, limit=280)
  ↳ *result:* 680	        }
681	      }, '*');
682	    }
683	
684	    function deleteSession() {
685	      if (confirm('Are you sure you want to end this session?')) {
686	        window.parent.postMessage({
687	          type: 'tool',
688	          payload: {
689	            toolName: 'delete_session',
690	            params: {}
691	          }
692	        }, '  …(+7496 more chars)
**Claude:** Let me look at the third vulnerable area (around lines 1633-1635) and check for existing escape helpers.

**→ Read**(file_path=/work/src/ui/mcp-ui-utils.ts, offset=1600, limit=80)
  ↳ *result:* 1600	    function formatCode() {
1601	      // Basic formatting - could be enhanced with a proper formatter
1602	      const content = document.getElementById('codeContent');
1603	      const text = content.textContent;
1604	      // Add line numbers
1605	      const lines = text.split('\\n');
1606	      const formatted = lines.map((line, i) =>
160  …(+826 more chars)
**Claude:** Let me check whether there's an existing HTML-escape helper in the file and how other functions handle escaping.

**→ Bash**(command=grep -n "escape\|&amp;\|&lt;\|function escapeHtml\|replace(/&/g" src/ui/mcp-ui-utils.ts | head -50)
  ↳ *result:* 911:  const escapedSource = pageSource
912:    .replace(/&/g, '&amp;')
913:    .replace(/</g, '&lt;')
1028:    <pre class="xml-content" id="xmlContent">${escapedSource}</pre>
1066:        content.innerHTML = \`${escapedSource}\`;
1470:  const escapedCode = code
1471:    .replace(/&/g, '&amp;')
1472:    .replace(/</g, '&lt;')
1579:    <pre class="co  …(+49 more chars)
**Claude:** The vulnerability is in `createLocatorGeneratorUI`: device-controlled element data (`tagName`, `text`, `contentDesc`, `resourceId`, and locator `strategy`/`selector`) is interpolated directly into HTML without escaping. Other functions in this file (like `createPageSourceInspectorUI`) already escape their input, but `createLocatorGeneratorUI` does not. Let me add a reusable escape helper and apply it.

Let me first add a shared `escapeHtml` helper near the top of the file.

**→ Edit**(replace_all=false, file_path=/work/src/ui/mcp-ui-utils.ts, old_string=/**
 * Creates a UIResource object following MCP-UI protocol
 * @param uri - Unique identifier using ui:// scheme (e.g., 'ui://appium-mcp/de  …(+152 more chars), new_string=/**
 * Escapes a string for safe interpolation into HTML markup.
 *
 * Encodes the characters that are significant in HTML so that
 * attack  …(+724 more chars))
  ↳ *result:* The file /work/src/ui/mcp-ui-utils.ts has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now fix the locator card rendering. I'll escape all interpolated values and replace the inline `onclick` (which embeds data in a nested JS-in-HTML-attribute context) with safe data attributes + event delegation.

**→ Edit**(replace_all=false, file_path=/work/src/ui/mcp-ui-utils.ts, old_string=    <div class="locator-card" data-index="${index}">
      <div class="locator-header">
        <h3>${element.tagName}</h3>
        <div cla  …(+1149 more chars), new_string=    <div class="locator-card" data-index="${index}">
      <div class="locator-header">
        <h3>${escapeHtml(element.tagName)}</h3>
      …(+1226 more chars))
  ↳ *result:* The file /work/src/ui/mcp-ui-utils.ts has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now update the script to use event delegation reading the data attributes, preserving the same behavior:

**→ Edit**(replace_all=false, file_path=/work/src/ui/mcp-ui-utils.ts, old_string=  <script>
    function testLocator(strategy, selector) {
      window.parent.postMessage({
        type: 'tool',
        payload: {
         …(+249 more chars), new_string=  <script>
    function testLocator(strategy, selector) {
      window.parent.postMessage({
        type: 'tool',
        payload: {
         …(+598 more chars))
  ↳ *result:* The file /work/src/ui/mcp-ui-utils.ts has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now let me verify the change compiles cleanly with TypeScript.

**→ Bash**(command=(npx tsc --noEmit -p tsconfig.json 2>&1 | head -30 || echo "tsc-failed"); echo "exit: $?")
  ↳ *result:* npm warn exec The following package was not found and will be installed: tsc@2.0.4
npm warn deprecated tsc@2.0.4: Package no longer supported. Contact Support at https://www.npmjs.com/support for more info.

[41m                                                                               [0m
[41m[37m                This is not the tsc command  …(+619 more chars)
**→ Bash**(command=ls node_modules/.bin/tsc 2>/dev/null && ./node_modules/.bin/tsc --noEmit 2>&1 | head -30; echo "exit: ${PIPESTATUS[1]:-$?}")
  ↳ *result:* exit: 2
**→ Bash**(command=cat package.json | python3 -c "import json,sys; d=json.load(sys.stdin); print('scripts:', json.dumps(d.get('scripts',{}),indent=2)); print('  …(+167 more chars))
  ↳ *result:* scripts: {
  "build": "rimraf dist tsconfig.tsbuildinfo && tsc -b && chmod +x dist/index.js",
  "start": "node dist/index.js",
  "start:stdio": "node dist/index.js",
  "start:httpStream": "node dist/index.js --httpStream",
  "start:httpStream:port": "node dist/index.js --httpStream --port=",
  "telemetry:jaeger:start": "sh tools/telemetry/jaeger.sh  …(+1282 more chars)
**Claude:** No `node_modules` installed, so I can't run the project's compiler without a full install. My changes are straightforward and syntactically valid TypeScript. Let me verify the edited regions read correctly.

**→ Read**(file_path=/work/src/ui/mcp-ui-utils.ts, offset=734, limit=28)
  ↳ *result:* 734	    displayed: boolean;
735	  }>
736	): string {
737	  const locatorCards = locators
738	    .map(
739	      (element, index) => `
740	    <div class="locator-card" data-index="${index}">
741	      <div class="locator-header">
742	        <h3>${escapeHtml(element.tagName)}</h3>
743	        <div class="badges">
744	          ${element.clickable   …(+1182 more chars)
**Claude:** The fix is complete and consistent. Here's a summary of what I did.

## Vulnerability

**Cross-site Scripting (CWE-79)** in `src/ui/mcp-ui-utils.ts`, in `createLocatorGeneratorUI()`. This function builds an HTML UI from element data scraped off the device under test (`tagName`, `text`, `contentDesc`, `resourceId`, and locator `strategy`/`selector`). Those values were interpolated directly into HTML markup with no escaping, so a malicious app screen (e.g. an element whose text is `<img src=x onerror=...>`) could inject arbitrary markup/script into the rendered UI resource. The worst case was line 740, where `selector` and `strategy` were embedded into an inline `onclick="testLocator('...', \`...\`)"` — a nested JS-in-HTML-attribute context that only escaped backticks, leaving `"`, `'`, and `</script>`-style breakouts wide open.

## Remediation (behavior-preserving)

1. **Added a reusable `escapeHtml()` helper** at the top of the file, encoding `& < > " '` — the same encoding the file's other functions (`createPageSourceInspectorUI`, the code viewer) already apply to their inputs.

2. **Escaped every interpolated value** in the locator cards: `tagName`, `text`, `contentDesc`, `resourceId`, `strategy`, and `selector`.

3. **Removed the inline `onclick`** that embedded data in a nested JS string context. The values now go into `data-strategy` / `data-selector` attributes (HTML-escaped), and the buttons are wired up with `addEventListener` via event delegation in the existing script. The `testLocator()` postMessage behavior is identical — values are just passed as data instead of being spliced into code.

I left `addUIResourceToResponse()` unchanged: it's the generic delivery sink that merely appends the resource object to the response content array and has nothing to encode — the injection is fixed at its source, where the untrusted data is rendered into HTML.

Note: I couldn't run the project's TypeScript compiler since `node_modules` isn't installed here, but the edits use only standard string operations and a standard helper, and are syntactically valid TypeScript.


---
**Final (success):** The fix is complete and consistent. Here's a summary of what I did.

## Vulnerability

**Cross-site Scripting (CWE-79)** in `src/ui/mcp-ui-utils.ts`, in `createLocatorGeneratorUI()`. This function builds an HTML UI from element data scraped off the device under test (`tagName`, `text`, `contentDesc`, `resourceId`, and locator `strategy`/`selector`). Those values were interpolated directly into HTML markup with no escaping, so a malicious app screen (e.g. an element whose text is `<img src=x onerror=...>`) could inject arbitrary markup/script into the rendered UI resource. The worst case was line 740, where `selector` and `strategy` were embedded into an inline `onclick="testLocator('...', \`...\`)"` — a nested JS-in-HTML-attribute context that only escaped backticks, leaving `"`, `'`, and `</script>`-style breakouts wide open.

## Remediation (behavior-preserving)

1. **Added a reusable `escapeHtml()` helper** at the top of the file, encoding `& < > " '` — the same encoding the file's other functions (`createPageSourceInspectorUI`, the code viewer) already apply to their inputs.

2. **Escaped every interpolated value** in the locator cards: `tagName`, `text`, `contentDesc`, `resourceId`, `strategy`, and `selector`.

3. **Removed the inline `onclick`** that embedded data in a nested JS string context. The values now go into `data-strategy` / `data-selector` attributes (HTML-escaped), and the buttons are wired up with `addEventListener` via event delegation in the existing script. The `testLocator()` postMessage behavior is identical — values are just passed as data instead of being spliced into code.

I left `addUIResourceToResponse()` unchanged: it's the generic delivery sink that merely appends the resource object to the response content array and has nothing to encode — the injection is fixed at its source, where the untrusted data is rendered into HTML.

Note: I couldn't run the project's TypeScript compiler since `node_modules` isn't installed here, but the edits use only standard string operations and a standard helper, and are syntactically valid TypeScript.

*turns 13 · cost $0.53*
