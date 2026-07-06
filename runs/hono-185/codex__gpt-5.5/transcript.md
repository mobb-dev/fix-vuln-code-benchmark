**Codex:** I’ll inspect the vulnerability note and the surrounding code first, then patch only the affected local source. After that I’ll run the relevant checks I can find in the project.

**→ shell:** `/bin/bash -lc ls`
```
FINDING.txt
LICENSE
README.md
benchmarks
build
bun.lock
bunfig.toml
codecov.yml
docs
eslint.config.mjs
jsr.json
package.cjs.json
package.json
perf-measures
runtime-tests
src
tsconfig.base.json
tsconfig.build.json
tsconfig.json
tsconfig.spec.json
vitest.config.ts

```
**→ shell:** `/bin/bash -lc "pwd && rg --files -g 'FINDING.txt' -g '"'!*node_modules*'"' -g '"'!*.git*'"'"`
```
/work
FINDING.txt

```
**Codex:** I found the project layout and the finding file. Next I’m reading the report plus package metadata so I can identify the test/build commands without guessing.

**→ shell:** `/bin/bash -lc "sed -n '1,220p' FINDING.txt"`
```
Project: honojs/hono
Vulnerability type: Incorrect Regular Expression (CWE-185)

Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):

  src/middleware/ip-restriction/index.ts
    - lines 6-18
    - lines 35-47   in: type GetIPAddr = GetConnInfo | ((c: Context) => string)
    - lines 59-65   in: const buildMatcher = (
    - lines 79-99   in: const buildMatcher = (
    - lines 115-120   in: const buildMatcher = (
    - lines 221-234   in: export const ipRestrictio  …(+291 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,220p' package.json"`
```
{
  "name": "hono",
  "version": "4.12.20",
  "description": "Web framework built on Web Standards",
  "main": "dist/cjs/index.js",
  "type": "module",
  "module": "dist/index.js",
  "types": "dist/types/index.d.ts",
  "files": [
    "dist"
  ],
  "scripts": {
    "test": "tsc --noEmit && vitest --run",
    "test:watch": "vitest --watch",
    "test:deno": "deno test --allow-read --allow-env --allow-write --allow-net -c runtime-tests/deno/deno.json runtime-tests/deno && deno test --no-lock -c run  …(+8494 more chars)
```
**→ shell:** `/bin/bash -lc "rg --files src runtime-tests | sed -n '1,160p'"`
```
runtime-tests/deno-jsx/jsx.test.tsx
runtime-tests/deno-jsx/deno.precompile.json
runtime-tests/deno-jsx/deno.react-jsx.json
src/router/common.case.test.ts
runtime-tests/node/vitest.config.ts
runtime-tests/node/tsconfig.json
runtime-tests/node/index.test.ts
src/router/trie-router/index.ts
src/router/trie-router/node.test.ts
src/router/trie-router/router.test.ts
src/router/trie-router/router.ts
src/router/trie-router/node.ts
runtime-tests/lambda/vitest.config.ts
runtime-tests/lambda/tsconfig.json
r  …(+4645 more chars)
```
**Codex:** The report points at IP parsing and matching. I’m going to inspect those files and their tests now, especially any regex-based validation that accepts malformed addresses or creates expensive matching paths.

**→ shell:** `/bin/bash -lc "nl -ba src/middleware/ip-restriction/index.ts | sed -n '1,280p'"`
```
     1	/**
     2	 * IP Restriction Middleware for Hono
     3	 * @module
     4	 */
     5	
     6	import type { Context, MiddlewareHandler } from '../..'
     7	import type { AddressType, GetConnInfo } from '../../helper/conninfo'
     8	import { HTTPException } from '../../http-exception'
     9	import {
    10	  convertIPv4MappedIPv6ToIPv4,
    11	  convertIPv4ToBinary,
    12	  convertIPv6BinaryToString,
    13	  convertIPv6ToBinary,
    14	  distinctRemoteAddr,
    15	  isIPv4MappedIPv6,
   …(+8178 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba src/utils/ipaddr.ts | sed -n '1,180p'"`
```
     1	/**
     2	 * Utils for IP Addresses
     3	 * @module
     4	 */
     5	
     6	import type { AddressType } from '../helper/conninfo'
     7	
     8	/**
     9	 * Expand IPv6 Address
    10	 * @param ipV6 Shorten IPv6 Address
    11	 * @return expanded IPv6 Address
    12	 */
    13	export const expandIPv6 = (ipV6: string): string => {
    14	  const sections = ipV6.split(':')
    15	  if (IPV4_REGEX.test(sections.at(-1) as string)) {
    16	    sections.splice(
    17	      -1,
    18	   …(+4705 more chars)
```
**→ shell:** `/bin/bash -lc 'rg -n "ipRestriction|expandIPv6|distinctRemoteAddr|convertIPv4ToBinary|ipaddr" src runtime-tests'`
```
src/utils/ipaddr.test.ts:3:  convertIPv4ToBinary,
src/utils/ipaddr.test.ts:6:  distinctRemoteAddr,
src/utils/ipaddr.test.ts:7:  expandIPv6,
src/utils/ipaddr.test.ts:8:} from './ipaddr'
src/utils/ipaddr.test.ts:10:describe('expandIPv6', () => {
src/utils/ipaddr.test.ts:12:    expect(expandIPv6('1::1')).toBe('0001:0000:0000:0000:0000:0000:0000:0001')
src/utils/ipaddr.test.ts:13:    expect(expandIPv6('::1')).toBe('0000:0000:0000:0000:0000:0000:0000:0001')
src/utils/ipaddr.test.ts:14:    expect(expa  …(+4506 more chars)
```
**Codex:** I’ve confirmed the weak spot: IPv6 is currently classified by `includes(':')`, and conversion assumes validation already happened. I’m checking tests around these helpers and the middleware so the fix preserves accepted valid formats while rejecting malformed ones deterministically.

**→ shell:** `/bin/bash -lc "nl -ba src/utils/ipaddr.test.ts | sed -n '1,220p'"`
```
     1	import {
     2	  convertIPv4BinaryToString,
     3	  convertIPv4ToBinary,
     4	  convertIPv6BinaryToString,
     5	  convertIPv6ToBinary,
     6	  distinctRemoteAddr,
     7	  expandIPv6,
     8	} from './ipaddr'
     9	
    10	describe('expandIPv6', () => {
    11	  it('Should result be valid', () => {
    12	    expect(expandIPv6('1::1')).toBe('0001:0000:0000:0000:0000:0000:0000:0001')
    13	    expect(expandIPv6('::1')).toBe('0000:0000:0000:0000:0000:0000:0000:0001')
    14	    exp  …(+3782 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba src/middleware/ip-restriction/index.test.ts | sed -n '1,260p'"`
```
     1	import { Context } from '../../context'
     2	import type { AddressType, GetConnInfo } from '../../helper/conninfo'
     3	import { Hono } from '../../hono'
     4	import { ipRestriction } from '.'
     5	import type { IPRestrictionRule } from '.'
     6	
     7	describe('ipRestriction middleware', () => {
     8	  it('Should restrict', async () => {
     9	    const getConnInfo: GetConnInfo = (c) => {
    10	      return {
    11	        remote: {
    12	          address: c.env.ip,
     …(+6171 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"AddressType|type AddressType|interface ConnInfo|addressType\" src/helper src/adapter src | sed -n '1,200p'"`
```
src/adapter/cloudflare-workers/conninfo.test.ts:17:    expect(info.remote.addressType).toBeUndefined()
src/adapter/bun/conninfo.test.ts:2:import type { AddressType } from '../../helper/conninfo'
src/adapter/bun/conninfo.test.ts:12:  family?: AddressType | string
src/adapter/bun/conninfo.test.ts:36:    expect(info.remote.addressType).toBe('IPv6')
src/adapter/bun/conninfo.test.ts:47:    expect(info.remote.addressType).toBe('IPv6')
src/adapter/bun/conninfo.test.ts:50:  it('should return undefined w  …(+3731 more chars)
```
**Codex:** The current tests intentionally normalize `1234:::5678`, which is not a valid IPv6 literal. I’m going to tighten parsing around valid IP literals and CIDR prefixes; that changes only malformed input handling, while preserving valid IPv4, IPv6, IPv4-mapped IPv6, and CIDR behavior.

**Codex:** I’m making the parser changes now: replacing colon-presence detection with bounded IPv4/IPv6 validation, making binary conversion reject invalid literals, and hardening CIDR parsing so empty or out-of-range prefixes never reach bigint shifts.

**✎ files:** update `/work/src/utils/ipaddr.ts`

**Codex:** The IP utility now validates literals structurally instead of relying on a regex or `includes(':')`. I’m applying the corresponding middleware hardening so invalid remote addresses are blocked and invalid CIDR rules fail during setup.

**✎ files:** update `/work/src/middleware/ip-restriction/index.ts`

**Codex:** I noticed one existing path still trusts adapter-provided address types. I’m tightening that now by verifying the actual address string matches its declared type before any rule matching.

**✎ files:** update `/work/src/middleware/ip-restriction/index.ts`

**Codex:** I’m adding regression tests for malformed IPv6 literals, invalid IPv4 conversion, and CIDR prefixes. One small parser edge case also needs guarding: dotted IPv4 syntax inside IPv6 must actually be after a colon.

**✎ files:** update `/work/src/utils/ipaddr.ts`

**Codex:** Now I’m updating the focused tests so they lock in the remediation: invalid literals are rejected instead of normalized, and bad CIDR rules fail at middleware construction.

**✎ files:** update `/work/src/utils/ipaddr.test.ts`

**Codex:** The helper tests are updated. I’m adding middleware coverage for invalid remote addresses and malformed CIDR strings, including out-of-range prefixes.

**✎ files:** update `/work/src/middleware/ip-restriction/index.test.ts`

**Codex:** The source and regression tests are patched. I’m going to run the focused test files first, then address any type or formatting failures they expose.

**→ shell:** `/bin/bash -lc 'bun test src/utils/ipaddr.test.ts src/middleware/ip-restriction/index.test.ts'`
```
/bin/bash: line 1: bun: command not found

```
**→ shell:** `/bin/bash -lc "nl -ba src/utils/ipaddr.ts | sed -n '1,180p'"`
```
     1	/**
     2	 * Utils for IP Addresses
     3	 * @module
     4	 */
     5	
     6	import type { AddressType } from '../helper/conninfo'
     7	
     8	const parseIPv4ToParts = (ipv4: string): number[] | undefined => {
     9	  const parts = ipv4.split('.')
    10	  if (parts.length !== 4) {
    11	    return
    12	  }
    13	
    14	  const parsed = []
    15	  for (const part of parts) {
    16	    if (part.length === 0 || (part.length > 1 && part[0] === '0')) {
    17	      return
    1  …(+5037 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba src/middleware/ip-restriction/index.ts | sed -n '1,260p'"`
```
     1	/**
     2	 * IP Restriction Middleware for Hono
     3	 * @module
     4	 */
     5	
     6	import type { Context, MiddlewareHandler } from '../..'
     7	import type { AddressType, GetConnInfo } from '../../helper/conninfo'
     8	import { HTTPException } from '../../http-exception'
     9	import {
    10	  convertIPv4MappedIPv6ToIPv4,
    11	  convertIPv4ToBinary,
    12	  convertIPv6BinaryToString,
    13	  convertIPv6ToBinary,
    14	  distinctRemoteAddr,
    15	  isIPv4MappedIPv6,
   …(+8969 more chars)
```
**Codex:** The focused test command could not run because `bun` is not installed in this environment. I’m checking what local tooling is available so I can still run TypeScript/tests without installing anything.

**→ shell:** `/bin/bash -lc "test -d node_modules && rg --files node_modules/.bin | sed -n '1,80p' || true"`
**→ shell:** `/bin/bash -lc 'node --version'`
```
v22.23.0

```
**→ shell:** `/bin/bash -lc "sed -n '1,220p' src/utils/ipaddr.test.ts"`
```
import {
  convertIPv4BinaryToString,
  convertIPv4ToBinary,
  convertIPv6BinaryToString,
  convertIPv6ToBinary,
  distinctRemoteAddr,
  expandIPv6,
} from './ipaddr'

describe('expandIPv6', () => {
  it('Should result be valid', () => {
    expect(expandIPv6('1::1')).toBe('0001:0000:0000:0000:0000:0000:0000:0001')
    expect(expandIPv6('::1')).toBe('0000:0000:0000:0000:0000:0000:0000:0001')
    expect(expandIPv6('2001:2::')).toBe('2001:0002:0000:0000:0000:0000:0000:0000')
    expect(expandIPv6(  …(+4099 more chars)
```
**→ shell:** `/bin/bash -lc 'npm --version'`
```
10.9.8

```
**Codex:** There is no `node_modules` directory either, so local test binaries are absent. I also spotted a formatting artifact in one test table from the patch; I’ll clean that up before running any downloaded tooling.

**✎ files:** update `/work/src/utils/ipaddr.test.ts`

**Codex:** The code path is now tighter, but I need an actual type/test run. Since the repo has no installed dependencies and `bun` is unavailable, I’m checking the declared dev tool versions and then I’ll use `npx` for targeted verification without editing lockfiles.

**→ shell:** `/bin/bash -lc "rg -n '\"(typescript|vitest|prettier|eslint)\"' package.json"`
```
671:    "eslint": "^9.39.3",
678:    "prettier": "3.7.4",
680:    "typescript": "^5.9.2",
683:    "vitest": "^3.2.4",

```
**→ shell:** `/bin/bash -lc 'git diff -- src/utils/ipaddr.ts src/utils/ipaddr.test.ts src/middleware/ip-restriction/index.ts src/middleware/ip-restriction/index.test.ts'`
```
diff --git a/src/middleware/ip-restriction/index.test.ts b/src/middleware/ip-restriction/index.test.ts
index 6f54095..3c1ef43 100644
--- a/src/middleware/ip-restriction/index.test.ts
+++ b/src/middleware/ip-restriction/index.test.ts
@@ -60,6 +60,25 @@ describe('ipRestriction middleware', () => {
       expect(await res.text()).toBe('error')
     }
   })
+
+  it('Should block invalid remote addresses', async () => {
+    const app = new Hono<{
+      Bindings: {
+        ip: string
+      }
+      …(+12238 more chars)
```
**Codex:** Before running verification, I’m cleaning up a couple of small TypeScript details in the parser: explicit number array typing and avoiding repeated dotted-IPv4 checks.

**✎ files:** update `/work/src/utils/ipaddr.ts`

**Codex:** I’m going to use `npx` for formatter, type checking, and the focused Vitest files because this checkout has neither `bun` nor installed `node_modules`.

**→ shell:** `/bin/bash -lc 'npx --yes prettier@3.7.4 --write src/utils/ipaddr.ts src/utils/ipaddr.test.ts src/middleware/ip-restriction/index.ts src/middleware/ip-restriction/index.test.ts'`
```
npm error code E403
npm error 403 403 blocked by egress allowlist - GET https://registry.npmjs.org/prettier
npm error 403 In most cases, you or one of your dependencies are requesting
npm error 403 a package version that is forbidden by your security policy, or
npm error 403 on a server you do not have access to.
npm error A complete log of this run can be found in: /root/.npm/_logs/2026-06-30T15_22_56_367Z-debug-0.log

```
**Codex:** `npx` is blocked by the environment’s npm egress policy, so I can’t download the project tools. I’ll do a manual formatting pass and then use whatever local static checks are possible.

**→ shell:** `/bin/bash -lc 'git diff --check -- src/utils/ipaddr.ts src/utils/ipaddr.test.ts src/middleware/ip-restriction/index.ts src/middleware/ip-restriction/index.test.ts'`
**→ shell:** `/bin/bash -lc "find /root/.npm -maxdepth 5 -type f -name 'prettier' -o -name 'vitest' -o -name 'tsc' 2>/dev/null | sed -n '1,120p'"`
**→ shell:** `/bin/bash -lc "find /work -maxdepth 3 -type f \\( -path '*/node_modules/.bin/*' -o -name 'tsc' -o -name 'vitest' -o -name 'prettier' \\) | sed -n '1,120p'"`
**Codex:** There are no local test or formatter binaries available, but the edited files pass `git diff --check` for whitespace. I’m reviewing the final diff and then I’ll run any lightweight syntax checks possible with plain Node.

**→ shell:** `/bin/bash -lc "sed -n '1,180p' src/utils/ipaddr.ts"`
```
/**
 * Utils for IP Addresses
 * @module
 */

import type { AddressType } from '../helper/conninfo'

const parseIPv4ToParts = (ipv4: string): number[] | undefined => {
  const parts = ipv4.split('.')
  if (parts.length !== 4) {
    return
  }

  const parsed: number[] = []
  for (const part of parts) {
    if (part.length === 0 || (part.length > 1 && part[0] === '0')) {
      return
    }

    let value = 0
    for (let i = 0; i < part.length; i++) {
      const code = part.charCodeAt(i)
      i  …(+3810 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,180p' src/middleware/ip-restriction/index.test.ts"`
```
import { Context } from '../../context'
import type { AddressType, GetConnInfo } from '../../helper/conninfo'
import { Hono } from '../../hono'
import { ipRestriction } from '.'
import type { IPRestrictionRule } from '.'

describe('ipRestriction middleware', () => {
  it('Should restrict', async () => {
    const getConnInfo: GetConnInfo = (c) => {
      return {
        remote: {
          address: c.env.ip,
        },
      }
    }
    const app = new Hono<{
      Bindings: {
        ip: strin  …(+6184 more chars)
```
**→ shell:** `/bin/bash -lc 'git diff --stat && git diff -- src/utils/ipaddr.ts src/middleware/ip-restriction/index.ts'`
```
 src/middleware/ip-restriction/index.test.ts |  29 ++++++
 src/middleware/ip-restriction/index.ts      |  46 ++++++++--
 src/utils/ipaddr.test.ts                    |  27 +++++-
 src/utils/ipaddr.ts                         | 137 ++++++++++++++++++++++------
 4 files changed, 202 insertions(+), 37 deletions(-)
diff --git a/src/middleware/ip-restriction/index.ts b/src/middleware/ip-restriction/index.ts
index 9ebf306..18f3818 100644
--- a/src/middleware/ip-restriction/index.ts
+++ b/src/middleware/  …(+7698 more chars)
```
**Codex:** The final diff looks coherent. I’m checking for globally available TypeScript tooling now; if it exists, I’ll use that instead of package-managed binaries.

**→ shell:** `/bin/bash -lc 'command -v prettier || true'`
**→ shell:** `/bin/bash -lc 'command -v tsc || true'`
**→ shell:** `/bin/bash -lc 'command -v vitest || true'`
**→ shell:** `/bin/bash -lc 'command -v eslint || true'`
**Codex:** No global `tsc`, `vitest`, `prettier`, or `eslint` binaries are present. I’m doing one more manual pass for edge cases in the CIDR and parser logic before wrapping up with the verification limitation clearly stated.

**→ shell:** `/bin/bash -lc 'git diff -- src/utils/ipaddr.test.ts src/middleware/ip-restriction/index.test.ts'`
```
diff --git a/src/middleware/ip-restriction/index.test.ts b/src/middleware/ip-restriction/index.test.ts
index 6f54095..3c1ef43 100644
--- a/src/middleware/ip-restriction/index.test.ts
+++ b/src/middleware/ip-restriction/index.test.ts
@@ -60,6 +60,25 @@ describe('ipRestriction middleware', () => {
       expect(await res.text()).toBe('error')
     }
   })
+
+  it('Should block invalid remote addresses', async () => {
+    const app = new Hono<{
+      Bindings: {
+        ip: string
+      }
+      …(+4389 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"IPV4_REGEX|IS_CIDR|includes\\(':\\'\\)|1234:::5678|/\\[0-9\\]\" src/utils/ipaddr.ts src/middleware/ip-restriction/index.ts src/utils/ipaddr.test.ts src/middleware/ip-restriction  …(+15 more chars)`
```
src/middleware/ip-restriction/index.test.ts:79:    expect((await app.request('/basic', {}, { ip: '1234:::5678' })).status).toBe(403)
src/utils/ipaddr.test.ts:21:    expect(() => expandIPv6('1234:::5678')).toThrow(TypeError)
src/utils/ipaddr.test.ts:39:    expect(distinctRemoteAddr('1234:::5678')).toBeUndefined()
src/utils/ipaddr.test.ts:97:    expect(() => convertIPv6ToBinary('1234:::5678')).toThrow(TypeError)

```
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M src/middleware/ip-restriction/index.test.ts
 M src/middleware/ip-restriction/index.ts
 M src/utils/ipaddr.test.ts
 M src/utils/ipaddr.ts

```
**Codex:** One small cleanup remains in the middleware: compute the inferred address type once, then compare it with any adapter-provided type. That keeps the validation clear and avoids parsing the same address twice.

**✎ files:** update `/work/src/middleware/ip-restriction/index.ts`

**Codex:** Node 22 may be able to strip TypeScript types directly, so I’m trying a lightweight runtime import of the edited utility. If that works, I can at least exercise the parser behavior without Vitest.

**→ shell:** `/bin/bash -lc "node --experimental-strip-types --input-type=module <<'EOF'
import { distinctRemoteAddr, expandIPv6, convertIPv4ToBinary, convertIPv6ToBinary } from './src/utils/ipaddr.ts'
const checks  …(+749 more chars)`
**Codex:** The direct Node runtime check of the IP utility passed. I’m doing final whitespace and status checks now.

**→ shell:** `/bin/bash -lc 'git diff --check'`
**→ shell:** `/bin/bash -lc 'git diff --stat'`
```
 src/middleware/ip-restriction/index.test.ts |  29 ++++++
 src/middleware/ip-restriction/index.ts      |  50 ++++++++--
 src/utils/ipaddr.test.ts                    |  27 +++++-
 src/utils/ipaddr.ts                         | 137 ++++++++++++++++++++++------
 4 files changed, 204 insertions(+), 39 deletions(-)

```
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M src/middleware/ip-restriction/index.test.ts
 M src/middleware/ip-restriction/index.ts
 M src/utils/ipaddr.test.ts
 M src/utils/ipaddr.ts

```
**Codex:** Whitespace checks are clean. Since full project tests are blocked by missing tooling, I’m collecting the exact changed line references for the final summary.

**→ shell:** `/bin/bash -lc "nl -ba src/utils/ipaddr.ts | sed -n '1,170p'"`
```
     1	/**
     2	 * Utils for IP Addresses
     3	 * @module
     4	 */
     5	
     6	import type { AddressType } from '../helper/conninfo'
     7	
     8	const parseIPv4ToParts = (ipv4: string): number[] | undefined => {
     9	  const parts = ipv4.split('.')
    10	  if (parts.length !== 4) {
    11	    return
    12	  }
    13	
    14	  const parsed: number[] = []
    15	  for (const part of parts) {
    16	    if (part.length === 0 || (part.length > 1 && part[0] === '0')) {
    17	      re  …(+4687 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba src/middleware/ip-restriction/index.ts | sed -n '35,120p;240,260p'"`
```
    35	type IPRestrictionRuleFunction = (addr: { addr: string; type: AddressType }) => boolean
    36	export type IPRestrictionRule = string | ((addr: { addr: string; type: AddressType }) => boolean)
    37	
    38	const parseCIDRRule = (rule: string): [string, number] | undefined => {
    39	  const separatorIndex = rule.indexOf('/')
    40	  if (separatorIndex === -1) {
    41	    return
    42	  }
    43	  if (separatorIndex !== rule.lastIndexOf('/')) {
    44	    throw new TypeError(`Invalid  …(+3781 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba src/utils/ipaddr.test.ts | sed -n '1,125p'"`
```
     1	import {
     2	  convertIPv4BinaryToString,
     3	  convertIPv4ToBinary,
     4	  convertIPv6BinaryToString,
     5	  convertIPv6ToBinary,
     6	  distinctRemoteAddr,
     7	  expandIPv6,
     8	} from './ipaddr'
     9	
    10	describe('expandIPv6', () => {
    11	  it('Should result be valid', () => {
    12	    expect(expandIPv6('1::1')).toBe('0001:0000:0000:0000:0000:0000:0000:0001')
    13	    expect(expandIPv6('::1')).toBe('0000:0000:0000:0000:0000:0000:0000:0001')
    14	    exp  …(+4908 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba src/middleware/ip-restriction/index.test.ts | sed -n '60,155p'"`
```
    60	      expect(await res.text()).toBe('error')
    61	    }
    62	  })
    63	
    64	  it('Should block invalid remote addresses', async () => {
    65	    const app = new Hono<{
    66	      Bindings: {
    67	        ip: string
    68	      }
    69	    }>()
    70	    app.use(
    71	      '/basic',
    72	      ipRestriction((c) => c.env.ip, {
    73	        allowList: ['::1'],
    74	      })
    75	    )
    76	    app.get('/basic', (c) => c.text('Hello World!'))
    77	
    78	      …(+4086 more chars)
```
**Codex:** Implemented the remediation locally.

Changed:
- [src/utils/ipaddr.ts](/work/src/utils/ipaddr.ts:8): replaced regex/colon-based IP detection with bounded IPv4 and IPv6 parsing, including strict IPv4-mapped IPv6 handling.
- [src/middleware/ip-restriction/index.ts](/work/src/middleware/ip-restriction/index.ts:38): hardened CIDR parsing, rejects empty/non-numeric/out-of-range prefixes, and blocks invalid or mismatched remote address types.
- Added regression coverage in [src/utils/ipaddr.test.ts](/work/src/utils/ipaddr.test.ts:20) and [src/middleware/ip-restriction/index.test.ts](/work/src/middleware/ip-restriction/index.test.ts:64).

Verification:
- `git diff --check` passed.
- A direct Node `--experimental-strip-types` smoke test of the IP utility passed.
- Full project tests were not runnable here: `bun` is not installed, no `node_modules` exist, and `npx` package download is blocked by the environment’s npm egress policy.


---
*tokens — input 1015101 (cached 949120), output 12936, reasoning 3884*
