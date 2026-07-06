**→ Read**(file_path=/work/FINDING.txt)
  ↳ *result:* 1	Project: googleapis/mcp-toolbox
2	Vulnerability type: Improper Authentication (CWE-287)
3	
4	Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):
5	
6	  internal/auth/generic/generic.go
7	    - lines 155-160   in: func discoverOIDCConfig(client *http.Client, AuthorizationServer string) (jwksUR
8	    - lines 471-48  …(+91 more chars)
**→ Read**(file_path=/work/internal/auth/generic/generic.go)
  ↳ *result:* 1	// Copyright 2026 Google LLC
2	//
3	// Licensed under the Apache License, Version 2.0 (the "License");
4	// you may not use this file except in compliance with the License.
5	// You may obtain a copy of the License at
6	//
7	//	http://www.apache.org/licenses/LICENSE-2.0
8	//
9	// Unless required by applicable law or agreed to in writing, software  …(+17595 more chars)
**Claude:** I've read both the finding and the vulnerable code. Let me analyze the issue.

The vulnerability is **Improper Authentication via missing/skippable issuer (`iss`) validation**:

1. **`discoverOIDCConfig` (lines ~149-172):** It requires `jwks_uri` to be present but never requires or validates the `issuer` field from the OIDC discovery document. Per the OIDC Discovery spec (and RFC 8414), the `issuer` value MUST be present and MUST match the authorization server URL. If it's missing, `a.issuer` ends up empty.

2. **`validateClaims` (lines ~473-479):** Issuer validation only runs `if a.issuer != "" && iss != ""`. So if either the discovered issuer is empty *or* the token presents an empty `iss`, the issuer check is silently skipped — allowing tokens that aren't bound to the trusted issuer to be accepted.

Let me check for existing tests to make sure my fix aligns with intended behavior.

**→ Bash**(command=ls internal/auth/generic/ && grep -rn "issuer\|Issuer\|discoverOIDCConfig\|validateClaims" internal/auth/generic/*_test.go 2>/dev/null | hea  …(+5 more chars))
  ↳ *result:* generic.go
generic_test.go
internal/auth/generic/generic_test.go:51:				"issuer":   "https://example.com",
internal/auth/generic/generic_test.go:471:						"issuer":   "https://example.com",
internal/auth/generic/generic_test.go:621:			name: "missing issuer",
internal/auth/generic/generic_test.go:628:			errContains: "missing issuer claim in token",
  …(+238 more chars)
**→ Read**(file_path=/work/internal/auth/generic/generic_test.go, offset=30, limit=90)
  ↳ *result:* 30		"github.com/golang-jwt/jwt/v5"
31		"github.com/googleapis/mcp-toolbox/internal/log"
32		"github.com/googleapis/mcp-toolbox/internal/util"
33	)
34	
35	func generateRSAPrivateKey(t *testing.T) *rsa.PrivateKey {
36		t.Helper()
37		key, err := rsa.GenerateKey(rand.Reader, 2048)
38		if err != nil {
39			t.Fatalf("failed to create RSA private key: %v  …(+2348 more chars)
**→ Read**(file_path=/work/internal/auth/generic/generic_test.go, offset=600, limit=60)
  ↳ *result:* 600				token: generateValidToken(t, privateKey, keyID, jwt.MapClaims{
601					"iss":   "https://example.com",
602					"aud":   "wrong-audience",
603					"scope": "read:files",
604					"exp":   time.Now().Add(time.Hour).Unix(),
605				}),
606				wantError:   true,
607				errContains: "audience validation failed",
608			},
609			{
610				name: "insuf  …(+1717 more chars)
**Claude:** Now I understand. The discovery issuer (`https://example.com`) intentionally differs from the `AuthorizationServer` URL in tests, so I must not require those to match. The two precise fixes:

1. **`discoverOIDCConfig`:** require the `issuer` to be present in the discovery doc (so `a.issuer` is never silently empty), mirroring the existing `jwks_uri` check.
2. **`validateClaims`:** enforce the issuer match whenever an issuer is configured — remove the `iss != ""` escape that lets a token with an empty/missing `iss` bypass validation entirely.

**→ Edit**(replace_all=false, file_path=/work/internal/auth/generic/generic.go, old_string=	if config.JwksUri == "" {
		return "", "", "", fmt.Errorf("jwks_uri not found in config")
	}, new_string=	if config.JwksUri == "" {
		return "", "", "", fmt.Errorf("jwks_uri not found in config")
	}

	// The issuer is required to bind tokens to   …(+191 more chars))
  ↳ *result:* The file /work/internal/auth/generic/generic.go has been updated successfully. (file state is current in your context — no need to Read it back)
**→ Edit**(replace_all=false, file_path=/work/internal/auth/generic/generic.go, old_string=	// Validate issuer
	if a.issuer != "" && iss != "" {
		if iss != a.issuer {
			logger.WarnContext(ctx, "issuer validation failed: expected   …(+160 more chars), new_string=	// Validate issuer. When an issuer is configured (discovered from the
	// authorization server), the token's issuer must match it. A missin  …(+404 more chars))
  ↳ *result:* The file /work/internal/auth/generic/generic.go has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now let me verify the build and run the existing tests:

**→ Bash**(command=go build ./internal/auth/generic/ && go test ./internal/auth/generic/ 2>&1 | tail -30)
  ↳ *result:* Exit code 1
go: downloading github.com/MicahParks/keyfunc/v3 v3.8.0
go: downloading github.com/golang-jwt/jwt/v5 v5.3.1
go: downloading github.com/go-playground/validator/v10 v10.30.2
go: downloading github.com/goccy/go-yaml v1.19.2
go: downloading google.golang.org/api v0.279.0
go: downloading go.opentelemetry.io/otel/trace v1.43.0
go: downloading  …(+4092 more chars)
**Claude:** Dependencies can't be downloaded due to egress restrictions. Let me check if a module cache exists offline:

**→ Bash**(command=ls $(go env GOMODCACHE)/github.com/golang-jwt 2>/dev/null; echo "---vendor---"; ls vendor 2>/dev/null | head; echo "exit: build cannot run o  …(+7 more chars))
  ↳ *result:* ---vendor---
exit: build cannot run offline
**Claude:** The module cache isn't available offline, so the build can't run. My changes introduce no new imports and are syntactically simple. Let me at least verify formatting/syntax with `gofmt`:

**→ Bash**(command=gofmt -l internal/auth/generic/generic.go && echo "gofmt: clean (no formatting issues)"; gofmt -e internal/auth/generic/generic.go > /dev/nu  …(+23 more chars))
  ↳ *result:* gofmt: clean (no formatting issues)
syntax: OK
**Claude:** The fix is complete and syntactically valid. Let me show the final state of both remediated sections:

**→ Read**(file_path=/work/internal/auth/generic/generic.go, offset=158, limit=10)
  ↳ *result:* 158		if config.JwksUri == "" {
159			return "", "", "", fmt.Errorf("jwks_uri not found in config")
160		}
161	
162		// The issuer is required to bind tokens to this authorization server.
163		// Without it, issuer validation cannot be enforced during token checks.
164		if config.Issuer == "" {
165			return "", "", "", fmt.Errorf("issuer not found i  …(+22 more chars)
**→ Read**(file_path=/work/internal/auth/generic/generic.go, offset=478, limit=12)
  ↳ *result:* 478	
479		// Validate issuer. When an issuer is configured (discovered from the
480		// authorization server), the token's issuer must match it. A missing or
481		// empty token issuer must not bypass this check, otherwise tokens that are
482		// not bound to the trusted issuer would be accepted.
483		if a.issuer != "" {
484			if iss != a.issuer {
  …(+244 more chars)
**Claude:** I've remediated the **Improper Authentication (CWE-287)** vulnerability in `internal/auth/generic/generic.go`. The flaw was a bypassable OIDC issuer (`iss`) validation across two locations the finding identified:

## What was wrong

1. **`discoverOIDCConfig`** — The OIDC discovery document's `issuer` field was read but never required. If the authorization server's `.well-known/openid-configuration` omitted `issuer`, `a.issuer` was silently left empty (the code only enforced the presence of `jwks_uri`).

2. **`validateClaims`** — Issuer enforcement was guarded by `if a.issuer != "" && iss != ""`. This created two bypass paths:
   - If `a.issuer` was empty (case #1 above), the check was skipped entirely.
   - If a token presented an **empty or missing `iss`**, the check was skipped — so a token not bound to the trusted issuer would be accepted (subject only to signature/audience checks).

## The fix

1. In `discoverOIDCConfig`, the discovered `issuer` is now required (returns an error if missing), mirroring the existing `jwks_uri` guard. This guarantees `a.issuer` is always populated for a valid provider.

2. In `validateClaims`, the condition is now `if a.issuer != ""` only. Whenever an issuer is configured, the token's `iss` **must** equal it — an empty/missing token issuer can no longer bypass validation.

## Behavior preserved
- I deliberately did **not** require the discovered `issuer` to equal the `AuthorizationServer` URL, since those legitimately differ (the existing tests configure issuer `https://example.com` while connecting to a local mock URL). 
- The JWT path already rejected empty `iss` upstream, so legitimate JWT flows are unaffected; the tightening hardens the opaque-token introspection path where `iss` could previously be empty.

Build/test execution wasn't possible here because module dependencies are blocked by the egress allowlist (no module cache or vendor directory), but the changes add no new imports, pass `gofmt` syntax/format checks, and align with the existing test expectations (`issuer validation failed`, etc.).


---
**Final (success):** I've remediated the **Improper Authentication (CWE-287)** vulnerability in `internal/auth/generic/generic.go`. The flaw was a bypassable OIDC issuer (`iss`) validation across two locations the finding identified:

## What was wrong

1. **`discoverOIDCConfig`** — The OIDC discovery document's `issuer` field was read but never required. If the authorization server's `.well-known/openid-configuration` omitted `issuer`, `a.issuer` was silently left empty (the code only enforced the presence of `jwks_uri`).

2. **`validateClaims`** — Issuer enforcement was guarded by `if a.issuer != "" && iss != ""`. This created two bypass paths:
   - If `a.issuer` was empty (case #1 above), the check was skipped entirely.
   - If a token presented an **empty or missing `iss`**, the check was skipped — so a token not bound to the trusted issuer would be accepted (subject only to signature/audience checks).

## The fix

1. In `discoverOIDCConfig`, the discovered `issuer` is now required (returns an error if missing), mirroring the existing `jwks_uri` guard. This guarantees `a.issuer` is always populated for a valid provider.

2. In `validateClaims`, the condition is now `if a.issuer != ""` only. Whenever an issuer is configured, the token's `iss` **must** equal it — an empty/missing token issuer can no longer bypass validation.

## Behavior preserved
- I deliberately did **not** require the discovered `issuer` to equal the `AuthorizationServer` URL, since those legitimately differ (the existing tests configure issuer `https://example.com` while connecting to a local mock URL). 
- The JWT path already rejected empty `iss` upstream, so legitimate JWT flows are unaffected; the tightening hardens the opaque-token introspection path where `iss` could previously be empty.

Build/test execution wasn't possible here because module dependencies are blocked by the egress allowlist (no module cache or vendor directory), but the changes add no new imports, pass `gofmt` syntax/format checks, and align with the existing test expectations (`issuer validation failed`, etc.).

*turns 13 · cost $0.703*
