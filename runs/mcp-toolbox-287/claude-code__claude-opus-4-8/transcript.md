**→ Read**(file_path=/work/FINDING.txt)
  ↳ *result:* 1	Project: googleapis/mcp-toolbox
2	Vulnerability type: Improper Authentication (CWE-287)
3	
4	Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):
5	
6	  internal/auth/auth.go
7	    - lines 32-34   in: type AuthService interface {
8	
9	  internal/auth/generic/generic.go
10	    - lines 57-62   in: func (cfg Config)   …(+2798 more chars)
**→ Read**(file_path=/work/internal/server/mcp/util/auth.go)
  ↳ *result:* 1	// Copyright 2026 Google LLC
2	//
3	// Licensed under the Apache License, Version 2.0 (the "License");
4	// you may not use this file except in compliance with the License.
5	// You may obtain a copy of the License at
6	//
7	//     http://www.apache.org/licenses/LICENSE-2.0
8	//
9	// Unless required by applicable law or agreed to in writing, soft  …(+1791 more chars)
**→ Read**(file_path=/work/internal/server/mcp/v20251125/method.go, offset=200, limit=90)
  ↳ *result:* 200				err := util.NewClientServerError(
201					"missing access token in the 'Authorization' header",
202					http.StatusUnauthorized,
203					nil,
204				)
205				return jsonrpc.NewError(id, jsonrpc.INVALID_REQUEST, err.Error(), nil), err
206			}
207		}
208	
209		// marshal arguments and decode it using decodeJSON instead to prevent loss between   …(+2968 more chars)
**→ Read**(file_path=/work/internal/server/mcp/v20251125/method.go, offset=150, limit=60)
  ↳ *result:* 150			err = fmt.Errorf("invalid mcp tools call request: %w", err)
151			return jsonrpc.NewError(id, jsonrpc.INVALID_REQUEST, err.Error(), nil), err
152		}
153	
154		toolName := req.Params.Name
155		toolArgument := req.Params.Arguments
156		logger.DebugContext(ctx, fmt.Sprintf("tool name: %s", toolName))
157	
158		// Update span name and set gen_ai   …(+2146 more chars)
**→ Read**(file_path=/work/internal/server/server.go, offset=490, limit=90)
  ↳ *result:* 490		// default endpoint for validating server is running
491		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
492			_, _ = w.Write([]byte("🧰 Hello, World! 🧰"))
493		})
494	
495		return s, nil
496	}
497	
498	func mcpAuthMiddleware(s *Server) func(http.Handler) http.Handler {
499		return func(next http.Handler) http.Handler {
500			return   …(+3404 more chars)
**→ Read**(file_path=/work/internal/auth/generic/generic.go)
  ↳ *result:* 1	// Copyright 2026 Google LLC
2	//
3	// Licensed under the Apache License, Version 2.0 (the "License");
4	// you may not use this file except in compliance with the License.
5	// You may obtain a copy of the License at
6	//
7	//	http://www.apache.org/licenses/LICENSE-2.0
8	//
9	// Unless required by applicable law or agreed to in writing, software  …(+16836 more chars)
**→ Read**(file_path=/work/internal/server/server.go, offset=420, limit=70)
  ↳ *result:* 420		}
421		r.Use(hostCheck(allowedHostsMap))
422	
423		// Host OAuth Protected Resource Metadata endpoint
424		mcpAuthEnabled := false
425		for _, authSvc := range s.ResourceMgr.GetAuthServiceMap() {
426			if genCfg, ok := authSvc.ToConfig().(generic.Config); ok && genCfg.McpEnabled {
427				mcpAuthEnabled = true
428				break
429			}
430		}
431	
4  …(+1932 more chars)
**→ Bash**(command=grep -rn "mcpAuthMiddleware\|func mcpRouter\|r.Use\|r.Mount\|r.Post\|r.Get" internal/server/mcp.go | head -50)
  ↳ *result:* internal/server/mcp.go:349:func mcpRouter(s *Server) (chi.Router, error) {
internal/server/mcp.go:352:	r.Use(middleware.AllowContentType("application/json", "application/json-rpc", "application/jsonrequest"))
internal/server/mcp.go:353:	r.Use(middleware.StripSlashes)
internal/server/mcp.go:354:	r.Use(render.SetContentType(render.ContentTypeJSON))
i  …(+1303 more chars)
**→ Bash**(command=grep -rn "active\|Active" internal/auth/generic/*_test.go | head -40; echo "---tests files---"; ls internal/auth/generic/)
  ↳ *result:* internal/auth/generic/generic_test.go:234:				"active": true,
internal/auth/generic/generic_test.go:248:				"active": true,
internal/auth/generic/generic_test.go:265:				"active": true,
internal/auth/generic/generic_test.go:279:				"active": true,
internal/auth/generic/generic_test.go:288:			name:           "inactive opaque token",
internal/auth/ge  …(+1182 more chars)
**→ Read**(file_path=/work/internal/auth/generic/generic_test.go, offset=280, limit=120)
  ↳ *result:* 280					"scope":  "read:files",
281					"aud":    []string{"other-audience", "my-audience"},
282					"exp":    time.Now().Add(time.Hour).Unix(),
283				},
284				mockStatus: http.StatusOK,
285				wantError:  false,
286			},
287			{
288				name:           "inactive opaque token",
289				token:          "opaque-inactive",
290				scopesRequired: []str  …(+3497 more chars)
**Claude:** I have enough context. Let me look closely at the two flagged regions in the introspection/claims validation path, which is the heart of the authentication flow.

**→ Read**(file_path=/work/internal/auth/generic/generic.go, offset=376, limit=17)
  ↳ *result:* 376		var introspectResp struct {
377			Active   *bool           `json:"active"`
378			Scope    string          `json:"scope"`
379			Aud      json.RawMessage `json:"aud"`
380			Audience json.RawMessage `json:"audience"`
381			Exp      json.Number     `json:"exp"`
382			Iss      string          `json:"iss"`
383		}
384	
385		if err := json.Unmarshal(b  …(+382 more chars)
**Claude:** Confirmed. This is the vulnerability. In `validateOpaqueToken`, the `active` field from the OAuth 2.0 Token Introspection response (RFC 7662) is decoded into a `*bool`, and the check only rejects the token when `active` is **explicitly present and false**:

```go
if introspectResp.Active != nil && !*introspectResp.Active {
```

If the introspection endpoint omits the `active` field (or returns a body where it can't be decoded), `Active` stays `nil` and the token is **accepted** — a fail-open authentication bypass (CWE-287). RFC 7662 §2.2 makes `active` REQUIRED and states that absence of `active: true` means the token is invalid. The fix is to fail closed.

**→ Edit**(replace_all=false, file_path=/work/internal/auth/generic/generic.go, old_string=	if introspectResp.Active != nil && !*introspectResp.Active {
		logger.InfoContext(ctx, "token is not active")
		return nil, &MCPAuthError{C  …(+98 more chars), new_string=	// Per RFC 7662, "active" is a REQUIRED field and the token must be treated
	// as invalid unless the endpoint explicitly reports active: t  …(+326 more chars))
  ↳ *result:* The file /work/internal/auth/generic/generic.go has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now let me verify the fix builds and existing tests still pass, and add a regression test for the absent-`active` case.

**→ Bash**(command=go build ./internal/auth/... && go test ./internal/auth/generic/... 2>&1 | tail -20)
  ↳ *result:* Exit code 1
go: downloading google.golang.org/api v0.279.0
go: downloading github.com/MicahParks/keyfunc/v3 v3.8.0
go: downloading github.com/golang-jwt/jwt/v5 v5.3.1
go: downloading github.com/go-playground/validator/v10 v10.30.2
go: downloading github.com/goccy/go-yaml v1.19.2
go: downloading github.com/GoogleCloudPlatform/opentelemetry-operation  …(+4259 more chars)
**Claude:** The build environment can't download dependencies (egress blocked). Let me check if modules are available offline.

**→ Bash**(command=ls vendor 2>/dev/null && echo "has vendor" || echo "no vendor"; ls $(go env GOMODCACHE)/github.com/golang-jwt 2>/dev/null || echo "jwt not c  …(+6 more chars))
  ↳ *result:* no vendor
jwt not cached
**Claude:** Dependencies aren't cached and egress is blocked, so I can't compile here — but my change is a minimal, type-preserving edit. Let me add a regression test for the absent-`active` case, matching the existing table-driven structure. Let me inspect the test struct and a valid case.

**→ Read**(file_path=/work/internal/auth/generic/generic_test.go, offset=210, limit=75)
  ↳ *result:* 210					}
211				}
212			})
213		}
214	}
215	
216	func TestValidateMCPAuth_Opaque(t *testing.T) {
217		tests := []struct {
218			name           string
219			token          string
220			scopesRequired []string
221			audience       string
222			mockOidcConfig map[string]any
223			mockResponse   map[string]any
224			mockStatus     int
225			wantError   …(+1995 more chars)
**Claude:** Now I'll add a regression test case for the missing-`active` field, right after the existing "inactive opaque token" case.

**→ Edit**(replace_all=false, file_path=/work/internal/auth/generic/generic_test.go, old_string=		{
			name:           "inactive opaque token",
			token:          "opaque-inactive",
			scopesRequired: []string{"read:files"},
			mockResp  …(+191 more chars), new_string=		{
			name:           "inactive opaque token",
			token:          "opaque-inactive",
			scopesRequired: []string{"read:files"},
			mockResp  …(+687 more chars))
  ↳ *result:* <tool_use_error>Found 2 matches of the string to replace, but replace_all is false. To replace all occurrences, set replace_all to true. To replace only one occurrence, please provide more context to uniquely identify the instance.
String: 		{
			name:           "inactive opaque token",
			token:          "opaque-inactive",
			scopesRequired: []str  …(+238 more chars)
**Claude:** There are two such blocks (two test functions). Let me check the second one's context to distinguish them.

**→ Read**(file_path=/work/internal/auth/generic/generic_test.go, offset=540, limit=90)
  ↳ *result:* 540						t.Fatalf("unexpected error: %v", err)
541					}
542				}
543			})
544		}
545	}
546	
547	func TestValidateOpaqueToken(t *testing.T) {
548		tests := []struct {
549			name           string
550			token          string
551			scopesRequired []string
552			audience       string
553			mockOidcConfig map[string]any
554			mockResponse   map[string]a  …(+2412 more chars)
**Claude:** Both test functions cover the same path; I'll add the regression case to both using `replace_all`.

**→ Edit**(replace_all=true, file_path=/work/internal/auth/generic/generic_test.go, old_string=			name:           "inactive opaque token",
			token:          "opaque-inactive",
			scopesRequired: []string{"read:files"},
			mockResponse  …(+187 more chars), new_string=			name:           "inactive opaque token",
			token:          "opaque-inactive",
			scopesRequired: []string{"read:files"},
			mockResponse  …(+683 more chars))
  ↳ *result:* The file /work/internal/auth/generic/generic_test.go has been updated. All occurrences were successfully replaced. (file state is current in your context — no need to Read it back)
**Claude:** Let me do a syntax check with `gofmt` (no network needed) on both edited files.

**→ Bash**(command=gofmt -l internal/auth/generic/generic.go internal/auth/generic/generic_test.go && echo "gofmt: clean (no formatting diffs)")
  ↳ *result:* gofmt: clean (no formatting diffs)
**Claude:** Both files parse cleanly. I can't run the full suite (module downloads are blocked by the egress allowlist), but `gofmt` confirms both edits are syntactically valid, and the change is minimal and type-preserving.

## Summary

**Vulnerability:** Improper Authentication (CWE-287) — a fail-open authentication bypass in the OAuth 2.0 Token Introspection (RFC 7662) path.

**Location:** `internal/auth/generic/generic.go`, in `validateOpaqueToken` — the function that validates opaque bearer tokens used for MCP authentication. This is the shared auth logic that every MCP request flows through (the middleware in `server.go`, the `toolsCallHandler` in each `internal/server/mcp/v*/method.go`, and scope validation in `mcp/util/auth.go`), which is why the finding spanned the whole auth subsystem.

**The bug:** The introspection response's `active` field is decoded into a `*bool`, and the check was:

```go
if introspectResp.Active != nil && !*introspectResp.Active {  // reject only if explicitly false
```

If the introspection endpoint omits `active` (or returns a body where it can't be decoded), `Active` stays `nil` and the token was **accepted**. RFC 7662 §2.2 makes `active` REQUIRED and states a token must be treated as invalid unless `active: true` is explicitly returned.

**The fix:** Fail closed — reject when `active` is absent or false:

```go
if introspectResp.Active == nil || !*introspectResp.Active {
```

This preserves intended behavior for compliant introspection servers (which always return `active`), while closing the bypass for missing/malformed responses.

**Regression test:** Added an `"opaque token missing active field"` case to both `TestValidateMCPAuth_Opaque` and `TestValidateOpaqueToken`, asserting that a response without `active` is rejected with `"token is not active"`.

No commits, pushes, or behavior changes beyond the security fix.


---
**Final (success):** Both files parse cleanly. I can't run the full suite (module downloads are blocked by the egress allowlist), but `gofmt` confirms both edits are syntactically valid, and the change is minimal and type-preserving.

## Summary

**Vulnerability:** Improper Authentication (CWE-287) — a fail-open authentication bypass in the OAuth 2.0 Token Introspection (RFC 7662) path.

**Location:** `internal/auth/generic/generic.go`, in `validateOpaqueToken` — the function that validates opaque bearer tokens used for MCP authentication. This is the shared auth logic that every MCP request flows through (the middleware in `server.go`, the `toolsCallHandler` in each `internal/server/mcp/v*/method.go`, and scope validation in `mcp/util/auth.go`), which is why the finding spanned the whole auth subsystem.

**The bug:** The introspection response's `active` field is decoded into a `*bool`, and the check was:

```go
if introspectResp.Active != nil && !*introspectResp.Active {  // reject only if explicitly false
```

If the introspection endpoint omits `active` (or returns a body where it can't be decoded), `Active` stays `nil` and the token was **accepted**. RFC 7662 §2.2 makes `active` REQUIRED and states a token must be treated as invalid unless `active: true` is explicitly returned.

**The fix:** Fail closed — reject when `active` is absent or false:

```go
if introspectResp.Active == nil || !*introspectResp.Active {
```

This preserves intended behavior for compliant introspection servers (which always return `active`), while closing the bypass for missing/malformed responses.

**Regression test:** Added an `"opaque token missing active field"` case to both `TestValidateMCPAuth_Opaque` and `TestValidateOpaqueToken`, asserting that a response without `active` is rejected with `"token is not active"`.

No commits, pushes, or behavior changes beyond the security fix.

*turns 20 · cost $1.136*
