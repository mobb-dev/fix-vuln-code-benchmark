**Codex:** I’ll read the finding and inspect the implicated code before editing, then I’ll make the smallest source change that preserves behavior and run the relevant tests if feasible.

**→ shell:** `/bin/bash -lc "sed -n '1,220p' FINDING.txt"`
```
Project: googleapis/mcp-toolbox
Vulnerability type: Improper Authentication (CWE-287)

Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):

  internal/auth/auth.go
    - lines 32-34   in: type AuthService interface {

  internal/auth/generic/generic.go
    - lines 57-62   in: func (cfg Config) AuthServiceConfigType() string {
    - lines 157-163   in: func discoverOIDCConfig(client *http.Client, AuthorizationServer string) (jwksUR
    - lines 182-187   in: func   …(+2483 more chars)
```
**→ shell:** `/bin/bash -lc "pwd && rg --files -g 'FINDING.txt' -g 'go.mod' -g 'go.sum' -g 'AGENTS.md'"`
```
go.mod
FINDING.txt
docs/en/documentation/getting-started/quickstart/go/openAI/go.sum
docs/en/documentation/getting-started/quickstart/go/openAI/go.mod
docs/en/documentation/getting-started/quickstart/go/genAI/go.sum
docs/en/documentation/getting-started/quickstart/go/genAI/go.mod
docs/en/documentation/getting-started/quickstart/go/adkgo/go.sum
docs/en/documentation/getting-started/quickstart/go/adkgo/go.mod
docs/en/documentation/getting-started/quickstart/go/langchain/go.sum
docs/en/documentatio  …(+328 more chars)
```
**Codex:** The finding points at the auth plumbing rather than a single obvious sink, so I’m tracing how claims are attached to request context and then consumed during tool execution. Next I’m checking tests around auth to preserve the current public behavior while tightening the authentication boundary.

**→ shell:** `/bin/bash -lc "nl -ba internal/auth/auth.go | sed -n '1,140p'"`
```
     1	// Copyright 2024 Google LLC
     2	//
     3	// Licensed under the Apache License, Version 2.0 (the "License");
     4	// you may not use this file except in compliance with the License.
     5	// You may obtain a copy of the License at
     6	//
     7	//     http://www.apache.org/licenses/LICENSE-2.0
     8	//
     9	// Unless required by applicable law or agreed to in writing, software
    10	// distributed under the License is distributed on an "AS IS" BASIS,
    11	// WITHOUT WARRAN  …(+800 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba internal/auth/generic/generic.go | sed -n '1,540p'"`
```
     1	// Copyright 2026 Google LLC
     2	//
     3	// Licensed under the Apache License, Version 2.0 (the "License");
     4	// you may not use this file except in compliance with the License.
     5	// You may obtain a copy of the License at
     6	//
     7	//	http://www.apache.org/licenses/LICENSE-2.0
     8	//
     9	// Unless required by applicable law or agreed to in writing, software
    10	// distributed under the License is distributed on an "AS IS" BASIS,
    11	// WITHOUT WARRANTIES  …(+18272 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba internal/auth/google/google.go | sed -n '1,180p'"`
```
     1	// Copyright 2024 Google LLC
     2	//
     3	// Licensed under the Apache License, Version 2.0 (the "License");
     4	// you may not use this file except in compliance with the License.
     5	// You may obtain a copy of the License at
     6	//
     7	//	http://www.apache.org/licenses/LICENSE-2.0
     8	//
     9	// Unless required by applicable law or agreed to in writing, software
    10	// distributed under the License is distributed on an "AS IS" BASIS,
    11	// WITHOUT WARRANTIES  …(+2210 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba internal/server/server.go | sed -n '380,560p'"`
```
   380	
   381		resourceManager := resources.NewResourceManager(sourcesMap, authServicesMap, embeddingModelsMap, toolsMap, toolsetsMap, promptsMap, promptsetsMap)
   382	
   383		s := &Server{
   384			version:             cfg.Version,
   385			sqlCommenterEnabled: cfg.SQLCommenter,
   386			srv:                 srv,
   387			root:                r,
   388			logger:              l,
   389			instrumentation:     instrumentation,
   390			sseManager:          sseManager,
   391			ResourceMgr:       …(+7423 more chars)
```
**Codex:** I found two auth modes: legacy per-tool headers like `<authName>_token`, and MCP-wide `Authorization: Bearer ...`. I’m now checking the tool call path because the likely issue is whether a tool that declares auth can run with claims from the wrong service or with no claims after middleware succeeds.

**→ shell:** `/bin/bash -lc "nl -ba internal/server/mcp/v20250618/method.go | sed -n '200,270p'"`
```
   200				err := util.NewClientServerError(
   201					"missing access token in the 'Authorization' header",
   202					http.StatusUnauthorized,
   203					nil,
   204				)
   205				return jsonrpc.NewError(id, jsonrpc.INVALID_REQUEST, err.Error(), nil), err
   206			}
   207		}
   208	
   209		// marshal arguments and decode it using decodeJSON instead to prevent loss between floats/int.
   210		aMarshal, err := json.Marshal(toolArgument)
   211		if err != nil {
   212			err = fmt.Errorf("unabl  …(+2129 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba internal/server/mcp.go | sed -n '560,900p'"`
```
   560				span.SetStatus(codes.Error, err.Error())
   561			}
   562			span.End()
   563		}()
   564	
   565		networkProtocolVersion := fmt.Sprintf("%d.%d", r.ProtoMajor, r.ProtoMinor)
   566	
   567		v, res, err := processMcpMessage(ctx, body, s, protocolVersion, toolsetName, promptsetName, r.Header, networkProtocolVersion)
   568		if err != nil {
   569			s.logger.DebugContext(ctx, fmt.Errorf("error processing message: %w", err).Error())
   570		}
   571	
   572		// notifications will return e  …(+14054 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba internal/server/mcp/util/auth.go | sed -n '1,140p'"`
```
     1	// Copyright 2026 Google LLC
     2	//
     3	// Licensed under the Apache License, Version 2.0 (the "License");
     4	// you may not use this file except in compliance with the License.
     5	// You may obtain a copy of the License at
     6	//
     7	//     http://www.apache.org/licenses/LICENSE-2.0
     8	//
     9	// Unless required by applicable law or agreed to in writing, software
    10	// distributed under the License is distributed on an "AS IS" BASIS,
    11	// WITHOUT WARRAN  …(+1911 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"WithAuthTokenClaims|AuthTokenClaims|ValidateScopes|authRequired|RequiresClientAuthorization|GetClaimsFromHeader|McpEnabled|ValidateMCPAuth\" internal tests -g '*.go'"`
```
internal/tools/cloudsqlpg/cloudsqlpgupgradeprecheck/cloudsqlpgupgradeprecheck.go:209:func (t Tool) RequiresClientAuthorization(resourceMgr tools.SourceProvider) (bool, error) {
internal/tools/spanner/spannerlisttables/spannerlisttables_test.go:66:            authRequired:
internal/tools/cloudsqlmysql/cloudsqlmysqlcreateinstance/cloudsqlmysqlcreateinstance.go:176:func (t Tool) RequiresClientAuthorization(resourceMgr tools.SourceProvider) (bool, error) {
internal/tools/cloudsqlpg/cloudsqlpgcreatei  …(+31168 more chars)
```
**Codex:** The vulnerable pattern is clearer now: MCP-wide validation can put claims in context, and each tool call then treats those claims as satisfying whichever MCP-enabled auth service exists. I’m checking the tool authorization helper and unit test scaffolding so the remediation can be enforced in one place and covered by tests.

**→ shell:** `/bin/bash -lc "rg -n \"func .*Authorized|type BaseTool|GetAuthRequired|AuthRequired|ScopesRequired|NewBaseTool\" internal/tools -g '*.go'"`
```
internal/tools/firebird/firebirdexecutesql/firebirdexecutesql.go:73:		BaseTool: tools.NewBaseTool(
internal/tools/firebird/firebirdexecutesql/firebirdexecutesql.go:76:			tools.Manifest{Description: cfg.Description, Parameters: params.Manifest(), AuthRequired: cfg.AuthRequired},
internal/tools/firebird/firebirdexecutesql/firebirdexecutesql_test.go:54:						AuthRequired: []string{"my-google-auth-service", "other-auth-service"},
internal/tools/postgres/postgresdatabaseoverview/postgresdatabaseoverv  …(+133707 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba internal/server/mcp/util/auth_test.go | sed -n '1,220p'"`
```
     1	// Copyright 2026 Google LLC
     2	//
     3	// Licensed under the Apache License, Version 2.0 (the "License");
     4	// you may not use this file except in compliance with the License.
     5	// You may obtain a copy of the License at
     6	//
     7	//     http://www.apache.org/licenses/LICENSE-2.0
     8	//
     9	// Unless required by applicable law or agreed to in writing, software
    10	// distributed under the License is distributed on an "AS IS" BASIS,
    11	// WITHOUT WARRAN  …(+4693 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba internal/server/mcp/v20241105/method.go | sed -n '180,290p' && nl -ba internal/server/api.go | sed -n '120,210p'"`
```
   180		if genAIAttrs := util.GenAIMetricAttrsFromContext(ctx); genAIAttrs != nil {
   181			genAIAttrs.OperationName = "execute_tool"
   182			genAIAttrs.ToolName = toolName
   183		}
   184	
   185		// Get access token
   186		authTokenHeadername, err := tool.GetAuthTokenHeaderName(resourceMgr)
   187		if err != nil {
   188			errMsg := fmt.Errorf("error during invocation: %w", err)
   189			return jsonrpc.NewError(id, jsonrpc.INTERNAL_ERROR, errMsg.Error(), nil), errMsg
   190		}
   191		acce  …(+7603 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba internal/tools/tools.go | sed -n '1,260p'"`
```
     1	// Copyright 2024 Google LLC
     2	//
     3	// Licensed under the Apache License, Version 2.0 (the "License");
     4	// you may not use this file except in compliance with the License.
     5	// You may obtain a copy of the License at
     6	//
     7	//     http://www.apache.org/licenses/LICENSE-2.0
     8	//
     9	// Unless required by applicable law or agreed to in writing, software
    10	// distributed under the License is distributed on an "AS IS" BASIS,
    11	// WITHOUT WARRAN  …(+11055 more chars)
```
**Codex:** The core weakness is not token cryptography; it is identity binding. A bearer token validated by one MCP auth service must not be recorded as verified for every MCP-enabled service, so I’m going to make the context carry the service name with the claims and only authorize that one service.

**→ shell:** `/bin/bash -lc "nl -ba internal/util/util.go | sed -n '190,245p'"`
```
   190		}
   191		return nil, fmt.Errorf("unable to retrieve instrumentation")
   192	}
   193	
   194	// GenAIMetricAttrs holds gen_ai and network attributes for metrics
   195	type GenAIMetricAttrs struct {
   196		OperationName          string
   197		ToolName               string
   198		PromptName             string
   199		NetworkProtocolName    string
   200		NetworkProtocolVersion string
   201	}
   202	
   203	const genAIMetricAttrsKey contextKey = "genAIMetricAttrs"
   204	
   205	// W  …(+1755 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba internal/server/config.go | sed -n '260,340p'"`
```
   260		if err != nil {
   261			return nil, err
   262		}
   263		return sourceConfig, nil
   264	}
   265	
   266	func UnmarshalYAMLAuthServiceConfig(ctx context.Context, name string, r map[string]any) (auth.AuthServiceConfig, error) {
   267		resourceType, ok := r["type"].(string)
   268		if !ok {
   269			return nil, fmt.Errorf("missing 'type' field or it is not a string")
   270		}
   271		dec, err := util.NewStrictDecoder(r)
   272		if err != nil {
   273			return nil, fmt.Errorf("error cr  …(+2775 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"mcpAuthMiddleware|ValidateScopes|MCPAuth|mcpEnabled|AuthTokenClaims\" internal/server internal/auth -g '*_test.go'"`
```
internal/server/server_test.go:948:func TestMCPAuthMiddleware(t *testing.T) {
internal/auth/generic/generic_test.go:216:func TestValidateMCPAuth_Opaque(t *testing.T) {
internal/auth/generic/generic_test.go:414:			_, err = genericAuth.ValidateMCPAuth(ctx, header)
internal/server/mcp/util/auth_test.go:30:	mcpEnabled bool
internal/server/mcp/util/auth_test.go:48:		McpEnabled: aS.mcpEnabled,
internal/server/mcp/util/auth_test.go:52:func TestValidateScopes(t *testing.T) {
internal/server/mcp/util/aut  …(+953 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"WithAuthTokenClaims\\(|AuthTokenClaimsFromContext\\(\" internal -g '*.go'"`
**Codex:** I’m going to add a small context wrapper that records both claims and the auth service that validated them. Then I’ll update the MCP/API call paths so MCP claims are only attributed to the matching service name, and leave legacy header auth untouched.

**→ shell:** `/bin/bash -lc "nl -ba internal/server/server_test.go | sed -n '900,1060p'"`
```
   900			Port:         port,
   901			AllowedHosts: []string{"*"},
   902		}
   903	
   904		// Initialize and Start the Server
   905		s, err := server.NewServer(ctx, cfg)
   906		if err != nil {
   907			t.Fatalf("unable to initialize server: %v", err)
   908		}
   909	
   910		if err := s.Listen(ctx, "", ""); err != nil {
   911			t.Fatalf("unable to start listener: %v", err)
   912		}
   913	
   914		go func() {
   915			if err := s.Serve(ctx); err != nil && err != http.ErrServerClosed {
     …(+4979 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"mcpAuthMiddleware|apiRouter|mcpRouter|Use\\(\" internal/server -g '*.go'"`
```
internal/server/api.go:34:// apiRouter creates a router that represents the routes under /api
internal/server/api.go:35:func apiRouter(s *Server) (chi.Router, error) {
internal/server/api.go:38:	r.Use(middleware.AllowContentType("application/json"))
internal/server/api.go:39:	r.Use(middleware.StripSlashes)
internal/server/api.go:40:	r.Use(render.SetContentType(render.ContentTypeJSON))
internal/server/mcp.go:348:// mcpRouter creates a router that represents the routes under /mcp
internal/server/m  …(+1125 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba internal/server/server_test.go | sed -n '1060,1160p'"`
```
  1060						"scope":  "mcp",
  1061						"aud":    "test-audience",
  1062						"exp":    time.Now().Add(time.Hour).Unix(),
  1063					}
  1064					mockRawResponse = ""
  1065				},
  1066				wantStatusCode: http.StatusOK,
  1067			},
  1068			{
  1069				name:  "insufficient scope",
  1070				token: "bad-scope-token",
  1071				setupMock: func() {
  1072					mockStatus = http.StatusOK
  1073					mockResponse = map[string]any{
  1074						"active": true,
  1075						"scope":  "wrong-scope",
  10  …(+2651 more chars)
```
**Codex:** I’m editing the shared context helper first, because that keeps the change explicit and makes the rest of the authorization code read the same way across all MCP protocol versions.

**→ shell:** `/bin/bash -lc "nl -ba internal/server/mcp/v20250618/method.go | sed -n '1,45p' && nl -ba internal/server/api.go | sed -n '1,35p'"`
```
     1	// Copyright 2025 Google LLC
     2	//
     3	// Licensed under the Apache License, Version 2.0 (the "License");
     4	// you may not use this file except in compliance with the License.
     5	// You may obtain a copy of the License at
     6	//
     7	//     http://www.apache.org/licenses/LICENSE-2.0
     8	//
     9	// Unless required by applicable law or agreed to in writing, software
    10	// distributed under the License is distributed on an "AS IS" BASIS,
    11	// WITHOUT WARRAN  …(+2891 more chars)
```
**✎ files:** update `/work/internal/util/util.go`

**Codex:** The context now carries the validating service name. I’m updating the middleware and call handlers so they use that binding instead of treating a valid MCP token as proof for every configured MCP auth service.

**→ shell:** `/bin/bash -lc "perl -0pi -e 's/util\\.WithAuthTokenClaims\\(r\\.Context\\(\\), claims\\)/util.WithAuthTokenClaimsForService(r.Context(), mcpSvc.GetName(), claims)/' internal/server/server.go
perl -0pi  …(+555 more chars)`
```
/bin/bash: line 3: gofmt: command not found

```
**Codex:** The source edit is in place, but this environment does not have `gofmt` on `PATH`. I’m checking the Go tool availability and then I’ll format manually if needed.

**→ shell:** `/bin/bash -lc 'which go || true; which gofmt || true; go version || true'`
```
/bin/bash: line 1: go: command not found

```
**→ shell:** `/bin/bash -lc 'git diff -- internal/util/util.go internal/server/server.go internal/server/api.go internal/server/mcp/v20241105/method.go internal/server/mcp/v20250326/method.go internal/server/mcp/v2  …(+58 more chars)`
```
diff --git a/internal/server/api.go b/internal/server/api.go
index 9cf4a83..86ada67 100644
--- a/internal/server/api.go
+++ b/internal/server/api.go
@@ -165,7 +165,7 @@ func toolInvokeHandler(s *Server, w http.ResponseWriter, r *http.Request) {
 
 		cfg := aS.ToConfig()
 		if genCfg, ok := cfg.(generic.Config); ok && genCfg.McpEnabled {
-			claims = util.AuthTokenClaimsFromContext(ctx)
+			claims = util.AuthTokenClaimsForServiceFromContext(ctx, aS.GetName())
 		} else {
 			claims, err = aS.GetC  …(+4875 more chars)
```
**Codex:** I’m adding a focused regression test for the new binding behavior: claims validated for one service must be invisible when another service name is requested, while the old claim accessor still works for code that only needs scope checks.

**→ shell:** `/bin/bash -lc "rg -n \"package util\" internal/util -g '*_test.go'"`
```
internal/util/util_test.go:13:package util
internal/util/errors_test.go:13:package util

```
**→ shell:** `/bin/bash -lc "rg -n \"WithAuthTokenClaims|AuthTokenClaims\" internal/util -g '*_test.go'"`
**→ shell:** `/bin/bash -lc "nl -ba internal/util/util_test.go | sed -n '1,220p'"`
```
     1	// Copyright 2026 Google LLC
     2	// Licensed under the Apache License, Version 2.0 (the "License");
     3	// you may not use this file except in compliance with the License.
     4	// You may obtain a copy of the License at
     5	//
     6	//	http://www.apache.org/licenses/LICENSE-2.0
     7	//
     8	// Unless required by applicable law or agreed to in writing, software
     9	// distributed under the License is distributed on an "AS IS" BASIS,
    10	// WITHOUT WARRANTIES OR CONDIT  …(+2738 more chars)
```
**Codex:** I’m applying the test as a small addition to the existing util test file. Since the Go toolchain is absent here, I’ll still verify by static inspection and report that limitation clearly.

**✎ files:** update `/work/internal/util/util_test.go`

**Codex:** The regression test is in place. I’m doing a final pass over all remaining claim lookups and the diff to make sure no MCP-enabled auth path still attributes context claims without checking the service name.

**→ shell:** `/bin/bash -lc "rg -n \"AuthTokenClaimsFromContext|AuthTokenClaimsForServiceFromContext|WithAuthTokenClaims\" internal -g '*.go'"`
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M internal/server/api.go
 M internal/server/mcp/v20241105/method.go
 M internal/server/mcp/v20250326/method.go
 M internal/server/mcp/v20250618/method.go
 M internal/server/mcp/v20251125/method.go
 M internal/server/server.go
 M internal/util/util.go
 M internal/util/util_test.go

```
**→ shell:** `/bin/bash -lc 'git diff --stat && git diff -- internal/util/util.go internal/util/util_test.go internal/server/server.go internal/server/api.go internal/server/mcp/v20241105/method.go internal/server/  …(+104 more chars)`
```
 internal/server/api.go                  |  2 +-
 internal/server/mcp/v20241105/method.go |  2 +-
 internal/server/mcp/v20250326/method.go |  2 +-
 internal/server/mcp/v20250618/method.go |  2 +-
 internal/server/mcp/v20251125/method.go |  2 +-
 internal/server/server.go               |  2 +-
 internal/util/util.go                   | 34 ++++++++++++++++++++++++++++++---
 internal/util/util_test.go              | 16 ++++++++++++++++
 8 files changed, 53 insertions(+), 9 deletions(-)
diff --git a  …(+6392 more chars)
```
**Codex:** The remaining raw claim accessor is only used for scope checking after authentication, not to mark a service as verified. I’m doing whitespace/static checks next; the repository’s Go binaries are not installed in this container, so compilation tests cannot run here.

**✎ files:** update `/work/internal/util/util.go`

**→ shell:** `/bin/bash -lc 'git diff --check'`
**→ shell:** `/bin/bash -lc 'git diff -- internal/util/util.go internal/util/util_test.go internal/server/server.go internal/server/api.go internal/server/mcp/v20241105/method.go internal/server/mcp/v20250326/metho  …(+85 more chars)`
```
diff --git a/internal/server/api.go b/internal/server/api.go
index 9cf4a83..86ada67 100644
--- a/internal/server/api.go
+++ b/internal/server/api.go
@@ -165,7 +165,7 @@ func toolInvokeHandler(s *Server, w http.ResponseWriter, r *http.Request) {
 
 		cfg := aS.ToConfig()
 		if genCfg, ok := cfg.(generic.Config); ok && genCfg.McpEnabled {
-			claims = util.AuthTokenClaimsFromContext(ctx)
+			claims = util.AuthTokenClaimsForServiceFromContext(ctx, aS.GetName())
 		} else {
 			claims, err = aS.GetC  …(+6000 more chars)
```
**Codex:** Whitespace checks passed. I’m checking once for a non-standard Go install location before I conclude testing is blocked by the missing toolchain.

**→ shell:** `/bin/bash -lc 'ls /usr/local/go/bin/go /usr/bin/go /opt/go/bin/go 2>/dev/null || true'`
```
/usr/local/go/bin/go

```
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M internal/server/api.go
 M internal/server/mcp/v20241105/method.go
 M internal/server/mcp/v20250326/method.go
 M internal/server/mcp/v20250618/method.go
 M internal/server/mcp/v20251125/method.go
 M internal/server/server.go
 M internal/util/util.go
 M internal/util/util_test.go

```
**Codex:** There is a Go install at `/usr/local/go/bin`, just not on `PATH`. I’m using it directly now to format and run the focused package tests.

**→ shell:** `/bin/bash -lc '/usr/local/go/bin/gofmt -w internal/util/util.go internal/util/util_test.go internal/server/server.go internal/server/api.go internal/server/mcp/v20241105/method.go internal/server/mcp/  …(+315 more chars)`
```
go: downloading github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric v0.56.0
go: downloading github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/trace v1.32.0
go: downloading go.opentelemetry.io/contrib/propagators/autoprop v0.68.0
go: downloading go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp v1.43.0
go: downloading go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.43.0
go: downloading go.opentelemetry.io/otel/sdk/metric   …(+37170 more chars)
```
**Codex:** Formatting completed. The test run is blocked before compilation because dependencies are not cached and `proxy.golang.org` is blocked by the environment’s egress allowlist; I’m doing final diff/status checks now.

**→ shell:** `/bin/bash -lc 'git diff --check'`
**→ shell:** `/bin/bash -lc 'git diff --stat && git diff -- internal/util/util.go internal/util/util_test.go internal/server/server.go internal/server/api.go internal/server/mcp/v20241105/method.go internal/server/  …(+104 more chars)`
```
 internal/server/api.go                  |  2 +-
 internal/server/mcp/v20241105/method.go |  2 +-
 internal/server/mcp/v20250326/method.go |  2 +-
 internal/server/mcp/v20250618/method.go |  2 +-
 internal/server/mcp/v20251125/method.go |  2 +-
 internal/server/server.go               |  2 +-
 internal/util/util.go                   | 36 ++++++++++++++++++++++++++++++---
 internal/util/util_test.go              | 16 +++++++++++++++
 8 files changed, 55 insertions(+), 9 deletions(-)
diff --git a/  …(+6487 more chars)
```
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M internal/server/api.go
 M internal/server/mcp/v20241105/method.go
 M internal/server/mcp/v20250326/method.go
 M internal/server/mcp/v20250618/method.go
 M internal/server/mcp/v20251125/method.go
 M internal/server/server.go
 M internal/util/util.go
 M internal/util/util_test.go

```
**Codex:** Implemented the auth remediation.

Changed:
- MCP middleware now stores validated claims with the specific auth service name that validated them.
- Tool/API authorization paths now only treat MCP context claims as verified for that same service.
- Added a regression test for service-bound auth claims.
- Updated all MCP protocol versions consistently.

Verification:
- Ran `/usr/local/go/bin/gofmt` on touched Go files.
- Ran `git diff --check` successfully.
- Attempted focused `go test`, but it could not compile because dependencies are not cached and access to `proxy.golang.org` is blocked by the environment egress allowlist.


---
*tokens — input 1356543 (cached 1194880), output 5956, reasoning 1375*
