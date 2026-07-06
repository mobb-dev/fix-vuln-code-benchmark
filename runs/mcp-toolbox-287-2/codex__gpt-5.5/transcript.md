**Codex:** I’ll inspect the finding and the relevant code paths first, then patch the smallest surface that removes the vulnerability while preserving behavior.

**→ shell:** `/bin/bash -lc "sed -n '1,220p' FINDING.txt"`
```
Project: googleapis/mcp-toolbox
Vulnerability type: Improper Authentication (CWE-287)

Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):

  internal/auth/generic/generic.go
    - lines 155-160   in: func discoverOIDCConfig(client *http.Client, AuthorizationServer string) (jwksUR
    - lines 471-481   in: func (a AuthService) validateClaims(ctx context.Context, iss string, aud []strin

```
**→ shell:** `/bin/bash -lc "pwd && rg --files -g 'FINDING.txt' -g 'go.mod' -g 'go.sum'"`
```
go.mod
FINDING.txt
go.sum
docs/en/documentation/getting-started/quickstart/go/openAI/go.sum
docs/en/documentation/getting-started/quickstart/go/openAI/go.mod
docs/en/documentation/getting-started/quickstart/go/genAI/go.sum
docs/en/documentation/getting-started/quickstart/go/genAI/go.mod
docs/en/documentation/getting-started/quickstart/go/adkgo/go.sum
docs/en/documentation/getting-started/quickstart/go/adkgo/go.mod
docs/en/documentation/getting-started/quickstart/go/langchain/go.sum
docs/en/docum  …(+328 more chars)
```
**→ shell:** `/bin/bash -lc 'git status --short'`
**Codex:** The finding points at generic OIDC discovery and claim validation. I’m reading that file plus nearby tests to understand the intended auth contract before editing.

**→ shell:** `/bin/bash -lc "sed -n '1,260p' internal/auth/generic/generic.go"`
```
// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for  …(+6839 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '260,560p' internal/auth/generic/generic.go"`
```

// ValidateMCPAuth handles MCP auth token validation
func (a AuthService) ValidateMCPAuth(ctx context.Context, h http.Header) (map[string]any, error) {
	tokenString := h.Get("Authorization")
	if tokenString == "" {
		return nil, &MCPAuthError{Code: http.StatusUnauthorized, Message: "missing access token", ScopesRequired: a.ScopesRequired}
	}

	headerParts := strings.Split(tokenString, " ")
	if len(headerParts) != 2 || strings.ToLower(headerParts[0]) != "bearer" {
		return nil, &MCPAuthError{Cod  …(+8155 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"discoverOIDCConfig|validateClaims|AuthorizationServer|auth.generic|generic\" internal/auth tests -g '*.go'"`
```
internal/auth/generic/generic_test.go:15:package generic
internal/auth/generic/generic_test.go:105:				Name:                "generic-auth",
internal/auth/generic/generic_test.go:106:				Type:                "generic",
internal/auth/generic/generic_test.go:108:				AuthorizationServer: mockOIDC.URL,
internal/auth/generic/generic_test.go:117:				Name:                "generic-auth",
internal/auth/generic/generic_test.go:118:				Type:                "generic",
internal/auth/generic/generic_test.go:12  …(+7160 more chars)
```
**Codex:** I found two weak checks: discovery accepts non-HTTPS metadata/JWKS endpoints, and MCP validation only compares issuer when both configured issuer and token issuer are non-empty. I’m checking tests now so I can tighten those checks without breaking the mock-server coverage unintentionally.

**→ shell:** `/bin/bash -lc "sed -n '1,220p' internal/auth/generic/generic_test.go"`
```
// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for  …(+5661 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '220,520p' internal/auth/generic/generic_test.go"`
```
		setupHeader func() http.Header
		wantError   bool
		errContains string
		validate    func(claims map[string]any)
	}{
		{
			name: "valid token",
			setupHeader: func() http.Header {
				token := generateValidToken(t, privateKey, keyID, jwt.MapClaims{
					"iss":   "https://example.com",
					"aud":   "my-audience",
					"scope": "read:files write:files",
					"sub":   "test-user",
					"exp":   time.Now().Add(time.Hour).Unix(),
				})
				header := http.Header{}
				header.Set("test-generic-au  …(+7934 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '520,920p' internal/auth/generic/generic_test.go"`
```
			if !ok {
				t.Fatalf("expected *AuthService, got %T", authService)
			}

			logger, err := log.NewLogger("standard", log.Debug, &bytes.Buffer{}, &bytes.Buffer{})
			if err != nil {
				t.Fatalf("failed to create logger: %v", err)
			}
			ctx := util.WithLogger(context.Background(), logger)

			header := http.Header{}
			header.Set("Authorization", "Bearer "+tc.token)

			_, err = genericAuth.ValidateMCPAuth(ctx, header)

			if tc.wantError {
				if err == nil {
					t.Fatalf("expected error,  …(+9693 more chars)
```
**Codex:** I’m going to add explicit endpoint validation for discovered OIDC metadata and JWKS URLs, allowing cleartext only for loopback test/dev servers, and then make issuer validation fail closed whenever discovery provided an issuer. This preserves the existing local test setup while removing the production auth bypass.

**✎ files:** update `/work/internal/auth/generic/generic.go`

**Codex:** The code now rejects non-HTTPS auth endpoints except loopback and requires an issuer from discovery. I’m running the focused test package to catch any behavior assumptions in the existing generic auth tests.

**→ shell:** `/bin/bash -lc 'gofmt -w internal/auth/generic/generic.go'`
```
/bin/bash: line 1: gofmt: command not found

```
**→ shell:** `/bin/bash -lc 'go test ./internal/auth/generic'`
```
/bin/bash: line 1: go: command not found

```
**Codex:** This container does not have `go` or `gofmt` on `PATH`, so I can’t run the Go test suite here. I’m doing a manual formatting/read-through and adding focused regression tests so the repository’s normal CI can verify the fix.

**→ shell:** `/bin/bash -lc "sed -n '460,505p' internal/auth/generic/generic.go"`
```
	if len(audData) == 0 {
		audData = introspectResp.Audience
	}

	var aud []string
	if len(audData) > 0 {
		var audStr string
		var audArr []string
		if err := json.Unmarshal(audData, &audStr); err == nil {
			aud = []string{audStr}
		} else if err := json.Unmarshal(audData, &audArr); err == nil {
			aud = audArr
		} else {
			logger.WarnContext(ctx, "failed to parse aud or audience claim in introspection response")
			return nil, &MCPAuthError{Code: http.StatusUnauthorized, Message: "invalid aud  …(+1039 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '20,190p' internal/auth/generic/generic.go"`
```
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/googleapis/mcp-toolbox/internal/auth"
	"github.com/googleapis/mcp-toolbox/internal/util"
)

const AuthServiceType string = "generic"

// validate interface
var _ auth.AuthServiceConfig = Config{}

// Auth service configuration
type Config struct {
	Name                   string   `yaml:"name" validate:"required"`
	Type              …(+4645 more chars)
```
**→ shell:** `/bin/bash -lc 'which go || true; which gofmt || true; ls /usr/local/go/bin 2>/dev/null || true'`
```
go
gofmt

```
**Codex:** `go` appears discoverable in a non-login lookup but the login shell cannot execute it, so I’m checking the exact command resolution. After that I’ll either run tests with the resolved binary or report the environment issue precisely.

**→ shell:** `/bin/bash -c 'command -v go; command -v gofmt; type go; type gofmt'`
```
/bin/bash: line 1: type: go: not found
/bin/bash: line 1: type: gofmt: not found

```
**→ shell:** `/bin/bash -lc 'command -v go; command -v gofmt; type go; type gofmt'`
```
/bin/bash: line 1: type: go: not found
/bin/bash: line 1: type: gofmt: not found

```
**Codex:** I’m adding regression coverage at the helper level for endpoint scheme validation and at claim validation for the missing-issuer bypass. That keeps the tests focused on the vulnerability rather than requiring a full TLS JWKS setup.

**✎ files:** update `/work/internal/auth/generic/generic_test.go`

**✎ files:** update `/work/internal/auth/generic/generic_test.go`

**Codex:** The focused regression tests are in place. I’m scanning the edited sections and the package diff now for formatting issues and unintended changes since automated formatting is unavailable in this environment.

**→ shell:** `/bin/bash -lc "sed -n '620,720p' internal/auth/generic/generic_test.go"`
```
	if !ok {
		t.Fatalf("expected *AuthService, got %T", authService)
	}

	tests := []struct {
		name        string
		token       string
		wantError   bool
		errContains string
	}{
		{
			name: "valid jwt",
			token: generateValidToken(t, privateKey, keyID, jwt.MapClaims{
				"iss":   "https://example.com",
				"aud":   "my-audience",
				"scope": "read:files",
				"exp":   time.Now().Add(time.Hour).Unix(),
			}),
			wantError: false,
		},
		{
			name:        "invalid token (wrong signature)",
			t  …(+2315 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,130p' internal/auth/generic/generic_test.go"`
```
// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for  …(+2770 more chars)
```
**→ shell:** `/bin/bash -lc 'git diff -- internal/auth/generic/generic.go internal/auth/generic/generic_test.go'`
```
diff --git a/internal/auth/generic/generic.go b/internal/auth/generic/generic.go
index 8a68a6d..c35597a 100644
--- a/internal/auth/generic/generic.go
+++ b/internal/auth/generic/generic.go
@@ -21,6 +21,7 @@ import (
 	"fmt"
 	"io"
 	"log"
+	"net"
 	"net/http"
 	"net/url"
 	"strings"
@@ -121,8 +122,8 @@ func discoverOIDCConfig(client *http.Client, AuthorizationServer string) (jwksUR
 	if err != nil {
 		return "", "", "", fmt.Errorf("invalid auth URL")
 	}
-	if u.Scheme != "https" {
-		log.Printf  …(+5272 more chars)
```
**Codex:** The diff is limited to the generic auth package. One concern remains: the existing tests use HTTP loopback JWKS servers, so the loopback allowance is deliberate; production/non-loopback HTTP is now rejected.

**→ shell:** `/bin/bash -lc "sed -n '120,170p' internal/auth/generic/generic_test.go"`
```
			rawURL:    "/auth",
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.Parse(tc.rawURL)
			if err != nil {
				t.Fatalf("failed to parse test URL: %v", err)
			}
			err = validateAuthEndpointURL(u, "test")
			if (err != nil) != tc.wantError {
				t.Fatalf("validateAuthEndpointURL() error = %v, wantError %v", err, tc.wantError)
			}
		})
	}
}

func TestInitialize_Validation(t *testing.T) {
	key := generateRSAPrivateKey(t)
	mockOIDC :  …(+739 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '720,755p' internal/auth/generic/generic_test.go"`
```
	ctx := util.WithLogger(context.Background(), logger)

	genericAuth := &AuthService{
		Config: Config{
			Audience: "my-audience",
		},
		issuer: "https://example.com",
	}

	err = genericAuth.validateClaims(ctx, "", []string{"my-audience"}, "")
	if err == nil {
		t.Fatalf("expected missing issuer to fail validation")
	}
	if !strings.Contains(err.Error(), "missing issuer claim") {
		t.Fatalf("expected missing issuer error, got: %v", err)
	}
}

func TestValidateOpaqueToken(t *testing.T) {
	tests :  …(+436 more chars)
```
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M internal/auth/generic/generic.go
 M internal/auth/generic/generic_test.go

```
**Codex:** I’m tightening two adjacent auth paths as well: configured/discovered introspection endpoints get the same URL validation, and non-MCP JWT validation now enforces the discovered issuer just like MCP JWT validation. Both are part of the same trust boundary.

**✎ files:** update `/work/internal/auth/generic/generic.go`

**Codex:** I’ve extended the remediation to cover the non-MCP JWT path. I’m adding a regression case so a token signed by the trusted JWKS but carrying the wrong issuer is rejected.

**✎ files:** update `/work/internal/auth/generic/generic_test.go`

**Codex:** The patch is complete. I’m doing a final diff review and another attempt to locate a runnable Go toolchain; if it’s still unavailable, I’ll leave the exact verification gap in the handoff.

**→ shell:** `/bin/bash -lc "env | rg '("'^PATH=|GOROOT|GOPATH)'"'"`
```
PATH=/usr/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-arm64/vendor/aarch64-unknown-linux-musl/codex-path:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
GOPATH=/go

```
**→ shell:** `/bin/bash -lc 'git diff -- internal/auth/generic/generic.go internal/auth/generic/generic_test.go'`
```
diff --git a/internal/auth/generic/generic.go b/internal/auth/generic/generic.go
index 8a68a6d..970c794 100644
--- a/internal/auth/generic/generic.go
+++ b/internal/auth/generic/generic.go
@@ -21,6 +21,7 @@ import (
 	"fmt"
 	"io"
 	"log"
+	"net"
 	"net/http"
 	"net/url"
 	"strings"
@@ -83,6 +84,15 @@ func (cfg Config) Initialize() (auth.AuthService, error) {
 	if cfg.IntrospectionEndpoint != "" {
 		introspectionURL = cfg.IntrospectionEndpoint
 	}
+	if introspectionURL != "" {
+		parsedIntrospe  …(+7517 more chars)
```
**→ shell:** `/bin/bash -lc "find / -path '*/bin/go' -o -path '*/bin/gofmt' 2>/dev/null | head -20"`
```
/usr/local/go/bin/go
/usr/local/go/bin/gofmt

```
**Codex:** A Go toolchain exists under `/usr/local/go/bin` but is not on `PATH`. I’m using the absolute binaries now to format and run the focused tests.

**→ shell:** `/bin/bash -lc '/usr/local/go/bin/gofmt -w internal/auth/generic/generic.go internal/auth/generic/generic_test.go'`
**→ shell:** `/bin/bash -lc '/usr/local/go/bin/go test ./internal/auth/generic'`
```
go: downloading github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric v0.56.0
go: downloading github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/trace v1.32.0
go: downloading go.opentelemetry.io/contrib/propagators/autoprop v0.68.0
go: downloading go.opentelemetry.io/otel v1.43.0
go: downloading go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp v1.43.0
go: downloading go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.43.0
go:  …(+4675 more chars)
```
**Codex:** Formatting succeeded. The focused test command now starts, but dependency downloads are blocked by the environment egress allowlist before compilation; I’m checking whether a vendor cache exists that can avoid network access.

**→ shell:** `/bin/bash -lc 'ls -la /go/pkg/mod/github.com 2>/dev/null | head -30'`
**→ shell:** `/bin/bash -lc 'test -d vendor && echo vendor-present || echo no-vendor'`
```
no-vendor

```
**→ shell:** `/bin/bash -lc 'git diff --check -- internal/auth/generic/generic.go internal/auth/generic/generic_test.go'`
**Codex:** There’s no vendored dependency tree or populated module cache, so the test run can’t get past blocked module downloads here. I’m doing one last source diff/status check for cleanliness.

**→ shell:** `/bin/bash -lc 'git diff -- internal/auth/generic/generic.go internal/auth/generic/generic_test.go'`
```
diff --git a/internal/auth/generic/generic.go b/internal/auth/generic/generic.go
index 8a68a6d..970c794 100644
--- a/internal/auth/generic/generic.go
+++ b/internal/auth/generic/generic.go
@@ -21,6 +21,7 @@ import (
 	"fmt"
 	"io"
 	"log"
+	"net"
 	"net/http"
 	"net/url"
 	"strings"
@@ -83,6 +84,15 @@ func (cfg Config) Initialize() (auth.AuthService, error) {
 	if cfg.IntrospectionEndpoint != "" {
 		introspectionURL = cfg.IntrospectionEndpoint
 	}
+	if introspectionURL != "" {
+		parsedIntrospe  …(+7517 more chars)
```
**→ shell:** `/bin/bash -lc 'git diff --stat'`
```
 internal/auth/generic/generic.go      | 78 +++++++++++++++++++++++++++----
 internal/auth/generic/generic_test.go | 87 +++++++++++++++++++++++++++++++++++
 2 files changed, 155 insertions(+), 10 deletions(-)

```
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M internal/auth/generic/generic.go
 M internal/auth/generic/generic_test.go

```
**Codex:** Implemented the remediation in [generic.go](/work/internal/auth/generic/generic.go):

- Rejects non-HTTPS auth, JWKS, and introspection endpoints, except loopback HTTP for local/test servers.
- Requires OIDC discovery metadata to include an issuer.
- Enforces issuer validation for both MCP claim validation and non-MCP JWT header validation, including rejecting missing issuer claims when an issuer was discovered.

Added regression coverage in [generic_test.go](/work/internal/auth/generic/generic_test.go) for endpoint URL validation, issuer mismatch, and missing issuer rejection.

Verification:
- Ran `/usr/local/go/bin/gofmt` successfully.
- Ran `git diff --check` successfully.
- Tried `/usr/local/go/bin/go test ./internal/auth/generic`, but it could not compile because dependency downloads from `proxy.golang.org` are blocked by the environment egress allowlist.


---
*tokens — input 622437 (cached 519936), output 7125, reasoning 1802*
