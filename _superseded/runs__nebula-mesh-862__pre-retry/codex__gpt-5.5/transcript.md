**Codex:** I’ll read the finding and inspect the referenced code paths before editing, then keep the fix scoped to the vulnerability without changing intended behavior.

**→ shell:** `/bin/bash -lc "sed -n '1,220p' FINDING.txt"`
```
Project: forgekeep/nebula-mesh
Vulnerability type: Missing Authorization (CWE-862)

Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):

  internal/api/audit.go
    - lines 10-16   in: import (

  internal/api/authz.go
    - lines 8-17   in: import (

  internal/api/cas.go
    - lines 37-43   in: func (s *Server) handleListCAs(w http.ResponseWriter, r *http.Request) {
    - lines 183-189   in: func (s *Server) handleDeleteCA(w http.ResponseWriter, r *http.Reques  …(+1285 more chars)
```
**→ shell:** `/bin/bash -lc 'pwd && rg --files'`
```
/work
SECURITY.md
configs/server.example.yml
configs/agent.example.yml
CONTRIBUTING.md
README.md
CHANGELOG.md
LICENSE
nebula-research.md
go.mod
docs/server.md
docs/deployment.md
cmd/nebula-mgmt/main.go
docs/screenshots/host-detail.png
docs/screenshots/profile.png
docs/screenshots/networks.png
docs/screenshots/2fa-enabled.png
docs/screenshots/host-new-advanced.png
docs/screenshots/register.png
docs/screenshots/hosts.png
docs/screenshots/login-totp.png
docs/screenshots/login.png
docs/screenshots/d  …(+11294 more chars)
```
**→ shell:** `/bin/bash -lc 'git status --short'`
**Codex:** The finding points at API handlers with missing authorization. I’m going to inspect the route wiring, auth middleware, and existing authz tests so the remediation uses the project’s current access model.

**→ shell:** `/bin/bash -lc "sed -n '1,260p' internal/api/server.go"`
```
package api

import (
	"context"
	"encoding/json"
	"expvar"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	poppkg "github.com/juev/nebula-mesh/internal/api/pop"
	"github.com/juev/nebula-mesh/internal/auth"
	"github.com/juev/nebula-mesh/internal/configgen"
	"github.com/juev/nebula-mesh/internal/keystore"
	"github.com/juev/nebula-mesh/internal/pki"
	"github.com/juev/nebula-mesh/interna  …(+8884 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,260p' internal/api/authz.go"`
```
package api

import (
	"context"
	"errors"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

// actorOwnsCA returns true if the actor in ctx is admin, or owns the CA with caID.
// Returns (false, nil) for empty caID or ErrNotFound. Errors only for unexpected DB errors.
func (s *Server) actorOwnsCA(ctx context.Context, caID string) (bool, error) {
	if actorIsAdmin(ctx) {
		return true, nil
	}
	if caID == "" {
		return false, nil
	}
	actor := ActorOf(  …(+1059 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,280p' internal/api/operators.go"`
```
package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

type createOperatorRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
	Role        string `json:"role"`
}

func (s  …(+7497 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,260p' internal/api/cas.go"`
```
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/juev/nebula-mesh/internal/keystore"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/pki"
	"github.com/juev/nebula-mesh/internal/store"
)

type createCARequest struct {
	Name     string `json:"name"`
	Duration string `json:"duration,omitempty"` // e.g. "8760h"
}

type caResponse struct {
	*models.CA
	IsDefault bool `  …(+5820 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,460p' internal/api/hosts.go"`
```
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

type createHostRequest struct {
	NetworkID  string               `json:"network_id"`
	Name       string               `json:"name"`
	NebulaIPs  []string             `json:"nebula_ips"`
	Groups     []string             `json:"groups"`
	Role       string           …(+13895 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,180p' internal/api/networks.go"`
```
package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

type createNetworkRequest struct {
	Name  string   `json:"name"`
	CIDRs []string `json:"cidrs"`
}

func (s *Server) handleCreateNetwork(w http.ResponseWriter, r *http.Request) {
	if !actorIsAdmin(r.Context()) {
		writeError(w, http.StatusForbidden, "network creation requires the admin role")
		r  …(+2462 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,120p' internal/api/settings.go"`
```
package api

import (
	"encoding/json"
	"net/http"
)

// settingEnforceTOTP duplicates the web package's exported key name so
// the API handler doesn't pull web in. Keep these literally identical
// — the value is the contract.
const settingEnforceTOTP = "enforce_2fa"

type settingsRequest struct {
	EnforceTOTP *bool `json:"enforce_2fa,omitempty"`
}

type settingsResponse struct {
	EnforceTOTP bool `json:"enforce_2fa"`
}

// handleGetSettings returns the current admin-tunable server settings.
/  …(+1477 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,220p' internal/api/audit.go"`
```
package api

import (
	"net/http"
	"strconv"

	"github.com/juev/nebula-mesh/internal/store"
)

const defaultAuditLimit = 100

func (s *Server) handleGetAuditLog(w http.ResponseWriter, r *http.Request) {
	if !actorIsAdmin(r.Context()) {
		writeError(w, http.StatusForbidden, "audit log access requires the admin role")
		return
	}
	filter := store.AuditFilter{
		Action: r.URL.Query().Get("action"),
		Limit:  defaultAuditLimit,
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		n, err := strconv.At  …(+530 more chars)
```
**Codex:** Some of the listed handlers already contain per-object or admin checks, so I’m checking whether the issue is inconsistent enforcement on specific routes or missing coverage around list/filter helpers.

**→ shell:** `/bin/bash -lc "sed -n '1,260p' internal/api/middleware.go"`
```
package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/juev/nebula-mesh/internal/ratelimit"
	"github.com/juev/nebula-mesh/internal/store"
)

// maxBodySize returns middleware that limits the size of request bodies.
func maxBodySize(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Re  …(+3850 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,260p' internal/api/actor.go"`
```
package api

import (
	"context"

	"github.com/juev/nebula-mesh/internal/models"
)

// actorContextKey scopes the authenticated operator on the request context.
type actorContextKeyType struct{}

var actorContextKey = actorContextKeyType{}

// ActorOf returns the operator attached to the request context. On protected
// API routes bearerAuth guarantees a non-nil value; nil indicates an
// unauthenticated context (e.g. public endpoints, tests).
func ActorOf(ctx context.Context) *models.Operator {  …(+1213 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,260p' internal/api/authz_test.go"`
```
package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/juev/nebula-mesh/internal/keystore"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/pki"
)

// createOperatorWithCA creates a non-admin operator with an API key and a CA owned by that operator.
// Returns (plaintext apiKey, operator  …(+6822 more chars)
```
**→ shell:** `/bin/bash -lc 'rg "actorIsAdmin|canAccess|requires the admin|forbidden|ListCAsByOwner|OwnerOperatorID" internal/api -n'`
```
internal/api/actor.go:36:// actorIsAdmin reports whether the request's authenticated actor has the
internal/api/actor.go:38:func actorIsAdmin(ctx context.Context) bool {
internal/api/operators.go:28:	if !actorIsAdmin(r.Context()) {
internal/api/operators.go:29:		writeError(w, http.StatusForbidden, "operator management requires the admin role")
internal/api/operators.go:68:	if !actorIsAdmin(r.Context()) {
internal/api/operators.go:69:		writeError(w, http.StatusForbidden, "operator management requ  …(+6740 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '260,560p' internal/api/authz_test.go"`
```
	op2 := &models.Operator{
		ID:           uuid.New().String(),
		Username:     "other-user",
		PasswordHash: "hash",
		Role:         "user",
		Status:       models.OperatorStatusActive,
		AuthProvider: models.OperatorAuthLocal,
	}
	err := srv.store.CreateOperator(context.Background(), op2)
	require.NoError(t, err)

	ctx := context.Background()
	ctx = context.WithValue(ctx, actorContextKey, op2)

	// Try to access network in other operator's CA
	network := &models.Network{
		ID:   uuid.New().Stri  …(+240 more chars)
```
**Codex:** The codebase already has a CA ownership model. One risky gap remains in helper/list paths: they assume every object has a CA owner and sometimes dereference the actor implicitly, so I’m going to tighten that into shared fail-closed helpers and add regression tests for the listed endpoints.

**→ shell:** `/bin/bash -lc "sed -n '1,260p' internal/api/hosts_authz_test.go"`
```
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/juev/nebula-mesh/internal/models"
)

// TestCreateHost_RequiresNetworkOwnership verifies that non-owners cannot create hosts in foreign networks
func TestCreateHost_RequiresNetworkOwnership(t *testing.T) {
	srv, testDB := newTestServer(t)

	// Create two operators with different CAs
	_, _, ca1 :=   …(+8104 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,240p' internal/api/server_test.go"`
```
package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/juev/nebula-mesh/internal/auth"
	"github.com/juev/nebula-mesh/internal/keystore"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/pki"
	"github.com/juev/nebula-mesh/internal/store"
)

const testAPIKey = "test-api-key-12345"

func newTestServer(t *testing.T) (*Server, *store.SQLit  …(+6068 more chars)
```
**→ shell:** `/bin/bash -lc 'rg "func newTestServer|createTest|api key|Authorization|Bearer" internal/api/*_test.go -n'`
```
internal/api/audit_authz_test.go:14:	req.Header.Set("Authorization", "Bearer "+userKey)
internal/api/audit_authz_test.go:27:	req.Header.Set("Authorization", "Bearer "+adminKey)
internal/api/audit_property_test.go:91:		t.Fatalf("decode api key: %v", err)
internal/api/audit_validator_test.go:81://   - Bare JWTs (without the "Bearer " prefix) — the bearer regex
internal/api/audit_validator_test.go:82://     catches `Bearer eyJ...` but a raw JWT pasted naked passes. OIDC
internal/api/audit_validator  …(+6065 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,220p' internal/api/networks_authz_test.go"`
```
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/juev/nebula-mesh/internal/models"
)

// TestCreateNetwork_RequiresAdmin verifies that handleCreateNetwork is
// admin-only: non-admin operators cannot create networks (createNetworkRequest
// has no CAID field, so non-admin creation would produce orphan networks).
func TestCreateNetwork_RequiresAd  …(+3819 more chars)
```
**Codex:** There are already endpoint tests for most of the object-level operations. I’m going to add the missing hardening in code first, then use focused tests to prove non-admins can’t see or mutate outside their scope.

**→ shell:** `/bin/bash -lc "sed -n '1,240p' internal/api/operators_admin_test.go"`
```
package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/juev/nebula-mesh/internal/models"
)

// createUserWithAPIKey seeds a non-admin operator + API key directly via the
// store, then returns the plaintext key.
func createUserWithAPIKey(t *testing.T, srv *Server, role string) string {
	t.Helper()
	ctx := context.Background()
	op := &models.Operator{
		ID:           uuid.New(  …(+5588 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '440,540p' internal/api/hosts_authz_test.go"`
```
		CAID:  caA.ID,
		CIDRs: []string{"10.0.0.0/8"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), netA))

	// Create network for operator B
	netB := &models.Network{
		ID:    "net-list-b",
		Name:  "Network B",
		CAID:  caB.ID,
		CIDRs: []string{"10.1.0.0/8"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), netB))

	// Create host under CA A
	hostA := &models.Host{
		ID:        "host-list-a",
		Name:      "Host A",
		NetworkID: netA.ID,
		CAID:      caA.ID,
		  …(+1814 more chars)
```
**→ shell:** `/bin/bash -lc 'rg "func createUserWithAPIKey|func create.*APIKey" internal/api -n'`
```
internal/api/operators_admin_test.go:20:func createUserWithAPIKey(t *testing.T, srv *Server, role string) string {

```
**→ shell:** `/bin/bash -lc 'go test ./internal/api'`
```
/bin/bash: line 1: go: command not found

```
**Codex:** Before editing, I found `go` is not installed in this container, so I won’t be able to run the Go test suite here. I’ll still add compile-conscious, narrowly scoped changes and report that verification limitation clearly.

**✎ files:** update `/work/internal/api/authz.go`

**Codex:** I added shared authorization helpers that fail closed on missing actors and centralize CA ownership scoping. Next I’m wiring the affected handlers to those helpers so list and object paths use one consistent rule.

**✎ files:** update `/work/internal/api/cas.go`

**Codex:** The CA handlers now avoid implicit actor dereferences and use the shared CA access check. I’m applying the same ownership-set helper to host and network listing so scoping can’t drift between endpoints.

**✎ files:** update `/work/internal/api/hosts.go`

**✎ files:** update `/work/internal/api/networks.go`

**→ shell:** `/bin/bash -lc 'rg "audit log access|operator management requires|network creation requires|blocklist access|admin role required|enforce_2fa" internal/api/*_test.go -n'`
```
internal/api/audit_validator_test.go:167:		{Actor: "alice", Action: auditSettingsEnforce2FA, Resource: "enforce_2fa", Details: "true", Timestamp: nowForTest()},
internal/api/audit_property_test.go:21://     (e.g. the historical "settings.enforce_2fa" drift fixed alongside
internal/api/audit_property_test.go:99:	// settings.enforce_2fa — the action that was historically a literal
internal/api/audit_property_test.go:103:		[]byte(`{"enforce_2fa":true}`), http.StatusOK)

```
**Codex:** I’m also moving the admin-only endpoints behind route-level admin middleware while keeping the handler checks. That gives defense in depth at the routing boundary without changing which callers are allowed.

**✎ files:** update `/work/internal/api/server.go`

**Codex:** The route table now enforces admin role before admin-only handlers are invoked. I’m doing a static pass for stale call sites and formatting/compile issues since the Go toolchain isn’t available here.

**→ shell:** `/bin/bash -lc "sed -n '1,220p' internal/api/authz.go"`
```
package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

// actorOwnsCA returns true if the actor in ctx is admin, or owns the CA with caID.
// Returns (false, nil) for empty caID or ErrNotFound. Errors only for unexpected DB errors.
func (s *Server) actorOwnsCA(ctx context.Context, caID string) (bool, error) {
	if actorIsAdmin(ctx) {
		return true, nil
	}
	if caID == "" {
		return false, nil
	}
	actor  …(+2220 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '140,235p' internal/api/server.go"`
```
	s.defaultCAID = id
}

func (s *Server) setupRoutes() {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(requestLogger(s.logger))
	r.Use(s.metricsMiddleware())
	r.Use(maxBodySize(1 << 20)) // 1MB

	// Public endpoints — operations and enrollment
	r.Get("/health", s.handleHealth) // legacy alias
	r.Get("/healthz", s.handleHealth)
	r.Get("/readyz", s.handleReady)
	if s.metricsEnabled {
		r.Method("GET", "/metrics", promhttp.HandlerFor(s.metrics.reg, promhttp.H  …(+3276 more chars)
```
**→ shell:** `/bin/bash -lc "rg \"canAccessCA\\(\" internal/api -n"`
```
internal/api/authz.go:59:func (s *Server) canAccessCA(ctx context.Context, c *models.CA) bool {
internal/api/cas.go:73:	if !s.canAccessCA(r.Context(), c) {
internal/api/cas.go:177:	if !s.canAccessCA(r.Context(), c) {
internal/api/cas.go:205:	if !s.canAccessCA(r.Context(), oldCA) {

```
**→ shell:** `/bin/bash -lc 'git diff -- internal/api/authz.go internal/api/cas.go internal/api/hosts.go internal/api/networks.go internal/api/server.go'`
```
diff --git a/internal/api/authz.go b/internal/api/authz.go
index 8acb9aa..c28f214 100644
--- a/internal/api/authz.go
+++ b/internal/api/authz.go
@@ -3,6 +3,7 @@ package api
 import (
 	"context"
 	"errors"
+	"net/http"
 
 	"github.com/juev/nebula-mesh/internal/models"
 	"github.com/juev/nebula-mesh/internal/store"
@@ -35,6 +36,47 @@ func (s *Server) actorOwnsCA(ctx context.Context, caID string) (bool, error) {
 	return ca.OwnerOperatorID == actor.ID, nil
 }
 
+// actorOwnedCAIDs returns the set   …(+8392 more chars)
```
**Codex:** One detail: route-level blocking would otherwise standardize the error message for all admin-only routes. I’m adjusting the middleware to preserve each endpoint family’s existing 403 message, so the permission behavior is hardened without changing response text.

**✎ files:** update `/work/internal/api/authz.go`

**Codex:** The admin middleware now accepts the existing endpoint message. I’m splitting the admin routes by endpoint family so current response bodies remain stable.

**✎ files:** update `/work/internal/api/server.go`

**Codex:** The source changes are in place. I’m running the checks available in this environment now: whitespace diff validation and a final grep/static review, since `go test` cannot run without the Go binary.

**→ shell:** `/bin/bash -lc 'which go || true'`
**→ shell:** `/bin/bash -lc 'git diff --check'`
**→ shell:** `/bin/bash -lc "rg \"requireAdminRole|canAccessCA\\(|actorOwnedCAIDs\" internal/api -n"`
```
internal/api/authz.go:39:// actorOwnedCAIDs returns the set of CA IDs owned by the authenticated actor.
internal/api/authz.go:42:func (s *Server) actorOwnedCAIDs(ctx context.Context) (map[string]struct{}, error) {
internal/api/authz.go:59:func (s *Server) canAccessCA(ctx context.Context, c *models.CA) bool {
internal/api/authz.go:70:func requireAdminRole(message string) func(http.Handler) http.Handler {
internal/api/hosts.go:192:		ownedCAIDs, err := s.actorOwnedCAIDs(r.Context())
internal/api/ne  …(+718 more chars)
```
**→ shell:** `/bin/bash -lc 'git diff --stat && git status --short'`
```
 internal/api/authz.go    | 44 ++++++++++++++++++++++++++++++++++++++++++++
 internal/api/cas.go      | 25 +++++++++++++------------
 internal/api/hosts.go    | 11 +----------
 internal/api/networks.go | 11 +----------
 internal/api/server.go   | 39 +++++++++++++++++++++++++++------------
 5 files changed, 86 insertions(+), 44 deletions(-)
 M internal/api/authz.go
 M internal/api/cas.go
 M internal/api/hosts.go
 M internal/api/networks.go
 M internal/api/server.go

```
**Codex:** `git diff --check` passed, and `which go` returned nothing, confirming the Go toolchain is unavailable. I’m doing one last review of the final diff for route coverage and fail-closed paths.

**→ shell:** `/bin/bash -lc "sed -n '35,85p' internal/api/authz.go"`
```
	}
	return ca.OwnerOperatorID == actor.ID, nil
}

// actorOwnedCAIDs returns the set of CA IDs owned by the authenticated actor.
// Admin callers should not use this helper because they are intentionally not
// scoped to ownership. Missing actors fail closed with an empty set.
func (s *Server) actorOwnedCAIDs(ctx context.Context) (map[string]struct{}, error) {
	actor := ActorOf(ctx)
	if actor == nil {
		return map[string]struct{}{}, nil
	}
	cas, err := s.store.ListCAsByOwner(ctx, actor.ID)
	if e  …(+960 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '185,225p' internal/api/server.go"`
```
		r.Get("/api/v1/networks/{id}/firewall", s.handleGetFirewall)
		r.Put("/api/v1/networks/{id}/firewall", s.handleUpdateFirewall)
		r.Get("/api/v1/cas", s.handleListCAs)
		r.Post("/api/v1/cas", s.handleCreateCA)
		r.Get("/api/v1/cas/{id}", s.handleGetCAByID)
		r.Delete("/api/v1/cas/{id}", s.handleDeleteCA)
		r.Post("/api/v1/cas/{id}/rotate", s.handleRotateCA)
		r.Group(func(r chi.Router) {
			r.Use(requireAdminRole("network creation requires the admin role"))
			r.Post("/api/v1/networks", s.handl  …(+1242 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '30,85p' internal/api/cas.go && sed -n '185,215p' internal/api/hosts.go && sed -n '55,85p' internal/api/networks.go"`
```
	return caResponse{CA: c, IsDefault: c.ID == s.defaultCAID}
}

// handleListCAs returns all CAs visible to the actor. Admin sees all,
// non-admin sees only CAs they own.
func (s *Server) handleListCAs(w http.ResponseWriter, r *http.Request) {
	var (
		cas []*models.CA
		err error
	)
	if actorIsAdmin(r.Context()) {
		cas, err = s.store.ListCAs(r.Context())
	} else {
		actor := ActorOf(r.Context())
		if actor == nil {
			writeJSON(w, http.StatusOK, []caResponse{})
			return
		}
		cas, err = s.sto  …(+2922 more chars)
```
**Codex:** Implemented the authorization remediation.

Changed:
- [internal/api/server.go](/work/internal/api/server.go): added route-level admin enforcement for admin-only API families while preserving existing 403 messages.
- [internal/api/authz.go](/work/internal/api/authz.go): centralized CA ownership checks, fail-closed missing actor handling, and shared owned-CA scoping.
- [internal/api/cas.go](/work/internal/api/cas.go), [internal/api/hosts.go](/work/internal/api/hosts.go), [internal/api/networks.go](/work/internal/api/networks.go): wired handlers to the shared authorization helpers and removed duplicated scoping logic.

Verification:
- `git diff --check` passed.
- I could not run `go test` because `go` is not installed in this environment (`which go` returned nothing).


---
*tokens — input 786574 (cached 726656), output 7033, reasoning 1621*
