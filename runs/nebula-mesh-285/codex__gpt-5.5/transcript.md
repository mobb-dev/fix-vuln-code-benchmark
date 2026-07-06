**Codex:** I’ll read the vulnerability note first, then inspect the referenced code paths before making a narrowly scoped fix.

**→ shell:** `/bin/bash -lc 'pwd && ls'`
```
/work
CHANGELOG.md
CODE_OF_CONDUCT.md
CONTRIBUTING.md
Dockerfile
FINDING.txt
LICENSE
Makefile
README.md
SECURITY.md
cmd
configs
deploy
details.md
docs
go.mod
go.sum
internal
nebula-research.md
tests

```
**→ shell:** `/bin/bash -lc "sed -n '1,220p' FINDING.txt"`
```
Project: forgekeep/nebula-mesh
Vulnerability type: Improper Authorization (CWE-285)

Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):

  internal/api/audit.go
    - lines 10-15   in: import (

  internal/api/firewall.go
    - lines 29-34   in: var defaultFirewallRules = firewallRulesRequest{
    - lines 42-47   in: func (s *Server) handleGetFirewall(w http.ResponseWriter, r *http.Request) {

  internal/api/hosts.go
    - lines 51-56   in: func (s *Server) han  …(+2115 more chars)
```
**Codex:** The finding points broadly at API handlers, so I’m checking how authorization is currently enforced and where router middleware is wired.

**→ shell:** `/bin/bash -lc 'rg -n "auth|authorize|operator|role|permission|middleware|handle(Get|Create|List|Delete|Block|Unblock|Update|Rotate|Mobile|Firewall|Network)" internal/api'`
```
internal/api/actor.go:9:// actorContextKey scopes the authenticated operator on the request context.
internal/api/actor.go:14:// ActorOf returns the operator attached to the request context. On protected
internal/api/actor.go:16:// unauthenticated context (e.g. public endpoints, tests).
internal/api/actor.go:36:// actorIsAdmin reports whether the request's authenticated actor has the
internal/api/actor.go:37:// admin role. Returns false when no actor is on the context (fail-closed).
internal/api  …(+30213 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,240p' internal/api/operators.go"`
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
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
	"golang.org/x/crypto/bcrypt"
)

type createOperatorRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
	Role        string `json:"role"`
}

func (s   …(+5360 more chars)
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
	Role       string            …(+14540 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,240p' internal/api/server.go"`
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
	poppkg "github.com/juev/nebula-mesh/internal/api/pop"
	"github.com/juev/nebula-mesh/internal/auth"
	"github.com/juev/nebula-mesh/internal/configgen"
	"github.com/juev/nebula-mesh/internal/keystore"
	"github.com/juev/nebula-mesh/internal/pki"
	"github.com/juev/nebula-mesh/internal/ratelimit"
	"github.com/juev/nebula-mesh/internal/store"
	  …(+8359 more chars)
```
**Codex:** I found existing admin checks on a few handlers, but many protected routes only require a valid API key. I’m looking at actor roles and CA/network ownership patterns now so the remediation matches the project’s authorization model instead of inventing a new one.

**→ shell:** `/bin/bash -lc "sed -n '1,280p' internal/api/cas.go"`
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
	IsDefault bool `j  …(+5819 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,220p' internal/api/actor.go"`
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
	var req createNetworkRequest
	if err := decodeJSONStrict(r, &req); err != nil {
		writeError(w, http.StatusBadRequest,  …(+1421 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,140p' internal/api/firewall.go && sed -n '1,120p' internal/api/audit.go && sed -n '1,120p' internal/api/mobile_bundle.go"`
```
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/juev/nebula-mesh/internal/store"
)

type firewallRulesRequest struct {
	Inbound  []firewallRule `json:"inbound"`
	Outbound []firewallRule `json:"outbound"`
}

type firewallRule struct {
	Port  string `json:"port"`
	Proto string `json:"proto"`
	Group string `json:"group"`
}

var defaultFirewallRules = firewallRulesRequest{
	Inbound:  []firewallRule{{Port: "any", Proto: "icmp", Group: "any  …(+5388 more chars)
```
**Codex:** The existing model has “admin bypass, non-admin owns CAs” for CA routes. The vulnerable handlers appear to miss the same resource authorization, especially when operating on hosts tied to a CA.

**→ shell:** `/bin/bash -lc "sed -n '1,260p' internal/models/models.go"`
```
sed: can't read internal/models/models.go: No such file or directory

```
**→ shell:** `/bin/bash -lc 'rg -n "OwnerOperatorID|CAID|ListHosts|HostFilter|CreateHost|GetHost|Network" internal/store internal/models internal/api/*test.go'`
```
internal/models/ca.go:19:	OwnerOperatorID      string    `json:"owner_operator_id"`
internal/models/validate_ip.go:52:// ValidateNetworkCIDRs validates a list of CIDRs for a network. It checks that:
internal/models/validate_ip.go:57:func ValidateNetworkCIDRs(cidrs []string) error {
internal/store/sqlite_test.go:26:func createTestNetwork(t *testing.T, s *SQLiteStore) *models.Network {
internal/store/sqlite_test.go:28:	n := &models.Network{
internal/store/sqlite_test.go:34:	if err := s.CreateNetwo  …(+50291 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,240p' internal/api/operators_admin_test.go && sed -n '120,380p' internal/api/cas_test.go"`
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
		ID:           uuid.New()  …(+9101 more chars)
```
**Codex:** I need one small support layer: a helper that answers “can this actor touch this host/network?” and then the handlers can fail closed before reading or mutating data. I’m checking store capabilities to avoid adding broad database changes.

**→ shell:** `/bin/bash -lc "rg -n \"type Host|type Network|type Operator\" internal/models && sed -n '1,180p' internal/models/host.go && sed -n '1,120p' internal/models/network.go && sed -n '1,80p' internal/models  …(+13 more chars)`
```
internal/models/network.go:5:type Network struct {
internal/models/host.go:9:type HostStatus string
internal/models/host.go:17:type HostRole string
internal/models/host.go:35:type HostKind string
internal/models/host.go:52:type HostVariant string
internal/models/host.go:130:type Host struct {
internal/models/host.go:176:type HostAdvanced struct {
internal/models/operator.go:6:type OperatorStatus string
internal/models/operator.go:14:type OperatorAuthProvider string
internal/models/operator.go:22  …(+9306 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"type Store|HostFilter|ListHosts\\(|ListCAsByOwner|OwnerOperatorID|GetCA\\(\" internal/store"`
```
internal/store/sqlite_test.go:60:	hosts, err := s.ListHosts(ctx, HostFilter{})
internal/store/sqlite_test.go:204:	hosts, err := s.ListHosts(ctx, HostFilter{NetworkID: net.ID})
internal/store/sqlite_test.go:232:	hosts, err := s.ListHosts(ctx, HostFilter{Limit: 2})
internal/store/sqlite_test.go:241:	hosts, err = s.ListHosts(ctx, HostFilter{})
internal/store/sqlite_test.go:272:	hosts, err := s.ListHosts(ctx, HostFilter{Group: "web"})
internal/store/sqlite_test.go:568:	hosts, err := s.ListHosts(ctx,  …(+2090 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,180p' internal/api/server_test.go"`
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

func newTestServer(t *testing.T) (*Server, *store.SQLit  …(+4327 more chars)
```
**Codex:** I’m going to implement the ownership checks against the existing CA ownership data. For hosts with no CA yet, I’ll keep legacy default-CA behavior compatible while making non-admin access fail closed for unknown or foreign CA IDs.

**→ shell:** `/bin/bash -lc "sed -n '1,130p' internal/store/store.go"`
```
package store

import (
	"context"
	"time"

	"github.com/juev/nebula-mesh/internal/models"
)

// HostFilter specifies filters for listing hosts.
type HostFilter struct {
	NetworkID string
	Group     string
	Status    models.HostStatus
	Limit     int // 0 = no limit
}

// AuditFilter specifies filters for audit log queries.
type AuditFilter struct {
	Action string
	Limit  int
}

// Store defines the persistence interface for the management server.
type Store interface {
	// CAs
	CreateCA(ctx cont  …(+6013 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '640,735p' internal/store/sqlite.go"`
```
	h, err := s.scanHost(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get host by fingerprint: %w", err)
	}

	addrs, err := s.loadHostAddresses(ctx, h.ID)
	if err != nil {
		return nil, err
	}
	h.NebulaIPs = addrs

	return h, nil
}

func (s *SQLiteStore) ListHosts(ctx context.Context, filter HostFilter) ([]*models.Host, error) {
	query := `SELECT ` + hostColumns + ` FROM hosts WHERE 1=1`
	var args []any

	if filter.NetworkID != ""   …(+1889 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '60,140p' internal/store/sqlite_cas.go"`
```
	}
	return nil
}

func (s *SQLiteStore) GetCA(_ context.Context, id string) (*models.CA, error) {
	row := s.db.QueryRow(`SELECT `+caColumns+` FROM cas WHERE id = ?`, id)
	c, err := scanCA(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get CA: %w", err)
	}
	return c, nil
}

func (s *SQLiteStore) GetCAByFingerprint(_ context.Context, fp string) (*models.CA, error) {
	row := s.db.QueryRow(`SELECT `+caColumns+` FROM cas WHERE fingerpr  …(+1994 more chars)
```
**Codex:** Before editing, I’m checking whether networks already carry a CA ID through creation. That determines whether host creation should bind to the network CA or the server default CA.

**→ shell:** `/bin/bash -lc "sed -n '1,120p' internal/models/ca.go"`
```
package models

import "time"

// CAStatus is the lifecycle status of a CA.
type CAStatus string

const (
	CAStatusActive  CAStatus = "active"
	CAStatusRetired CAStatus = "retired"
)

// CA is a per-operator certificate authority. Private key material lives
// only inside EncryptedKeyMaterial / NonceKey, wrapped under a per-CA DEK
// stored in EncryptedKeyDEK / NonceDEK (envelope encryption — see ADR 0002).
type CA struct {
	ID                   string    `json:"id"`
	Name                 string  …(+675 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"CAID|ca_id|CreateNetwork|Network\\{\" internal cmd docs tests | head -n 200"`
```
internal/pki/rotate.go:121:			"new_ca_id", newCA.ID,
internal/pki/rotate.go:122:			"old_ca_id", oldCA.ID,
internal/pki/autoprovision.go:133:			"ca_id", ca.ID,
tests/integration/e2e_test.go:136:	srv.WithDefaultCAID(ca.ID)
internal/store/sqlite_test.go:28:	n := &models.Network{
internal/store/sqlite_test.go:34:	if err := s.CreateNetwork(context.Background(), n); err != nil {
internal/store/sqlite_test.go:99:	n := &models.Network{
internal/store/sqlite_test.go:105:	if err := s.CreateNetwork(ctx, n)  …(+19499 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"handleHostUpdate|canAccessCA|owner|CA\" internal/web internal -g'*.go'"`
```
internal/web/oidc_auto_provision_test.go:27:	o.provisionCA = w.provisionDefaultCA
internal/web/oidc_auto_provision_test.go:43:	// Verify default CA was auto-provisioned.
internal/web/oidc_auto_provision_test.go:44:	cas, err := s.ListCAsByOwner(ctx, op.ID)
internal/web/oidc_auto_provision_test.go:46:		t.Fatalf("ListCAsByOwner failed: %v", err)
internal/web/oidc_auto_provision_test.go:49:		t.Fatalf("ListCAsByOwner returned %d CAs, want 1", len(cas))
internal/web/oidc_auto_provision_test.go:54:		t.  …(+156439 more chars)
```
**Codex:** The Web UI already has the intended security rule: user-created networks are tied to an owned CA, and host creation inherits the network CA. I’ll mirror that in the API so both surfaces enforce the same boundary.

**→ shell:** `/bin/bash -lc "sed -n '110,190p' internal/web/form_state.go && sed -n '1,120p' internal/web/networks.go && sed -n '1,130p' internal/web/hosts.go"`
```
	if err != nil {
		return nil, err
	}
	out := make([]*models.CA, 0, len(cas))
	for _, c := range cas {
		if c.Status == models.CAStatusActive {
			out = append(out, c)
		}
	}
	return out, nil
}

// accessibleNetworks returns the networks an operator can attach a host
// to. admins see every network; users see only networks whose CAID
// points at a CA they own. Legacy networks with an empty CAID are
// visible to admins (they predate per-operator CAs) and hidden from
// users (issue #93 — a self  …(+2157 more chars)
```
**→ shell:** `/bin/bash -lc 'rg -n "ca_id|owner|authorization|Improper Authorization|CWE-285" details.md nebula-research.md docs internal/api'`
```
docs/server.md:184:  "ca_id": "ca_xyz789",
docs/server.md:396:- **New CA** (`predecessor_id = old-ca-id`): The successor. Same owner, same
internal/api/middleware.go:39:				writeError(w, http.StatusUnauthorized, "missing authorization header")
internal/api/enroll.go:119:		s.logger.Error("resolve host CA", "error", err, "host", host.ID, "ca_id", host.CAID)
internal/api/cas.go:183:// canAccessCA checks ownership. Admins bypass.
internal/api/ca_for_host.go:16:		return nil, fmt.Errorf("host %s has n  …(+9879 more chars)
```
**Codex:** The docs confirm the API is supposed to accept `ca_id` on network creation. The current handler drops it, which is part of the authorization gap. I’m going to add that field, validate CA ownership on network creation, and enforce the same visibility/mutation checks on networks, hosts, firewall, audit, and operator administration.

**→ shell:** `/bin/bash -lc "sed -n '160,205p' docs/server.md"`
```

## Networks and Hosts

### Creating a network

Networks can contain one or more CIDR prefixes, enabling dual-stack (IPv4 + IPv6)
and segmented address schemes. Create via the Web UI or REST API:

```bash
curl -X POST "https://mgmt.example.com:8080/api/v1/networks" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "production",
    "cidrs": ["10.42.0.0/24", "fd00:42::/64"]
  }'
```

Response (201):
```json
{
  "id": "net_abc123",
  "name": "pro  …(+714 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"func \\(w \\*Web\\) handleNetwork|handleHostCreate|not tied to a CA|NetworkCreate\" internal/web -g'*.go'"`
```
internal/web/handlers.go:645:func (w *Web) handleHostCreate(rw http.ResponseWriter, r *http.Request) {
internal/web/handlers.go:675:				w.renderHostNewError(rw, r, form, "this network is not tied to a CA you own — pick a network you created")
internal/web/handlers.go:680:				w.renderHostNewError(rw, r, form, "this network is not tied to a CA you own — pick a network you created")
internal/web/handlers.go:1157:func (w *Web) handleNetworks(rw http.ResponseWriter, r *http.Request) {
internal/web/ha  …(+1650 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1150,1245p' internal/web/handlers.go"`
```
		return ""
	}
	return n.CAID
}

// --- Networks ---

func (w *Web) handleNetworks(rw http.ResponseWriter, r *http.Request) {
	op := w.session.CurrentOperator(r)
	if op == nil {
		http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
		return
	}
	networks, err := w.store.ListNetworks(r.Context())
	if err != nil {
		w.logger.Error("list networks", "error", err)
		http.Error(rw, "Failed to load networks", http.StatusInternalServerError)
		return
	}
	cas, err := w.accessibleActiveCAs(r.Context(),   …(+2263 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '630,710p' internal/web/handlers.go"`
```
	if err != nil {
		w.logger.Error("list networks for host form", "error", err)
		http.Error(rw, "Failed to load networks", http.StatusInternalServerError)
		return
	}
	form := hostFormState{Kind: "agent"}
	w.renderForRequest(rw, r, "host_new.html", map[string]any{
		"Active":      "hosts",
		"Networks":    networks,
		"HasNetworks": len(networks) > 0,
		"Form":        form,
		"Error":       "",
	})
}

func (w *Web) handleHostCreate(rw http.ResponseWriter, r *http.Request) {
	if err := r.ParseFor  …(+2141 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,220p' internal/api/operators_admin_test.go"`
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
		ID:           uuid.New()  …(+1508 more chars)
```
**Codex:** I’m making the API checks explicit in handler code and adding focused regression tests for cross-operator access. The edits are local to `internal/api`.

**✎ files:** update `/work/internal/api/audit.go`, add `/work/internal/api/authorization.go`, update `/work/internal/api/firewall.go`, update `/work/internal/api/networks.go`, update `/work/internal/api/operators.go`

**Codex:** The shared helpers and network/operator/audit/firewall checks are in place. I’m now threading host authorization through the host lifecycle endpoints, including token minting and mobile bundle generation.

**✎ files:** update `/work/internal/api/hosts.go`, update `/work/internal/api/mobile_bundle.go`

**Codex:** I’m adding tests with two non-admin operators and separate CAs/networks/hosts to verify the API now rejects cross-tenant reads and mutations.

**→ shell:** `/bin/bash -lc "sed -n '1240,1295p' internal/web/handlers.go"`
```
	if caID != "" && !containsCAID(cas, caID) {
		w.renderNetworksError(rw, r, form, cas, "selected CA is not accessible to you")
		return
	}

	network := &models.Network{
		ID:        uuid.New().String(),
		Name:      form.Name,
		CIDRs:     form.CIDRs,
		CAID:      caID,
		CreatedAt: time.Now(),
	}

	if err := w.store.CreateNetwork(r.Context(), network); err != nil {
		w.logger.Error("create network", "error", err)
		http.Error(rw, "Failed to create network", http.StatusInternalServerError)
		ret  …(+1199 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,70p' internal/store/sqlite_cas.go"`
```
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/juev/nebula-mesh/internal/models"
)

const caColumns = `id, name, owner_operator_id, cert_pem, fingerprint, not_before, not_after, status, predecessor_id, encrypted_key_dek, nonce_dek, encrypted_key_material, nonce_key, created_at, updated_at`

func scanCA(scanner interface {
	Scan(dest ...any) error
}) (*models.CA, error) {
	var c models.CA
	var predecessorID sql.NullString
	if err := scanner.S  …(+1439 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,40p' internal/api/mobile_bundle.go"`
```
package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/juev/nebula-mesh/internal/mobilebundle"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/pki"
	"github.com/juev/nebula-mesh/internal/store"
)

// handleMobileBundle implements POST /api/v1/hosts/{id}/mobile-bundle.
// Generates a self-contained mobile bundle (YAML config + certificate + key)
// for a mobile host. The private key is generated fresh and returned inl  …(+666 more chars)
```
**✎ files:** add `/work/internal/api/authorization_test.go`, update `/work/internal/api/mobile_bundle.go`

**Codex:** The regression tests are added. I’m running formatting and the API test package now, then I’ll fix any compile or behavior issues that shake out.

**→ shell:** `/bin/bash -lc 'gofmt -w internal/api/authorization.go internal/api/networks.go internal/api/firewall.go internal/api/audit.go internal/api/operators.go internal/api/hosts.go internal/api/mobile_bundle  …(+39 more chars)`
```
/bin/bash: line 1: gofmt: command not found

```
**→ shell:** `/bin/bash -lc 'go test ./internal/api'`
```
/bin/bash: line 1: go: command not found

```
**Codex:** This container does not have the Go toolchain installed (`go` and `gofmt` are unavailable), so I can’t execute the package tests here. I’m doing a static pass over imports and touched code to catch issues manually.

**→ shell:** `/bin/bash -lc "sed -n '1,560p' internal/api/hosts.go"`
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
	Role       string            …(+16697 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,280p' internal/api/authorization_test.go"`
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
	"time"

	"github.com/google/uuid"
	"github.com/juev/nebula-mesh/internal/models"
)

func createOperatorKey(t *testing.T, srv *Server, username, role string) (string, string) {
	t.Helper()
	opID := uuid.New().String()
	if err := srv.store.CreateOperator(context.Background(), &models.Operator{
		ID:           opID,
		Username:     username,
		PasswordHash: "x",
	  …(+6889 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,240p' internal/api/authorization.go && sed -n '1,180p' internal/api/networks.go"`
```
package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request, msg string) bool {
	if actorIsAdmin(r.Context()) {
		return true
	}
	writeError(w, http.StatusForbidden, msg)
	return false
}

func (s *Server) canAccessNetwork(ctx context.Context, n *models.Network) (bool, error) {
	if actorIsAdmin(ctx) {
		return true, nil
	}
	if n == nil ||  …(+5834 more chars)
```
**→ shell:** `/bin/bash -lc 'git diff -- internal/api'`
**Codex:** The static pass caught no obvious import issues in the touched files. I’m running repository-neutral checks (`git diff --check`, file listing) since Go-specific verification is blocked by the missing toolchain.

**→ shell:** `/bin/bash -lc 'git diff --check'`
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M internal/api/audit.go
 M internal/api/firewall.go
 M internal/api/hosts.go
 M internal/api/mobile_bundle.go
 M internal/api/networks.go
 M internal/api/operators.go
?? internal/api/authorization.go
?? internal/api/authorization_test.go

```
**→ shell:** `/bin/bash -lc 'rg -n "API trusts|per-CA ownership is enforced only|handleGetAuditLog|handleListOperators|handleCreateHost|handleMobileBundle|handleGetFirewall|createNetworkRequest|loadAuthorized" inte  …(+9 more chars)`
```
internal/api/operators.go:65:func (s *Server) handleListOperators(w http.ResponseWriter, r *http.Request) {
internal/api/hosts.go:43:func (s *Server) handleCreateHost(w http.ResponseWriter, r *http.Request) {
internal/api/hosts.go:54:	network, ok := s.loadAuthorizedNetwork(w, r, req.NetworkID)
internal/api/hosts.go:157:		if _, ok := s.loadAuthorizedNetwork(w, r, filter.NetworkID); !ok {
internal/api/hosts.go:188:	host, ok := s.loadAuthorizedHost(w, r, id)
internal/api/hosts.go:198:	if _, ok := s  …(+1984 more chars)
```
**Codex:** Whitespace checks passed. I’m doing one more targeted scan for Go version compatibility and existing test expectations that may need adjustment after making operator endpoints admin-only.

**→ shell:** `/bin/bash -lc "sed -n '1,20p' go.mod"`
```
module github.com/juev/nebula-mesh

go 1.26.3

require (
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc
	github.com/coreos/go-oidc/v3 v3.18.0
	github.com/go-chi/chi/v5 v5.2.5
	github.com/google/uuid v1.6.0
	github.com/pquerna/otp v1.5.0
	github.com/prometheus/client_golang v1.23.2
	github.com/slackhq/nebula v1.10.3
	github.com/stretchr/testify v1.11.1
	golang.org/x/crypto v0.47.0
	golang.org/x/oauth2 v0.36.0
	golang.org/x/time v0.15.0
	gopkg.in/yaml.v3 v3.0.1
	modernc.org/sql  …(+15 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,230p' internal/api/operators_test.go"`
```
package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

func TestOperatorLifecycle_CreateListDisable(t *testing.T) {
	srv, st := newTestServer(t)

	body, _ := json.Marshal(map[string]string{
		"username": "bob", "password": "supersecret", "display_name": "Bob",
	})
	req := httptest.NewRequest("POST", "/api/v1/operators", bytes.NewBuffer(b  …(+5256 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"createUserWithAPIKey|createOperatorKey|map\\[string\\]any|/api/v1/operators|/api/v1/audit-log\" internal/api/*test.go"`
```
internal/api/authorization_test.go:18:func createOperatorKey(t *testing.T, srv *Server, username, role string) (string, string) {
internal/api/authorization_test.go:101:	aliceID, aliceKey := createOperatorKey(t, srv, "alice", "user")
internal/api/authorization_test.go:102:	bobID, bobKey := createOperatorKey(t, srv, "bob", "user")
internal/api/authorization_test.go:131:	body, _ := json.Marshal(map[string]any{
internal/api/authorization_test.go:153:	aliceID, aliceKey := createOperatorKey(t, srv, "  …(+3308 more chars)
```
**Codex:** One existing operator API-key test expected a newly-created non-admin key to read the operator list. Since operator listing is now deliberately admin-only, I’m adjusting that test to prove the key still authenticates on a normal protected endpoint instead.

**✎ files:** update `/work/internal/api/operators_test.go`

**Codex:** I’m doing a final grep for any remaining tests that assume non-admin access to admin-only endpoints.

**→ shell:** `/bin/bash -lc "rg -n \"keyResp\\.Key|userKey|nonAdminKey|Bearer \\+.*Key|createUserWithAPIKey|createOperatorKey\" internal/api/*test.go"`
```
internal/api/authorization_test.go:18:func createOperatorKey(t *testing.T, srv *Server, username, role string) (string, string) {
internal/api/authorization_test.go:101:	aliceID, aliceKey := createOperatorKey(t, srv, "alice", "user")
internal/api/authorization_test.go:102:	bobID, bobKey := createOperatorKey(t, srv, "bob", "user")
internal/api/authorization_test.go:153:	aliceID, aliceKey := createOperatorKey(t, srv, "alice", "user")
internal/api/authorization_test.go:154:	bobID, _ := createOperat  …(+1374 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '100,175p' internal/api/operators_test.go"`
```
	if err := json.NewDecoder(rec.Body).Decode(&keyResp); err != nil {
		t.Fatal(err)
	}
	if keyResp.Key == "" {
		t.Fatal("plaintext key is empty")
	}
	// The plain key length is 64 (32 bytes hex)
	if _, err := hex.DecodeString(keyResp.Key); err != nil {
		t.Errorf("key is not hex: %v", err)
	}

	// Use the new key to access a protected endpoint that does not require admin.
	req = httptest.NewRequest("GET", "/api/v1/networks", nil)
	req.Header.Set("Authorization", "Bearer "+keyResp.Key)
	rec = htt  …(+1878 more chars)
```
**→ shell:** `/bin/bash -lc 'git diff --check && git diff --stat'`
```
 internal/api/audit.go          |  4 +++
 internal/api/firewall.go       |  6 ++++
 internal/api/hosts.go          | 81 ++++++++++++++++++++++++------------------
 internal/api/mobile_bundle.go  | 11 ++----
 internal/api/networks.go       | 76 ++++++++++++++++++++++++++++++++++-----
 internal/api/operators.go      | 27 ++++++++++++--
 internal/api/operators_test.go |  6 ++--
 7 files changed, 154 insertions(+), 57 deletions(-)

```
**Codex:** Implemented the remediation in `internal/api`:

- Added centralized authorization helpers in [authorization.go](/work/internal/api/authorization.go).
- Scoped network, host, firewall, and mobile-bundle API access to admin or CA owner.
- Made audit log and operator management endpoints admin-only.
- Updated network creation to accept and validate `ca_id`, and host creation now inherits the network CA.
- Added regression coverage in [authorization_test.go](/work/internal/api/authorization_test.go).
- Adjusted an operator API-key test so non-admin keys authenticate against a non-admin endpoint.

Verification:
- `git diff --check` passed.
- I could not run `gofmt` or `go test ./internal/api` because this container does not have `gofmt` or `go` installed.


---
*tokens — input 1536055 (cached 1408896), output 13056, reasoning 2276*
