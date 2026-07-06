**Claude:** I'll start by reading the FINDING.txt file to understand the vulnerability.

**→ Read**(file_path=/work/FINDING.txt)
  ↳ *result:* 1	Project: forgekeep/nebula-mesh
2	Vulnerability type: Improper Authorization (CWE-285)
3	
4	Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):
5	
6	  internal/api/audit.go
7	    - lines 10-15   in: import (
8	
9	  internal/api/firewall.go
10	    - lines 29-34   in: var defaultFirewallRules = firewallRulesRequest{  …(+2379 more chars)
**Claude:** Let me explore the project structure and read the relevant files.

**→ Read**(file_path=/work/internal/api/hosts.go)
  ↳ *result:* 1	package api
2	
3	import (
4		"encoding/json"
5		"errors"
6		"fmt"
7		"net/http"
8		"strings"
9		"time"
10	
11		"github.com/go-chi/chi/v5"
12		"github.com/google/uuid"
13		"github.com/juev/nebula-mesh/internal/models"
14		"github.com/juev/nebula-mesh/internal/store"
15	)
16	
17	type createHostRequest struct {
18		NetworkID  string               `j  …(+19165 more chars)
**→ Read**(file_path=/work/internal/api/audit.go)
  ↳ *result:* 1	package api
2	
3	import (
4		"net/http"
5		"strconv"
6	
7		"github.com/juev/nebula-mesh/internal/store"
8	)
9	
10	const defaultAuditLimit = 100
11	
12	func (s *Server) handleGetAuditLog(w http.ResponseWriter, r *http.Request) {
13		filter := store.AuditFilter{
14			Action: r.URL.Query().Get("action"),
15			Limit:  defaultAuditLimit,
16		}
17		if   …(+667 more chars)
**→ Read**(file_path=/work/internal/api/firewall.go)
  ↳ *result:* 1	package api
2	
3	import (
4		"encoding/json"
5		"errors"
6		"fmt"
7		"net/http"
8	
9		"github.com/go-chi/chi/v5"
10		"github.com/juev/nebula-mesh/internal/store"
11	)
12	
13	type firewallRulesRequest struct {
14		Inbound  []firewallRule `json:"inbound"`
15		Outbound []firewallRule `json:"outbound"`
16	}
17	
18	type firewallRule struct {
19		Port   …(+2505 more chars)
**Claude:** Now let me read the remaining vulnerable files and understand the Web layer's authorization pattern.

**→ Read**(file_path=/work/internal/api/operators.go)
  ↳ *result:* 1	package api
2	
3	import (
4		"crypto/rand"
5		"crypto/sha256"
6		"encoding/hex"
7		"encoding/json"
8		"errors"
9		"net/http"
10		"strings"
11	
12		"github.com/go-chi/chi/v5"
13		"github.com/google/uuid"
14		"github.com/juev/nebula-mesh/internal/models"
15		"github.com/juev/nebula-mesh/internal/store"
16		"golang.org/x/crypto/bcrypt"
17	)
18	
19	t  …(+6146 more chars)
**→ Read**(file_path=/work/internal/api/networks.go)
**→ Read**(file_path=/work/internal/api/mobile_bundle.go)
  ↳ *result:* 1	package api
2	
3	import (
4		"context"
5		"errors"
6		"net/http"
7	
8		"github.com/go-chi/chi/v5"
9		"github.com/juev/nebula-mesh/internal/mobilebundle"
10		"github.com/juev/nebula-mesh/internal/models"
11		"github.com/juev/nebula-mesh/internal/pki"
12		"github.com/juev/nebula-mesh/internal/store"
13	)
14	
15	// handleMobileBundle implements POST  …(+2278 more chars)
  ↳ *result:* 1	package api
2	
3	import (
4		"errors"
5		"net/http"
6		"time"
7	
8		"github.com/go-chi/chi/v5"
9		"github.com/google/uuid"
10		"github.com/juev/nebula-mesh/internal/models"
11		"github.com/juev/nebula-mesh/internal/store"
12	)
13	
14	type createNetworkRequest struct {
15		Name  string   `json:"name"`
16		CIDRs []string `json:"cidrs"`
17	}
18	
19	  …(+1790 more chars)
**Claude:** The note at hosts.go:384 is the key clue. Let me understand the Web layer's per-CA authorization pattern that the API layer is missing.

**→ Bash**(command=ls internal/web/ 2>/dev/null && echo "---ROUTER---" && find . -name "*.go" | xargs grep -l "handleHostUpdate\|caForHost\|actorIsAdmin\|CanAc  …(+59 more chars))
  ↳ *result:* advanced.go
auto_provision_test.go
cas.go
cas_test.go
enforce_2fa_test.go
events.go
events_test.go
form_inline_errors_test.go
form_state.go
form_state_test.go
handlers.go
host_detail_test.go
host_edit_test.go
host_new_prefix_hint_test.go
host_new_segmented_test.go
host_role_reachability_test.go
mobile_bundle_test.go
networks_form_test.go
oidc.go
oi  …(+809 more chars)
**→ Read**(file_path=/work/internal/api/actor.go)
  ↳ *result:* 1	package api
2	
3	import (
4		"context"
5	
6		"github.com/juev/nebula-mesh/internal/models"
7	)
8	
9	// actorContextKey scopes the authenticated operator on the request context.
10	type actorContextKeyType struct{}
11	
12	var actorContextKey = actorContextKeyType{}
13	
14	// ActorOf returns the operator attached to the request context. On protecte  …(+1504 more chars)
**→ Read**(file_path=/work/internal/api/ca_for_host.go)
  ↳ *result:* 1	package api
2	
3	import (
4		"context"
5		"fmt"
6	
7		"github.com/juev/nebula-mesh/internal/models"
8		"github.com/juev/nebula-mesh/internal/pki"
9	)
10	
11	// caForHost returns the CAManager that should sign certificates for the
12	// given host. Requires host.CAID to be set; multi-CA resolution via caResolver.
13	// Hosts without a resolvable C  …(+360 more chars)
**Claude:** Now let me look at the Web layer to understand how per-CA ownership is enforced, which is the model the API should follow.

**→ Bash**(command=grep -rn "CanAccessCA\|OwnsCA\|allowedCA\|CAScope\|scopeCA\|AllowedCAs\|operatorCA\|OperatorCA\|caGate\|gateCA\|ca_id\|CAID" internal/web/*.  …(+32 more chars))
  ↳ *result:* internal/web/form_state.go:75:// CAID captures the operator's CA selection so the form can re-render
internal/web/form_state.go:84:	CAID      string
internal/web/form_state.go:92:		CAID:       r.FormValue("ca_id"),
internal/web/form_state.go:123:// to. admins see every network; users see only networks whose CAID
internal/web/form_state.go:124:// po  …(+1370 more chars)
**→ Read**(file_path=/work/internal/web/form_state.go, offset=100, limit=70)
  ↳ *result:* 100	func (w *Web) accessibleActiveCAs(ctx context.Context, op *models.Operator) ([]*models.CA, error) {
101		var (
102			cas []*models.CA
103			err error
104		)
105		if op.Role == "admin" {
106			cas, err = w.store.ListCAs(ctx)
107		} else {
108			cas, err = w.store.ListCAsByOwner(ctx, op.ID)
109		}
110		if err != nil {
111			return nil, err
112		}  …(+1865 more chars)
**Claude:** Let me look at how the web layer gates host edit/update by CA ownership.

**→ Bash**(command=grep -n "func (w \*Web)\|ListCAsByOwner\|containsCAID\|accessibleNetworks\|StatusForbidden\|StatusNotFound\|op.Role\|not authori\|access den  …(+43 more chars))
  ↳ *result:* 54:func (w *Web) requireAuth(next http.Handler) http.Handler {
72:func (w *Web) handleLoginPage(rw http.ResponseWriter, r *http.Request) {
80:func (w *Web) handleLogin(rw http.ResponseWriter, r *http.Request) {
111:func (w *Web) handleTOTPLoginPage(rw http.ResponseWriter, r *http.Request) {
119:func (w *Web) handleTOTPLogin(rw http.ResponseWriter,   …(+3726 more chars)
**Claude:** Let me read the canonical web authorization pattern in detail (handleHostUpdate, handleHostEdit, handleGenerateMobileBundle).

**→ Read**(file_path=/work/internal/web/handlers.go, offset=862, limit=90)
  ↳ *result:* 862	func (w *Web) handleHostEdit(rw http.ResponseWriter, r *http.Request) {
863		op := w.session.CurrentOperator(r)
864		if op == nil {
865			http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
866			return
867		}
868	
869		id := chi.URLParam(r, "id")
870		host, err := w.store.GetHost(r.Context(), id)
871		if errors.Is(err, store.ErrNotFound) {
  …(+2588 more chars)
**Claude:** Now let me look at the API router/middleware and the store interface to understand the full picture.

**→ Bash**(command=find internal/api -name "*.go" | grep -v _test | xargs ls; echo "---ROUTER---"; grep -rn "bearerAuth\|r.Get\|r.Post\|r.Put\|r.Patch\|r.Delet  …(+117 more chars))
  ↳ *result:* internal/api/actor.go
internal/api/audit.go
internal/api/ca_for_host.go
internal/api/cas.go
internal/api/enroll.go
internal/api/firewall.go
internal/api/helpers.go
internal/api/hosts.go
internal/api/metrics.go
internal/api/middleware.go
internal/api/mobile_bundle.go
internal/api/networks.go
internal/api/operators.go
internal/api/pop/nonce.go
intern  …(+4375 more chars)
**Claude:** Let me look at the API cas.go to see if any per-CA authorization pattern already exists in the API layer, plus the models.

**→ Read**(file_path=/work/internal/api/cas.go)
  ↳ *result:* 1	package api
2	
3	import (
4		"encoding/json"
5		"errors"
6		"fmt"
7		"net/http"
8		"time"
9	
10		"github.com/go-chi/chi/v5"
11		"github.com/google/uuid"
12		"github.com/juev/nebula-mesh/internal/keystore"
13		"github.com/juev/nebula-mesh/internal/models"
14		"github.com/juev/nebula-mesh/internal/pki"
15		"github.com/juev/nebula-mesh/internal/stor  …(+6749 more chars)
**Claude:** The API CA handlers already enforce `s.canAccessCA`. The vulnerability is that host/network/firewall/mobile-bundle/operator/audit handlers don't. Let me examine the models and the web layer's network handling to build faithful checks.

**→ Bash**(command=grep -rn "OwnerOperatorID\|type CA struct\|type Network struct\|type Host struct\|CAID\|NetworkID" internal/models/*.go | grep -v _test | he  …(+6 more chars))
  ↳ *result:* internal/models/network.go:5:type Network struct {
internal/models/network.go:9:	CAID      string    `json:"ca_id,omitempty"`
internal/models/ca.go:16:type CA struct {
internal/models/ca.go:19:	OwnerOperatorID      string    `json:"owner_operator_id"`
internal/models/host.go:130:type Host struct {
internal/models/host.go:132:	NetworkID           st  …(+119 more chars)
**→ Read**(file_path=/work/internal/web/handlers.go, offset=1157, limit=120)
  ↳ *result:* 1157	func (w *Web) handleNetworks(rw http.ResponseWriter, r *http.Request) {
1158		op := w.session.CurrentOperator(r)
1159		if op == nil {
1160			http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
1161			return
1162		}
1163		networks, err := w.store.ListNetworks(r.Context())
1164		if err != nil {
1165			w.logger.Error("list networks", "error",   …(+3826 more chars)
**Claude:** I now understand the model: per-CA ownership. The API CA handlers already enforce it via `canAccessCA`, but hosts/networks/firewall/mobile-bundle/operators/audit don't. Let me check existing tests to understand expected behavior and avoid breaking intended behavior.

**→ Bash**(command=ls internal/api/*_test.go && echo "---" && grep -rln "StatusForbidden\|owner\|Owner\|admin\|canAccess\|ListCAsByOwner" internal/api/*_test.g  …(+1 more chars))
  ↳ *result:* internal/api/agent_auth_constants_test.go
internal/api/ca_for_host_test.go
internal/api/cas_test.go
internal/api/helpers_test.go
internal/api/hosts_reenroll_test.go
internal/api/hosts_role_reachability_test.go
internal/api/hosts_rotate_cert_test.go
internal/api/hosts_token_ttl_test.go
internal/api/hosts_update_test.go
internal/api/lighthouse_test.g  …(+619 more chars)
**→ Read**(file_path=/work/internal/api/operators_admin_test.go)
  ↳ *result:* 1	package api
2	
3	import (
4		"bytes"
5		"context"
6		"crypto/sha256"
7		"encoding/hex"
8		"encoding/json"
9		"net/http"
10		"net/http/httptest"
11		"testing"
12	
13		"github.com/google/uuid"
14		"github.com/juev/nebula-mesh/internal/models"
15	)
16	
17	// createUserWithAPIKey seeds a non-admin operator + API key directly via the
18	// store, then  …(+1853 more chars)
**→ Bash**(command=grep -n "func Test\|StatusForbidden\|StatusOK\|StatusCreated\|admin\|Role\|withActor\|setActor\|actor\|seedOperator\|bearer\|token" internal  …(+33 more chars))
  ↳ *result:* 16:func TestOperatorLifecycle_CreateListDisable(t *testing.T) {
26:	if rec.Code != http.StatusCreated {
42:	if rec.Code != http.StatusOK {
73:func TestOperatorAPIKey_CreateAndUse(t *testing.T) {
83:	if rec.Code != http.StatusCreated {
96:	if rec.Code != http.StatusCreated {
116:	if rec.Code != http.StatusOK {
139:func TestDisableOperator_Invalidate  …(+256 more chars)
**Claude:** Let me read operators_test.go and the test server helper to understand how tests authenticate (admin vs user).

**→ Read**(file_path=/work/internal/api/operators_test.go)
**→ Read**(file_path=/work/internal/api/helpers_test.go)
  ↳ *result:* 1	package api
2	
3	import (
4		"bytes"
5		"context"
6		"encoding/hex"
7		"encoding/json"
8		"net/http"
9		"net/http/httptest"
10		"testing"
11	
12		"github.com/juev/nebula-mesh/internal/models"
13		"github.com/juev/nebula-mesh/internal/store"
14	)
15	
16	func TestOperatorLifecycle_CreateListDisable(t *testing.T) {
17		srv, st := newTestServer(t)
18  …(+6094 more chars)
  ↳ *result:* 1	package api
2	
3	import (
4		"net/netip"
5		"testing"
6	
7		"github.com/juev/nebula-mesh/internal/models"
8		"github.com/stretchr/testify/assert"
9		"github.com/stretchr/testify/require"
10	)
11	
12	func TestBuildHostPrefix(t *testing.T) {
13		tests := []struct {
14			name    string
15			hostIP  string
16			cidr    string
17			want    netip.Prefi  …(+3180 more chars)
**Claude:** Let me find `newTestServer` and `authRequest` to understand the default test actor.

**→ Bash**(command=grep -rn "func newTestServer\|func authRequest\|func authRequestFor\|Role:\|admin\|defaultCAID\|CreateCA\|CreateNetwork\|OwnerOperatorID" in  …(+36 more chars))
  ↳ *result:* internal/api/server_test.go:26:func newTestServer(t *testing.T) (*Server, *store.SQLiteStore) {
internal/api/server_test.go:51:		ID:           "test-admin",
internal/api/server_test.go:52:		Username:     "admin",
internal/api/server_test.go:54:		Role:         "admin",
internal/api/server_test.go:68:		ID:         "test-admin-key",
internal/api/serve  …(+252 more chars)
**→ Read**(file_path=/work/internal/api/server_test.go, offset=26, limit=110)
  ↳ *result:* 26	func newTestServer(t *testing.T) (*Server, *store.SQLiteStore) {
27		t.Helper()
28		s, err := store.NewSQLiteStore(":memory:")
29		if err != nil {
30			t.Fatal(err)
31		}
32		if err := s.Migrate(context.Background()); err != nil {
33			t.Fatal(err)
34		}
35		t.Cleanup(func() { s.Close() })
36	
37		ctx := context.Background()
38		logger := slog.N  …(+3073 more chars)
**Claude:** The default test actor is **admin**, so admin-bypass changes won't break existing tests. Let me check for any non-admin test expectations and how networks/hosts tests set up data.

**→ Bash**(command=grep -rn "createUserWithAPIKey\|\"user\"\|role.*user\|NonAdmin\|non-admin" internal/api/*_test.go; echo "===NETWORKS TEST==="; sed -n '475,5  …(+32 more chars))
  ↳ *result:* internal/api/cas_test.go:147:	keyA := makeOp("user")
internal/api/cas_test.go:148:	keyB := makeOp("user")
internal/api/cas_test.go:313:	// Create non-admin operator
internal/api/cas_test.go:318:		Username:     "non-admin",
internal/api/cas_test.go:320:		Role:         "user",
internal/api/operators_admin_test.go:17:// createUserWithAPIKey seeds a no  …(+1953 more chars)
**→ Bash**(command=grep -rn "func createNetwork\|func createHost\|CreateNetwork\|GetNetwork\|networkID\|NetworkID" internal/api/server_test.go | head; echo "==  …(+142 more chars))
  ↳ *result:* internal/api/server_test.go:247:func createNetwork(t *testing.T, srv *Server) string {
internal/api/server_test.go:266:		NetworkID: netID,
internal/api/server_test.go:286:		NetworkID: netID,
internal/api/server_test.go:327:		NetworkID: netID, Name: "to-delete", NebulaIPs: []string{"192.168.100.20"},
internal/api/server_test.go:364:		NetworkID: netI  …(+1930 more chars)
**Claude:** Let me check the web `handleHostCreate` and `handleHostDelete`/`handleHostBlock` to mirror their exact ownership semantics for create/delete/block.

**→ Read**(file_path=/work/internal/web/handlers.go, offset=645, limit=60)
  ↳ *result:* 645	func (w *Web) handleHostCreate(rw http.ResponseWriter, r *http.Request) {
646		if err := r.ParseForm(); err != nil {
647			http.Error(rw, "bad request", http.StatusBadRequest)
648			return
649		}
650		op := w.session.CurrentOperator(r)
651		if op == nil {
652			http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
653			return
654		}
655	
656	  …(+1935 more chars)
**Claude:** My understanding is complete and matches the web layer exactly. Now let me implement the fix. First, the shared authorization helpers:

**→ Write**(file_path=/work/internal/api/authz.go, content=package api

import (
	"context"
	"errors"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

  …(+2821 more chars))
  ↳ *result:* File created successfully at: /work/internal/api/authz.go (file state is current in your context — no need to Read it back)
**Claude:** Now let me fix the host handlers. Starting with `handleCreateHost`:

**→ Edit**(replace_all=false, file_path=/work/internal/api/hosts.go, old_string=	if req.Name == "" || len(req.NebulaIPs) == 0 || req.NetworkID == "" {
		writeError(w, http.StatusBadRequest, "name, nebula_ips, and network  …(+127 more chars), new_string=	if req.Name == "" || len(req.NebulaIPs) == 0 || req.NetworkID == "" {
		writeError(w, http.StatusBadRequest, "name, nebula_ips, and network  …(+871 more chars))
  ↳ *result:* The file /work/internal/api/hosts.go has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now `handleListHosts` — filter to accessible networks:

**→ Edit**(replace_all=false, file_path=/work/internal/api/hosts.go, old_string=	hosts, err := s.store.ListHosts(r.Context(), filter)
	if err != nil {
		s.logger.Error("list hosts", "error", err)
		writeError(w, http.Sta  …(+95 more chars), new_string=	hosts, err := s.store.ListHosts(r.Context(), filter)
	if err != nil {
		s.logger.Error("list hosts", "error", err)
		writeError(w, http.Sta  …(+591 more chars))
  ↳ *result:* The file /work/internal/api/hosts.go has been updated successfully. (file state is current in your context — no need to Read it back)
**→ Bash**(command=grep -rn "ListHosts(ctx context.Context" internal/store/*.go | head; grep -rn "ListHosts(" internal/store/store.go 2>/dev/null)
  ↳ *result:* internal/store/store.go:47:	ListHosts(ctx context.Context, filter HostFilter) ([]*models.Host, error)
internal/store/sqlite.go:657:func (s *SQLiteStore) ListHosts(ctx context.Context, filter HostFilter) ([]*models.Host, error) {
internal/store/store.go:47:	ListHosts(ctx context.Context, filter HostFilter) ([]*models.Host, error)
**Claude:** Good, `[]*models.Host` matches. Now `handleGetHost`:

**→ Edit**(replace_all=false, file_path=/work/internal/api/hosts.go, old_string=	if err != nil {
		s.logger.Error("get host", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get host")
		return
	  …(+476 more chars), new_string=	if err != nil {
		s.logger.Error("get host", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get host")
		return
	  …(+926 more chars))
  ↳ *result:* The file /work/internal/api/hosts.go has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now let me add the `requireHostAccess` helper to authz.go:

**→ Edit**(replace_all=false, file_path=/work/internal/api/authz.go, old_string=import (
	"context"
	"errors"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
), new_string=import (
	"context"
	"errors"
	"net/http"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

/  …(+198 more chars))
  ↳ *result:* The file /work/internal/api/authz.go has been updated successfully. (file state is current in your context — no need to Read it back)
**→ Edit**(replace_all=false, file_path=/work/internal/api/authz.go, old_string=// accessibleNetworkIDs returns the set of network IDs the actor may see., new_string=// requireHostAccess enforces that the request's actor may act on host. On
// denial or internal error it writes the HTTP response and retur  …(+1178 more chars))
  ↳ *result:* The file /work/internal/api/authz.go has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now `handleBlockHost` and `handleUnblockHost` — load host first to authorize:

**→ Edit**(replace_all=false, file_path=/work/internal/api/hosts.go, old_string=func (s *Server) handleBlockHost(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	host, err := s.store.BlockHostAndAd  …(+49 more chars), new_string=func (s *Server) handleBlockHost(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	existing, err := s.store.GetHost(r  …(+436 more chars))
  ↳ *result:* The file /work/internal/api/hosts.go has been updated successfully. (file state is current in your context — no need to Read it back)
**→ Edit**(replace_all=false, file_path=/work/internal/api/hosts.go, old_string=func (s *Server) handleUnblockHost(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	host, err := s.store.UnblockHostA  …(+38 more chars), new_string=func (s *Server) handleUnblockHost(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	existing, err := s.store.GetHost  …(+429 more chars))
  ↳ *result:* The file /work/internal/api/hosts.go has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now `handleRotateCert`, `mintEnrollmentTokenForHost`, and `handleUpdateHost` — each already loads the host:

**→ Edit**(replace_all=false, file_path=/work/internal/api/hosts.go, old_string=		s.logger.Error("get host for rotate-cert", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get host")
		return
	}  …(+14 more chars), new_string=		s.logger.Error("get host for rotate-cert", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get host")
		return
	}  …(+83 more chars))
  ↳ *result:* The file /work/internal/api/hosts.go has been updated successfully. (file state is current in your context — no need to Read it back)
**→ Edit**(replace_all=false, file_path=/work/internal/api/hosts.go, old_string=		s.logger.Error("get host", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get host")
		return
	}

	tokenStr := u  …(+18 more chars), new_string=		s.logger.Error("get host", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get host")
		return
	}
	if err := s.re  …(+87 more chars))
  ↳ *result:* The file /work/internal/api/hosts.go has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now `handleUpdateHost` — replace the comment that documents the missing check:

**→ Edit**(replace_all=false, file_path=/work/internal/api/hosts.go, old_string=	// API trusts the bearer token for authorisation; per-CA ownership is enforced only in the Web layer (handleHostUpdate). Matches handleCrea  …(+99 more chars), new_string=	// Enforce per-CA ownership: non-admin operators may only update hosts on a
	// network whose signing CA they own (mirrors the Web layer's   …(+152 more chars))
  ↳ *result:* The file /work/internal/api/hosts.go has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now `mobile_bundle.go`:

**→ Edit**(replace_all=false, file_path=/work/internal/api/mobile_bundle.go, old_string=		s.logger.Error("get host for mobile-bundle", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get host")
		return
  …(+33 more chars), new_string=		s.logger.Error("get host for mobile-bundle", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get host")
		return
  …(+102 more chars))
  ↳ *result:* The file /work/internal/api/mobile_bundle.go has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now the network handlers. Let me check `ListNetworks`/`GetNetwork` return types first:

**→ Bash**(command=grep -n "ListNetworks(ctx\|GetNetwork(ctx" internal/store/store.go)
  ↳ *result:* 39:	GetNetwork(ctx context.Context, id string) (*models.Network, error)
40:	ListNetworks(ctx context.Context) ([]*models.Network, error)
**→ Edit**(replace_all=false, file_path=/work/internal/api/networks.go, old_string=	networks, err := s.store.ListNetworks(r.Context())
	if err != nil {
		s.logger.Error("list networks", "error", err)
		writeError(w, http.St  …(+102 more chars), new_string=	networks, err := s.store.ListNetworks(r.Context())
	if err != nil {
		s.logger.Error("list networks", "error", err)
		writeError(w, http.St  …(+601 more chars))
  ↳ *result:* The file /work/internal/api/networks.go has been updated successfully. (file state is current in your context — no need to Read it back)
**→ Edit**(replace_all=false, file_path=/work/internal/api/networks.go, old_string=	if err != nil {
		s.logger.Error("get network", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get network")
		re  …(+46 more chars), new_string=	if err != nil {
		s.logger.Error("get network", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get network")
		re  …(+121 more chars))
  ↳ *result:* The file /work/internal/api/networks.go has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now `handleCreateNetwork` — add `ca_id` field and mirror the web's CA-ownership gating. First add the helper for accessible active CAs:

**→ Edit**(replace_all=false, file_path=/work/internal/api/authz.go, old_string=// accessibleNetworkIDs returns the set of network IDs the actor may see., new_string=// accessibleActiveCAs returns the active CAs the actor may attach a resource
// to: every active CA for admins, only owned active CAs for n  …(+835 more chars))
  ↳ *result:* The file /work/internal/api/authz.go has been updated successfully. (file state is current in your context — no need to Read it back)
**→ Edit**(replace_all=false, file_path=/work/internal/api/networks.go, old_string=type createNetworkRequest struct {
	Name  string   `json:"name"`
	CIDRs []string `json:"cidrs"`
}

func (s *Server) handleCreateNetwork(w ht  …(+542 more chars), new_string=type createNetworkRequest struct {
	Name  string   `json:"name"`
	CIDRs []string `json:"cidrs"`
	CAID  string   `json:"ca_id,omitempty"`
}

  …(+1600 more chars))
  ↳ *result:* The file /work/internal/api/networks.go has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now `firewall.go`. Let me check existing firewall tests first to avoid breaking behavior:

**→ Bash**(command=grep -rln "firewall\|Firewall" internal/api/*_test.go; echo "==="; grep -rn "firewall\|Firewall\|getFirewallRules" internal/api/*_test.go 2>  …(+16 more chars))
  ↳ *result:* internal/api/server_test.go
===
internal/api/server_test.go:596:func TestFirewallRules_DefaultAndCRUD(t *testing.T) {
internal/api/server_test.go:601:	req := httptest.NewRequest("GET", "/api/v1/networks/"+netID+"/firewall", nil)
internal/api/server_test.go:609:	var rules firewallRulesRequest
internal/api/server_test.go:619:	req = httptest.NewReques  …(+747 more chars)
**→ Read**(file_path=/work/internal/api/server_test.go, offset=671, limit=40)
  ↳ *result:* 671	func TestFirewallRules_CorruptedJSON(t *testing.T) {
672		srv, s := newTestServer(t)
673		netID := createNetwork(t, srv)
674	
675		// Write corrupted JSON directly into DB
676		if err := s.SetNetworkConfig(context.Background(), netID, "firewall", `{invalid json}`); err != nil {
677			t.Fatal(err)
678		}
679	
680		req := httptest.NewRequest("GET  …(+1052 more chars)
**Claude:** All firewall/audit tests use admin auth (bypass). Let me add a by-ID network authorization helper and apply it to the firewall handlers:

**→ Edit**(replace_all=false, file_path=/work/internal/api/authz.go, old_string=// accessibleActiveCAs returns the active CAs the actor may attach a resource, new_string=// requireNetworkAccessByID loads the network identified by networkID and
// enforces access. Writes 404 if it does not exist, 403 if the ac  …(+685 more chars))
  ↳ *result:* The file /work/internal/api/authz.go has been updated successfully. (file state is current in your context — no need to Read it back)
**→ Edit**(replace_all=false, file_path=/work/internal/api/firewall.go, old_string=func (s *Server) handleGetFirewall(w http.ResponseWriter, r *http.Request) {
	networkID := chi.URLParam(r, "id")

	rules, err := s.getFirewa  …(+21 more chars), new_string=func (s *Server) handleGetFirewall(w http.ResponseWriter, r *http.Request) {
	networkID := chi.URLParam(r, "id")

	if err := s.requireNetwor  …(+103 more chars))
  ↳ *result:* The file /work/internal/api/firewall.go has been updated successfully. (file state is current in your context — no need to Read it back)
**→ Edit**(replace_all=false, file_path=/work/internal/api/firewall.go, old_string=func (s *Server) handleUpdateFirewall(w http.ResponseWriter, r *http.Request) {
	networkID := chi.URLParam(r, "id")

	var req firewallRulesR  …(+6 more chars), new_string=func (s *Server) handleUpdateFirewall(w http.ResponseWriter, r *http.Request) {
	networkID := chi.URLParam(r, "id")

	if err := s.requireNet  …(+88 more chars))
  ↳ *result:* The file /work/internal/api/firewall.go has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now `audit.go` — the audit log is global across all CAs, so gate it admin-only:

**→ Edit**(replace_all=false, file_path=/work/internal/api/audit.go, old_string=func (s *Server) handleGetAuditLog(w http.ResponseWriter, r *http.Request) {
	filter := store.AuditFilter{, new_string=func (s *Server) handleGetAuditLog(w http.ResponseWriter, r *http.Request) {
	// The audit log spans every operator and CA and is not scoped  …(+238 more chars))
  ↳ *result:* The file /work/internal/api/audit.go has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now `operators.go` — operator management is admin-only (mirroring the existing `handleCreateOperator` gate). Let me gate the remaining management endpoints:

**→ Edit**(replace_all=false, file_path=/work/internal/api/operators.go, old_string=func (s *Server) handleListOperators(w http.ResponseWriter, r *http.Request) {
	ops, err := s.store.ListOperators(r.Context()), new_string=func (s *Server) handleListOperators(w http.ResponseWriter, r *http.Request) {
	if !actorIsAdmin(r.Context()) {
		writeError(w, http.StatusF  …(+116 more chars))
  ↳ *result:* The file /work/internal/api/operators.go has been updated successfully. (file state is current in your context — no need to Read it back)
**→ Edit**(replace_all=false, file_path=/work/internal/api/operators.go, old_string=func (s *Server) handleDisableOperator(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.store.DisableOper  …(+35 more chars), new_string=func (s *Server) handleDisableOperator(w http.ResponseWriter, r *http.Request) {
	if !actorIsAdmin(r.Context()) {
		writeError(w, http.Statu  …(+165 more chars))
  ↳ *result:* The file /work/internal/api/operators.go has been updated successfully. (file state is current in your context — no need to Read it back)
**→ Edit**(replace_all=false, file_path=/work/internal/api/operators.go, old_string=func (s *Server) handleEnableOperator(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.store.EnableOperat  …(+33 more chars), new_string=func (s *Server) handleEnableOperator(w http.ResponseWriter, r *http.Request) {
	if !actorIsAdmin(r.Context()) {
		writeError(w, http.Status  …(+163 more chars))
  ↳ *result:* The file /work/internal/api/operators.go has been updated successfully. (file state is current in your context — no need to Read it back)
**→ Edit**(replace_all=false, file_path=/work/internal/api/operators.go, old_string=func (s *Server) handleCreateOperatorAPIKey(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := s.store.Get  …(+39 more chars), new_string=func (s *Server) handleCreateOperatorAPIKey(w http.ResponseWriter, r *http.Request) {
	if !actorIsAdmin(r.Context()) {
		writeError(w, http.  …(+169 more chars))
  ↳ *result:* The file /work/internal/api/operators.go has been updated successfully. (file state is current in your context — no need to Read it back)
**→ Edit**(replace_all=false, file_path=/work/internal/api/operators.go, old_string=func (s *Server) handleRevokeOperatorAPIKey(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	kid := chi.URLParam(r, "  …(+5 more chars), new_string=func (s *Server) handleRevokeOperatorAPIKey(w http.ResponseWriter, r *http.Request) {
	if !actorIsAdmin(r.Context()) {
		writeError(w, http.  …(+135 more chars))
  ↳ *result:* The file /work/internal/api/operators.go has been updated successfully. (file state is current in your context — no need to Read it back)
**→ Edit**(replace_all=false, file_path=/work/internal/api/operators.go, old_string=func (s *Server) handleListOperatorAPIKeys(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	keys, err := s.store.List  …(+32 more chars), new_string=func (s *Server) handleListOperatorAPIKeys(w http.ResponseWriter, r *http.Request) {
	if !actorIsAdmin(r.Context()) {
		writeError(w, http.S  …(+162 more chars))
  ↳ *result:* The file /work/internal/api/operators.go has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now let me build and run the API tests to verify nothing breaks:

**→ Bash**(command=go build ./... 2>&1 | head -30)
  ↳ *result:* go: downloading github.com/slackhq/nebula v1.10.3
go: downloading golang.org/x/crypto v0.47.0
go: downloading github.com/go-chi/chi/v5 v5.2.5
go: downloading github.com/google/uuid v1.6.0
go: downloading github.com/prometheus/client_golang v1.23.2
go: downloading gopkg.in/yaml.v3 v3.0.1
go: downloading golang.org/x/time v0.15.0
go: downloading mode  …(+3105 more chars)
**Claude:** Dependencies need downloading but egress is blocked. Let me check for a vendor dir or module cache:

**→ Bash**(command=ls vendor 2>/dev/null && echo "HAS VENDOR"; ls $(go env GOMODCACHE) 2>/dev/null | head; echo "---GOFLAGS---"; go env GOFLAGS GOMODCACHE)
  ↳ *result:* cache
---GOFLAGS---

/go/pkg/mod
**→ Bash**(command=ls /go/pkg/mod/github.com 2>/dev/null | head; echo "---chi---"; ls /go/pkg/mod/github.com/go-chi 2>/dev/null; echo "---cache download---"; l  …(+47 more chars))
  ↳ *result:* ---chi---
---cache download---
github.com
golang.org
gopkg.in
modernc.org
**→ Bash**(command=GOFLAGS=-mod=mod go mod download 2>&1 | head -5; echo "exit: $?"; ls /go/pkg/mod/github.com/go-chi 2>/dev/null)
  ↳ *result:* Exit code 2
go: filippo.io/bigmod@v0.1.0: Get "https://proxy.golang.org/filippo.io/bigmod/@v/v0.1.0.mod": blocked by egress allowlist
exit: 0
**→ Bash**(command=GOPROXY=off GOFLAGS=-mod=mod go build ./internal/api/ 2>&1 | head -20; echo "exit: ${PIPESTATUS[0]}")
  ↳ *result:* go: downloading github.com/go-chi/chi/v5 v5.2.5
go: downloading github.com/google/uuid v1.6.0
go: downloading github.com/prometheus/client_golang v1.23.2
go: downloading github.com/slackhq/nebula v1.10.3
go: downloading golang.org/x/crypto v0.47.0
go: downloading modernc.org/sqlite v1.48.0
go: downloading golang.org/x/time v0.15.0
internal/api/cas.  …(+671 more chars)
**→ Bash**(command=find /go/pkg/mod/cache/download -name "*.zip" 2>/dev/null | head -20; echo "---count---"; find /go/pkg/mod/cache/download -name "*.zip" 2>/d  …(+15 more chars))
  ↳ *result:* ---count---
0
**→ Bash**(command=find /go/pkg/mod/cache/download -type f 2>/dev/null | head -20; echo "total files:"; find /go/pkg/mod/cache/download -type f 2>/dev/null | w  …(+4 more chars))
  ↳ *result:* /go/pkg/mod/cache/download/modernc.org/sqlite/@v/v1.48.0.lock
/go/pkg/mod/cache/download/gopkg.in/yaml.v3/@v/v3.0.1.lock
/go/pkg/mod/cache/download/github.com/google/uuid/@v/v1.6.0.lock
/go/pkg/mod/cache/download/github.com/prometheus/client_golang/@v/v1.23.2.lock
/go/pkg/mod/cache/download/github.com/slackhq/nebula/@v/v1.10.3.lock
/go/pkg/mod/cach  …(+491 more chars)
**Claude:** Dependencies aren't available offline and egress is blocked, so a full compile isn't possible. Let me at least verify syntax with `gofmt` (no deps needed) on all edited files:

**→ Bash**(command=gofmt -l -e internal/api/authz.go internal/api/hosts.go internal/api/networks.go internal/api/firewall.go internal/api/audit.go internal/api  …(+65 more chars))
  ↳ *result:* internal/api/operators.go
exit: 0
**Claude:** `gofmt` reports `operators.go` needs reformatting. Let me see what:

**→ Bash**(command=gofmt -d internal/api/operators.go 2>&1 | head -40)
  ↳ *result:* diff internal/api/operators.go.orig internal/api/operators.go
--- internal/api/operators.go.orig
+++ internal/api/operators.go
@@ -123,8 +123,8 @@
 }
 
 type createAPIKeyResponse struct {
-	Key   string                  `json:"key"`   // shown once
-	Entry *models.OperatorAPIKey  `json:"entry"`
+	Key   string                 `json:"key"` // shown o  …(+141 more chars)
**Claude:** The `operators.go` formatting diff is pre-existing (the `createAPIKeyResponse` struct alignment), unrelated to my edits — I'll leave it untouched to keep the diff focused. Since I can't compile, let me carefully re-read the modified hosts.go to verify correctness:

**→ Read**(file_path=/work/internal/api/hosts.go, offset=43, limit=100)
  ↳ *result:* 43	func (s *Server) handleCreateHost(w http.ResponseWriter, r *http.Request) {
44		var req createHostRequest
45		if err := decodeJSONStrict(r, &req); err != nil {
46			writeError(w, http.StatusBadRequest, err.Error())
47			return
48		}
49	
50		if req.Name == "" || len(req.NebulaIPs) == 0 || req.NetworkID == "" {
51			writeError(w, http.StatusBadReq  …(+3073 more chars)
**Claude:** Let me re-read the full modified networks.go and the key parts of authz.go to verify correctness:

**→ Read**(file_path=/work/internal/api/networks.go)
  ↳ *result:* 1	package api
2	
3	import (
4		"errors"
5		"net/http"
6		"time"
7	
8		"github.com/go-chi/chi/v5"
9		"github.com/google/uuid"
10		"github.com/juev/nebula-mesh/internal/models"
11		"github.com/juev/nebula-mesh/internal/store"
12	)
13	
14	type createNetworkRequest struct {
15		Name  string   `json:"name"`
16		CIDRs []string `json:"cidrs"`
17		CAID  st  …(+3603 more chars)
**Claude:** Let me check for any name collisions in the `api` package (e.g., a pre-existing `containsCAID`, `accessibleActiveCAs`, etc.):

**→ Bash**(command=grep -rn "func containsCAID\|func.*accessibleActiveCAs\|func.*accessibleNetworkIDs\|func.*networkOwned\|func.*hostOwned\|func.*requireHostAc  …(+81 more chars))
  ↳ *result:* internal/api/authz.go:12:// errForbidden is a sentinel returned by the require* authorization helpers so
internal/api/authz.go:14:var errForbidden = errors.New("forbidden")
internal/api/authz.go:32:func (s *Server) networkOwned(ctx context.Context, n *models.Network) (bool, error) {
internal/api/authz.go:52:func (s *Server) hostOwned(ctx context.Co  …(+887 more chars)
**Claude:** No collisions. Let me verify all the store methods I call exist in the store interface:

**→ Bash**(command=grep -n "GetNetwork(\|ListNetworks(\|GetCA(\|ListCAs(\|ListCAsByOwner(\|GetHost(\|GetOperator(" internal/store/store.go)
  ↳ *result:* 28:	GetCA(ctx context.Context, id string) (*models.CA, error)
30:	ListCAs(ctx context.Context) ([]*models.CA, error)
31:	ListCAsByOwner(ctx context.Context, ownerID string) ([]*models.CA, error)
39:	GetNetwork(ctx context.Context, id string) (*models.Network, error)
40:	ListNetworks(ctx context.Context) ([]*models.Network, error)
45:	GetHost(ctx co  …(+122 more chars)
**Claude:** All store methods exist. Let me verify `models.CAStatusActive` exists:

**→ Bash**(command=grep -rn "CAStatusActive" internal/models/*.go)
  ↳ *result:* internal/models/ca.go:9:	CAStatusActive  CAStatus = "active"
**Claude:** Let me review the remaining host handler edits (list, delete, block, unblock):

**→ Read**(file_path=/work/internal/api/hosts.go, offset=162, limit=110)
  ↳ *result:* 162	func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
163		filter := store.HostFilter{
164			NetworkID: r.URL.Query().Get("network_id"),
165			Group:     r.URL.Query().Get("group"),
166			Status:    models.HostStatus(r.URL.Query().Get("status")),
167			Limit:     1000,
168		}
169	
170		hosts, err := s.store.ListHosts(r.Cont  …(+3349 more chars)
**Claude:** Let me check the other test files for any non-admin expectations on endpoints I changed:

**→ Bash**(command=grep -rn "Bearer\|authRequest\|makeOp\|createUser\|\"user\"\|Role:" internal/api/networks_test.go internal/api/mobile_bundle_test.go interna  …(+161 more chars))
  ↳ *result:* internal/api/networks_test.go:22:	authRequest(req)
internal/api/networks_test.go:51:	authRequest(req)
internal/api/networks_test.go:85:	authRequest(req)
internal/api/networks_test.go:102:	authRequest(req)
internal/api/networks_test.go:122:	authRequest(req)
internal/api/hosts_reenroll_test.go:25:	authRequest(req)
internal/api/hosts_reenroll_test.go:  …(+2002 more chars)
**Claude:** All those tests use admin auth (`authRequest`), bypassing the new checks. Let me check the two non-admin sections in cas_test.go to ensure they don't hit my changed handlers expecting success:

**→ Bash**(command=sed -n '300,360p' internal/api/cas_test.go)
  ↳ *result:* 	req := httptest.NewRequest("POST", "/api/v1/cas", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+adminKey)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create CA = %d", rec.Code)
	}

	var ca caResponse
	if err := json.NewDecoder(rec.Body).Decode(&ca); err != nil {
		t.F  …(+1620 more chars)
**Claude:** Let me do a final review of the complete authz.go to verify syntax and logic:

**→ Read**(file_path=/work/internal/api/authz.go)
  ↳ *result:* 1	package api
2	
3	import (
4		"context"
5		"errors"
6		"net/http"
7	
8		"github.com/juev/nebula-mesh/internal/models"
9		"github.com/juev/nebula-mesh/internal/store"
10	)
11	
12	// errForbidden is a sentinel returned by the require* authorization helpers so
13	// callers can return immediately after the helper has written the response.
14	var errF  …(+6383 more chars)
**Claude:** All edits are syntactically clean (gofmt flagged only a pre-existing alignment issue in `operators.go`'s `createAPIKeyResponse` struct, unrelated to my changes). Let me do a final check that the old vulnerable comment is gone and confirm the full diff:

**→ Bash**(command=grep -rn "API trusts the bearer token" internal/ || echo "OLD COMMENT REMOVED"; echo "=== DIFF STAT ==="; git diff --stat)
  ↳ *result:* OLD COMMENT REMOVED
=== DIFF STAT ===
 internal/api/audit.go         |  7 ++++
 internal/api/firewall.go      |  8 ++++
 internal/api/hosts.go         | 98 ++++++++++++++++++++++++++++++++++++++++++-
 internal/api/mobile_bundle.go |  3 ++
 internal/api/networks.go      | 51 ++++++++++++++++++++++
 internal/api/operators.go     | 24 +++++++++++
 6 f  …(+46 more chars)
**Claude:** The vulnerable comment is gone. The new `internal/api/authz.go` is an untracked file (not shown in diff --stat). Let me confirm the full set of changes:

**→ Bash**(command=git status --short)
  ↳ *result:*  M internal/api/audit.go
 M internal/api/firewall.go
 M internal/api/hosts.go
 M internal/api/mobile_bundle.go
 M internal/api/networks.go
 M internal/api/operators.go
?? internal/api/authz.go
**Claude:** I've remediated the **Improper Authorization (CWE-285)** vulnerability described in `FINDING.txt`.

## The vulnerability

`forgekeep/nebula-mesh` uses a **per-CA ownership** model: each operator owns CAs, and resources (networks → hosts → firewall rules → mobile bundles) are scoped to a CA's owner. The **Web layer** enforced this (e.g. `handleHostUpdate` resolves host → network → CA → checks `ca.OwnerOperatorID == op.ID`), and the **API's own CA handlers** already enforced it via `canAccessCA`. But the API's host/network/firewall/mobile-bundle handlers "trusted the bearer token alone" (as the comment at `hosts.go:384` admitted) — so any authenticated operator could read or mutate *any* tenant's resources. Operator-management and audit-log endpoints were also ungated for non-admins.

## The fix

New file **`internal/api/authz.go`** with helpers mirroring the Web layer's exact semantics (admins keep blanket access; non-admins act only on resources tied to a CA they own; legacy CA-less rows are denied to non-admins):
- `networkOwned` / `hostOwned` — resolve ownership through network → CA → owner
- `requireHostAccess` / `requireNetworkAccess` / `requireNetworkAccessByID` — enforce + write the response
- `accessibleNetworkIDs` / `accessibleActiveCAs` / `containsCAID` — for list filtering and create-time CA gating

Applied to every location in the finding:
- **hosts.go** — create (authorize target network), list (filter to accessible), get/delete/block/unblock/rotate-cert/reenroll/regenerate-token/update (ownership check after load; delete/block/unblock now load the host first to authorize)
- **networks.go** — create (gate by accessible active CA, mirroring the Web's `ca_id` selection; added optional `ca_id` field), list (filter), get (ownership check)
- **firewall.go** — get & update (network ownership check by ID)
- **mobile_bundle.go** — ownership check after host load
- **audit.go** — admin-only (the global audit log has no per-CA scoping)
- **operators.go** — admin-only gate on list/disable/enable/create-API-key/revoke-API-key/list-API-keys (matching the existing `handleCreateOperator` gate)

Behavior is preserved for admins and for legitimate owners; only cross-tenant/unauthorized access is now rejected (403, or 404 for not-found).

## Verification note

I could not run `go build`/tests: the sandbox blocks egress and the module cache has no extracted dependencies (only `.lock` files). I verified manually instead — `gofmt` is clean on all changed files (the one flagged item in `operators.go` is a pre-existing struct-alignment quirk I left untouched), all referenced store methods / model fields / package symbols exist, there are no name collisions or unused imports, and existing tests authenticate as admin (which bypasses the new checks) or already assert 403 on unchanged endpoints — so they should continue to pass.


---
**Final (success):** I've remediated the **Improper Authorization (CWE-285)** vulnerability described in `FINDING.txt`.

## The vulnerability

`forgekeep/nebula-mesh` uses a **per-CA ownership** model: each operator owns CAs, and resources (networks → hosts → firewall rules → mobile bundles) are scoped to a CA's owner. The **Web layer** enforced this (e.g. `handleHostUpdate` resolves host → network → CA → checks `ca.OwnerOperatorID == op.ID`), and the **API's own CA handlers** already enforced it via `canAccessCA`. But the API's host/network/firewall/mobile-bundle handlers "trusted the bearer token alone" (as the comment at `hosts.go:384` admitted) — so any authenticated operator could read or mutate *any* tenant's resources. Operator-management and audit-log endpoints were also ungated for non-admins.

## The fix

New file **`internal/api/authz.go`** with helpers mirroring the Web layer's exact semantics (admins keep blanket access; non-admins act only on resources tied to a CA they own; legacy CA-less rows are denied to non-admins):
- `networkOwned` / `hostOwned` — resolve ownership through network → CA → owner
- `requireHostAccess` / `requireNetworkAccess` / `requireNetworkAccessByID` — enforce + write the response
- `accessibleNetworkIDs` / `accessibleActiveCAs` / `containsCAID` — for list filtering and create-time CA gating

Applied to every location in the finding:
- **hosts.go** — create (authorize target network), list (filter to accessible), get/delete/block/unblock/rotate-cert/reenroll/regenerate-token/update (ownership check after load; delete/block/unblock now load the host first to authorize)
- **networks.go** — create (gate by accessible active CA, mirroring the Web's `ca_id` selection; added optional `ca_id` field), list (filter), get (ownership check)
- **firewall.go** — get & update (network ownership check by ID)
- **mobile_bundle.go** — ownership check after host load
- **audit.go** — admin-only (the global audit log has no per-CA scoping)
- **operators.go** — admin-only gate on list/disable/enable/create-API-key/revoke-API-key/list-API-keys (matching the existing `handleCreateOperator` gate)

Behavior is preserved for admins and for legitimate owners; only cross-tenant/unauthorized access is now rejected (403, or 404 for not-found).

## Verification note

I could not run `go build`/tests: the sandbox blocks egress and the module cache has no extracted dependencies (only `.lock` files). I verified manually instead — `gofmt` is clean on all changed files (the one flagged item in `operators.go` is a pre-existing struct-alignment quirk I left untouched), all referenced store methods / model fields / package symbols exist, there are no name collisions or unused imports, and existing tests authenticate as admin (which bypasses the new checks) or already assert 403 on unchanged endpoints — so they should continue to pass.

*turns 79 · cost $5.256*
