**Claude:** I'll start by reading the FINDING.txt file to understand the vulnerability.

**→ Read**(file_path=/work/FINDING.txt)
  ↳ *result:* 1	Project: nhost/nhost
2	Vulnerability type: Missing Authentication (CWE-306)
3	
4	Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):
5	
6	  cli/clienv/filesystem.go
7	    - lines 71-76   in: func (p PathStructure) DockerCompose() string {
8	
9	  cli/cmd/configserver/configserver.go
10	    - lines 3-17   in: packa  …(+2802 more chars)
**Claude:** The finding spans many files but centers on a config server. Let me examine the core files.

**→ Read**(file_path=/work/cli/cmd/configserver/configserver.go)
  ↳ *result:* 1	package configserver
2	
3	import (
4		"context"
5		"fmt"
6		"os"
7	
8		"github.com/99designs/gqlgen/graphql"
9		"github.com/docker/docker/client"
10		"github.com/gin-gonic/gin"
11		"github.com/google/uuid"
12		"github.com/nhost/be/services/mimir/graph"
13		"github.com/nhost/nhost/cli/cmd/configserver/logsapi"
14		cors "github.com/rs/cors/wrapper/  …(+4997 more chars)
**→ Read**(file_path=/work/cli/cmd/configserver/local.go)
  ↳ *result:* 1	package configserver
2	
3	import (
4		"context"
5		"encoding/json"
6		"errors"
7		"fmt"
8		"os"
9		"strings"
10	
11		"github.com/nhost/be/services/mimir/graph"
12		"github.com/nhost/be/services/mimir/model"
13		"github.com/nhost/nhost/cli/project/env"
14		"github.com/pelletier/go-toml/v2"
15		"github.com/sirupsen/logrus"
16	)
17	
18	const zeroUUI  …(+5993 more chars)
**→ Read**(file_path=/work/internal/lib/oapi/middleware/cors.go)
  ↳ *result:* 1	package middleware
2	
3	import (
4		"net/http"
5		"slices"
6		"strings"
7	
8		"github.com/gin-gonic/gin"
9	)
10	
11	// CORSOptions configures the CORS middleware behavior.
12	//
13	// The middleware supports three strategies for handling Access-Control-Allow-Headers:
14	//   - nil (default): Reflects the Access-Control-Request-Headers from the cl  …(+4456 more chars)
**→ Read**(file_path=/work/cli/dockercompose/configserver.go)
  ↳ *result:* 1	package dockercompose
2	
3	import (
4		"fmt"
5		"path/filepath"
6		"slices"
7	)
8	
9	func configserver( //nolint: funlen
10		image,
11		rootPath,
12		nhostPath,
13		projectName string,
14		useTLS bool,
15		runServices ...*RunService,
16	) (*Service, error) {
17		bindings := make([]Volume, 0, len(runServices))
18		extraArgs := make([]string, len(r  …(+2469 more chars)
**Claude:** The vulnerability centers on CORS. Let me look at how auth/storage configure CORS and how the dashboard origin is derived.

**→ Read**(file_path=/work/services/auth/go/cmd/serve.go, offset=1340, limit=60)
  ↳ *result:* 1340		*controller.JWTGetter,
1341		*oidc.IDTokenValidatorProviders,
1342		error,
1343	) {
1344		emailer, templates, err := getEmailer(cmd, logger)
1345		if err != nil {
1346			return nil, nil, nil, nil, fmt.Errorf("problem creating emailer: %w", err)
1347		}
1348	
1349		sms, err := getSMS(cmd, templates, db, logger)
1350		if err != nil {
1351			ret  …(+1494 more chars)
**→ Read**(file_path=/work/services/storage/cmd/serve.go, offset=40, limit=60)
  ↳ *result:* 40		flagHasuraMetadata           = "hasura-metadata"
41		flagHasuraAdminSecret        = "hasura-graphql-admin-secret" //nolint: gosec
42		flagS3Endpoint               = "s3-endpoint"
43		flagS3AccessKey              = "s3-access-key"
44		flagS3SecretKey              = "s3-secret-key" //nolint: gosec
45		flagS3Region                 = "s3-region"
46  …(+2262 more chars)
**Claude:** The picture is becoming clear: the configserver serves sensitive config/secrets with no auth, and uses `cors.Default()` (rs/cors) which allows **all** origins. Let me examine the remaining files to understand the dashboard origin and how CORS is intended to be scoped.

**→ Read**(file_path=/work/cli/dockercompose/compose.go, offset=300, limit=120)
  ↳ *result:* 300		return &Service{
301			Image:      "minio/minio:RELEASE.2025-02-28T09-55-16Z",
302			DependsOn:  nil,
303			EntryPoint: []string{"/bin/sh"},
304			Command: []string{
305				"-c", "mkdir -p /data/nhost && /usr/bin/minio server --address :9000 /data",
306			},
307			Environment: map[string]string{
308				"MINIO_ROOT_PASSWORD": "minioaccesskey123  …(+3283 more chars)
**→ Read**(file_path=/work/cli/dockercompose/compose_cloud.go)
  ↳ *result:* 1	package dockercompose
2	
3	import (
4		"fmt"
5	
6		"github.com/nhost/be/services/mimir/model"
7	)
8	
9	const (
10		schemeHTTP  = "http"
11		schemeHTTPS = "https"
12	)
13	
14	func dashboardCloud(
15		cfg *model.ConfigConfig,
16		subdomain string,
17		cloudSubdomain string,
18		cloudRegion string,
19		cloudAdminSecret string,
20		httpPort uint,
21	  …(+4693 more chars)
**Claude:** Now let me read the remaining referenced files to understand the full call chain that would need the dashboard origin threaded through.

**→ Read**(file_path=/work/cli/dockercompose/compose.go, offset=560, limit=200)
  ↳ *result:* 560	) bool {
561		if jwtSecret != nil && jwtSecret.Type != nil && *jwtSecret.Type != "" && jwtSecret.Key != nil &&
562			*jwtSecret.Key != "" {
563			return *jwtSecret.Type == "HS256" || *jwtSecret.Type == "HS384" ||
564				*jwtSecret.Type == "HS512" || *jwtSecret.Type == "RS256" ||
565				*jwtSecret.Type == "RS384" || *jwtSecret.Type == "RS512"
56  …(+4922 more chars)
**Claude:** Let me find the `URL` helper and look at the dev/up.go and cloud.go call sites plus filesystem.go.

**→ Bash**(command=grep -rn "func URL\|func WebsocketURL\|func traefikHostMatch\|func extraHosts" cli/dockercompose/)
  ↳ *result:* cli/dockercompose/auth.go:10:func traefikHostMatch(name string) string {
cli/dockercompose/compose.go:115:func extraHosts(subdomain string) []string {
cli/dockercompose/url.go:8:func URL(host, service string, port uint, useTLS bool) string {
cli/dockercompose/url.go:24:func WebsocketURL(host, service string, port uint, useTLS bool) string {
**→ Read**(file_path=/work/cli/clienv/filesystem.go, offset=60, limit=25)
  ↳ *result:* 60	}
61	
62	func (p PathStructure) HasuraConfig() string {
63		return filepath.Join(p.nhostFolder, "config.yaml")
64	}
65	
66	func (p PathStructure) ProjectFile() string {
67		return filepath.Join(p.dotNhostFolder, "project.json")
68	}
69	
70	func (p PathStructure) DockerCompose() string {
71		return filepath.Join(p.dotNhostFolder, "docker-compose.  …(+277 more chars)
**→ Read**(file_path=/work/cli/dockercompose/url.go)
  ↳ *result:* 1	package dockercompose
2	
3	import (
4		"fmt"
5		"strings"
6	)
7	
8	func URL(host, service string, port uint, useTLS bool) string {
9		if useTLS && port == 443 {
10			return fmt.Sprintf("https://%s.%s.local.nhost.run", host, service)
11		} else if !useTLS && port == 80 {
12			return fmt.Sprintf("http://%s.%s.local.nhost.run", host, service)
13		}
  …(+428 more chars)
**→ Read**(file_path=/work/cli/dockercompose/auth.go, offset=1, limit=30)
  ↳ *result:* 1	package dockercompose
2	
3	import (
4		"fmt"
5	
6		"github.com/nhost/be/services/mimir/model"
7		"github.com/nhost/be/services/mimir/schema/appconfig"
8	)
9	
10	func traefikHostMatch(name string) string {
11		return fmt.Sprintf(
12			"(HostRegexp(`^.+\\.%s\\.local\\.nhost\\.run$`) || Host(`local.%s.nhost.run`))", name, name)
13	}
14	
15	func auth  …(+326 more chars)
**→ Bash**(command=grep -rn "rs/cors" --include=*.go cli/ internal/ services/ | grep -v vendor/)
  ↳ *result:* cli/cmd/configserver/configserver.go:14:	cors "github.com/rs/cors/wrapper/gin"
**→ Bash**(command=grep -rn "oapi/middleware\|oapimw\|middleware.CORS" --include=*.go cli/ internal/ services/ | grep -v vendor/ | grep -i cors)
  ↳ *result:* internal/lib/oapi/oapi.go:43:	corsOptions middleware.CORSOptions,
internal/lib/oapi/oapi.go:63:		middleware.CORS(corsOptions),
internal/lib/oapi/middleware/cors.go:57://	router.Use(middleware.CORS(middleware.CORSOptions{
internal/lib/oapi/middleware/cors_test.go:10:	"github.com/nhost/nhost/internal/lib/oapi/middleware"
internal/lib/oapi/middleware/  …(+2015 more chars)
**→ Bash**(command=grep -rn "func SetupRouter" $(go env GOMODCACHE 2>/dev/null)/github.com/nhost/be*/services/mimir/graph/*.go 2>/dev/null; find / -path "*nhos  …(+121 more chars))
  ↳ *result:* /work/vendor/github.com/nhost/be/services/mimir/graph/q_app_secrets.go
/work/vendor/github.com/nhost/be/services/mimir/graph/q_run_service_configs.go
/work/vendor/github.com/nhost/be/services/mimir/graph/m_delete_secret.go
/work/vendor/github.com/nhost/be/services/mimir/graph/q_config_raw_json.go
/work/vendor/github.com/nhost/be/services/mimir/grap  …(+487 more chars)
**→ Bash**(command=grep -rn "func SetupRouter" /work/vendor/github.com/nhost/be/services/mimir/graph/*.go)
  ↳ *result:* /work/vendor/github.com/nhost/be/services/mimir/graph/router.go:22:func SetupRouter(
**→ Read**(file_path=/work/vendor/github.com/rs/cors/wrapper/gin/gin.go)
  ↳ *result:* 1	// Package cors/wrapper/gin provides gin.HandlerFunc to handle CORS related
2	// requests as a wrapper of github.com/rs/cors handler.
3	package gin
4	
5	import (
6		"net/http"
7	
8		"github.com/gin-gonic/gin"
9		"github.com/rs/cors"
10	)
11	
12	// Options is a configuration container to setup the CORS middleware.
13	type Options = cors.Options
14  …(+1576 more chars)
**→ Read**(file_path=/work/vendor/github.com/nhost/be/services/mimir/graph/router.go)
  ↳ *result:* 1	package graph
2	
3	import (
4		"context"
5	
6		"github.com/99designs/gqlgen/graphql"
7		"github.com/99designs/gqlgen/graphql/handler"
8		"github.com/99designs/gqlgen/graphql/handler/extension"
9		"github.com/99designs/gqlgen/graphql/handler/transport"
10		"github.com/gin-gonic/gin"
11		nhgraphql "github.com/nhost/be/lib/graphql"
12		nhhandler "gi  …(+1704 more chars)
**Claude:** Now let me look at the dev/up.go and dev/cloud.go call sites.

**→ Read**(file_path=/work/cli/cmd/dev/up.go, offset=420, limit=70)
  ↳ *result:* 420		ctx, cancel := context.WithCancel(ctx)
421	
422		sigChan := make(chan os.Signal, 1)
423		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
424	
425		go func() {
426			<-sigChan
427			cancel()
428		}()
429	
430		var secrets model.Secrets
431		if err := clienv.UnmarshalFile(ce.Path.Secrets(), &secrets, env.Unmarshal); err !=   …(+1631 more chars)
**→ Read**(file_path=/work/cli/cmd/dev/cloud.go, offset=195, limit=40)
  ↳ *result:* 195			proj.GetRegion().GetName(),
196			cfgSecrets.Hasura.GetAdminSecret(),
197			postgresURL,
198			ce.ProjectName(),
199			httpPort,
200			useTLS,
201			ce.Path.NhostFolder(),
202			ce.Path.DotNhostFolder(),
203			ce.Path.Root(),
204			ports,
205			dashboardVersion,
206			configserverImage,
207			caCertificatesPath,
208		)
209		if err != nil {
21  …(+868 more chars)
**→ Read**(file_path=/work/cli/cmd/dev/cloud.go, offset=180, limit=20)
  ↳ *result:* 180		ctxWithTimeout, cancel := context.WithTimeout(ctx, 5*time.Second) //nolint:mnd
181		defer cancel()
182	
183		ce.Infoln("Checking versions...")
184	
185		if err := software.CheckVersions(ctxWithTimeout, ce, cfgSecrets, appVersion); err != nil {
186			ce.Warnln("Problem verifying recommended versions: %s", err.Error())
187		}
188	
189		ce.Infoln  …(+326 more chars)
**→ Bash**(command=grep -rn "func.*LocalSubdomain\|LocalSubdomain =" cli/ | grep -v vendor; grep -rn "func.*LocalSubdomain" cli/clienv/*.go)
  ↳ *result:* cli/clienv/clienv.go:98:func (ce *CliEnv) LocalSubdomain() string {
cli/clienv/flags.go:22:	flagLocalSubdomain = "local-subdomain"
cli/clienv/clienv.go:98:func (ce *CliEnv) LocalSubdomain() string {
**→ Read**(file_path=/work/cli/clienv/clienv.go, offset=98, limit=12)
  ↳ *result:* 98	func (ce *CliEnv) LocalSubdomain() string {
99		return ce.localSubdomain
100	}
101	
102	func (ce *CliEnv) AuthURL() string {
103		return ce.authURL
104	}
105	
106	func (ce *CliEnv) GraphqlURL() string {
107		return ce.graphqlURL
108	}
109	
**Claude:** I now have the full picture. The configserver serves sensitive config (including secrets) with no authentication (`dummyMiddleware` passes everything through), and uses `cors.Default()` from `rs/cors`, which sets `Access-Control-Allow-Origin: *` — allowing **any** website to read the secrets/config cross-origin from the developer's machine. The fix is to replace the permissive wildcard CORS with the project's own restrictive CORS middleware, scoped to the dashboard origin (the only legitimate consumer).

Let me implement. Starting with the configserver itself:

**→ Edit**(replace_all=false, file_path=/work/cli/cmd/configserver/configserver.go, old_string=	"github.com/google/uuid"
	"github.com/nhost/be/services/mimir/graph"
	"github.com/nhost/nhost/cli/cmd/configserver/logsapi"
	cors "github.c  …(+83 more chars), new_string=	"github.com/google/uuid"
	"github.com/nhost/be/services/mimir/graph"
	"github.com/nhost/nhost/cli/cmd/configserver/logsapi"
	"github.com/nh  …(+99 more chars))
  ↳ *result:* The file /work/cli/cmd/configserver/configserver.go has been updated successfully. (file state is current in your context — no need to Read it back)
**→ Edit**(replace_all=false, file_path=/work/cli/cmd/configserver/configserver.go, old_string=	storageLocalRunServicesPath = "storage-local-run-services-path"
	dockerComposeProjectEnv     = "DOCKER_COMPOSE_PROJECT"
), new_string=	storageLocalRunServicesPath = "storage-local-run-services-path"
	corsAllowedOriginsFlag      = "cors-allowed-origins"
	dockerComposeProject  …(+36 more chars))
  ↳ *result:* The file /work/cli/cmd/configserver/configserver.go has been updated successfully. (file state is current in your context — no need to Read it back)
**→ Edit**(replace_all=false, file_path=/work/cli/cmd/configserver/configserver.go, old_string=			&cli.StringSliceFlag{ //nolint: exhaustruct
				Name:     storageLocalRunServicesPath,
				Usage:    "Path to the local mimir run service  …(+124 more chars), new_string=			&cli.StringSliceFlag{ //nolint: exhaustruct
				Name:     storageLocalRunServicesPath,
				Usage:    "Path to the local mimir run service  …(+404 more chars))
  ↳ *result:* The file /work/cli/cmd/configserver/configserver.go has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now update the `serve` function to use the restrictive CORS middleware:

**→ Edit**(replace_all=false, file_path=/work/cli/cmd/configserver/configserver.go, old_string=	plugins := []graph.Plugin{st}

	resolver, err := graph.NewResolver(graph.NewMapStoreFromData(data), nil, Querier{}, plugins)
	if err != nil  …(+288 more chars), new_string=	plugins := []graph.Plugin{st}

	resolver, err := graph.NewResolver(graph.NewMapStoreFromData(data), nil, Querier{}, plugins)
	if err != nil  …(+966 more chars))
  ↳ *result:* The file /work/cli/cmd/configserver/configserver.go has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now thread the dashboard origin through the docker-compose generation. Update `dockercompose/configserver.go`:

**→ Edit**(replace_all=false, file_path=/work/cli/dockercompose/configserver.go, old_string=func configserver( //nolint: funlen
	image,
	rootPath,
	nhostPath,
	projectName string,
	useTLS bool,
	runServices ...*RunService,
) (*Servi  …(+12 more chars), new_string=func configserver( //nolint: funlen
	image,
	rootPath,
	nhostPath,
	projectName string,
	subdomain string,
	httpPort uint,
	useTLS bool,
	ru  …(+47 more chars))
  ↳ *result:* The file /work/cli/dockercompose/configserver.go has been updated successfully. (file state is current in your context — no need to Read it back)
**→ Edit**(replace_all=false, file_path=/work/cli/dockercompose/configserver.go, old_string=		Command: append([]string{
			"configserver",
			"--enable-playground",
			"--debug",
		}, extraArgs...),, new_string=		Command: append([]string{
			"configserver",
			"--enable-playground",
			"--debug",
			// Restrict cross-origin access to the dashboard,   …(+184 more chars))
  ↳ *result:* The file /work/cli/dockercompose/configserver.go has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Now update the two call sites of `configserver()`:

**→ Edit**(replace_all=false, file_path=/work/cli/dockercompose/compose.go, old_string=	cs, err := configserver(
		configserviceImage,
		rootFolder,
		nhostFolder,
		projectName,
		useTLS,
		runServices...,
	), new_string=	cs, err := configserver(
		configserviceImage,
		rootFolder,
		nhostFolder,
		projectName,
		subdomain,
		httpPort,
		useTLS,
		runServices  …(+7 more chars))
  ↳ *result:* The file /work/cli/dockercompose/compose.go has been updated successfully. (file state is current in your context — no need to Read it back)
**→ Edit**(replace_all=false, file_path=/work/cli/dockercompose/compose_cloud.go, old_string=	cs, err := configserver(
		configserviceImage,
		rootFolder,
		nhostFolder,
		projectName,
		useTLS,
	), new_string=	cs, err := configserver(
		configserviceImage,
		rootFolder,
		nhostFolder,
		projectName,
		subdomain,
		httpPort,
		useTLS,
	))
  ↳ *result:* The file /work/cli/dockercompose/compose_cloud.go has been updated successfully. (file state is current in your context — no need to Read it back)
**Claude:** Let me verify everything compiles:

**→ Bash**(command=go build ./cli/... ./internal/... 2>&1 | head -40)
  ↳ *result:* (Bash completed with no output)
**Claude:** Build succeeds. Let me run `go vet` on the affected packages and check the configserver test if any:

**→ Bash**(command=go vet ./cli/cmd/configserver/... ./cli/dockercompose/... 2>&1 | head -30; echo "---tests---"; ls cli/dockercompose/*_test.go cli/cmd/config  …(+28 more chars))
  ↳ *result:* ---tests---
cli/cmd/configserver/dockerlogs_test.go
cli/cmd/configserver/local_test.go
cli/dockercompose/ai_test.go
cli/dockercompose/auth_test.go
cli/dockercompose/graphql_test.go
cli/dockercompose/main_test.go
cli/dockercompose/postgres_test.go
cli/dockercompose/run_test.go
cli/dockercompose/storage_test.go
**Claude:** Let me check if any tests snapshot the docker-compose configserver command (which I changed):

**→ Bash**(command=grep -rln "configserver\|cors-allowed" cli/dockercompose/ | grep -i test; grep -rln "cors-allowed-origins\|configserver" cli/dockercompose/*  …(+29 more chars))
  ↳ *result:* cli/dockercompose/compose_cloud.go
cli/dockercompose/compose.go
**Claude:** No snapshot tests reference the configserver command. Let me run the affected test packages to confirm nothing broke:

**→ Bash**(command=go test ./cli/cmd/configserver/... ./cli/dockercompose/... ./internal/lib/oapi/... 2>&1 | tail -30)
  ↳ *result:* ok  	github.com/nhost/nhost/cli/dockercompose	0.004s
?   	github.com/nhost/nhost/internal/lib/oapi	[no test files]
[GIN-debug] [WARNING] Running in "debug" mode. Switch to "release" mode in production.
 - using env:	export GIN_MODE=release
 - using code:	gin.SetMode(gin.ReleaseMode)

[GIN-debug] POST   /signin/email-password    --> github.com/nhost  …(+4273 more chars)
**Claude:** The only failure is in `internal/lib/oapi/example` — an unrelated request-body validation message mismatch, not touched by my change. Let me confirm it's pre-existing by checking against the clean baseline:

**→ Bash**(command=git stash && go test ./internal/lib/oapi/example/... 2>&1 | tail -5; git stash pop)
  ↳ *result:* Saved working directory and index state WIP on main: c14bbcc9 baseline
FAIL
FAIL	github.com/nhost/nhost/internal/lib/oapi/example	0.007s
?   	github.com/nhost/nhost/internal/lib/oapi/example/api	[no test files]
?   	github.com/nhost/nhost/internal/lib/oapi/example/controller	[no test files]
FAIL
On branch main
Changes not staged for commit:
  (use   …(+445 more chars)
**Claude:** Confirmed — that failure is pre-existing on the clean baseline and unrelated to my change. 

Let me do a final review of the configserver.go changes:

**→ Read**(file_path=/work/cli/cmd/configserver/configserver.go, offset=160, limit=35)
  ↳ *result:* 160		}
161	
162		plugins := []graph.Plugin{st}
163	
164		resolver, err := graph.NewResolver(graph.NewMapStoreFromData(data), nil, Querier{}, plugins)
165		if err != nil {
166			return fmt.Errorf("failed to create resolver: %w", err)
167		}
168	
169		// The configserver exposes the project's configuration and secrets without
170		// authentication,   …(+861 more chars)
**Claude:** All changes compile and the only test failure is pre-existing and unrelated. Here's a summary of the remediation.

## Vulnerability

**Missing Authentication (CWE-306)** — `cli/cmd/configserver/configserver.go`.

The CLI's `configserver` exposes the project's full configuration **including secrets** over a GraphQL/HTTP API with no authentication (the resolver runs behind `dummyMiddleware`/`dummyMiddleware2`, which are pass-throughs). Its only access control was CORS, and it used `cors.Default()` from the vendored `github.com/rs/cors/wrapper/gin` package, which sets `Access-Control-Allow-Origin: *`.

Because the server binds on the developer's machine and allows **any** origin, any website a developer visited could issue cross-origin `fetch`/XHR requests to the local configserver and read back the project's secrets and config.

## Fix

Replaced the permissive wildcard CORS with the project's own restrictive CORS middleware (`internal/lib/oapi/middleware`), scoped to the trusted dashboard origin — which is in fact the *only* legitimate consumer (the dashboard talks to the configserver at its own host/path, so the legitimate flow is same-origin and keeps working unchanged).

- **`cli/cmd/configserver/configserver.go`**: dropped the `rs/cors` import; added a `cors-allowed-origins` flag (env `CORS_ALLOWED_ORIGINS`); built `middleware.CORS(...)` restricted to the configured origins with `AllowCredentials: false`. A nil origins list is normalized to an empty (deny-all) slice so a misconfiguration fails closed rather than re-opening the wildcard.
- **`cli/dockercompose/configserver.go`**: the generated container now passes `--cors-allowed-origins=<dashboard URL>`, computed via `URL(subdomain, "dashboard", httpPort, useTLS)`.
- **`cli/dockercompose/compose.go`** and **`compose_cloud.go`**: thread `subdomain`/`httpPort` into the `configserver()` builder at both call sites.

Behavior is preserved: the dashboard (same-origin / allowlisted origin) still works, while arbitrary cross-origin sites can no longer read the response.

Note: I left the now-unused vendored `rs/cors` files in place — removing them isn't part of the remediation and would require a `go mod tidy`/`vendor` regeneration that could destabilize the build. The vulnerability was the *use* of `cors.Default()`, which is now gone (no non-vendor code imports `rs/cors` anymore).


---
**Final (success):** All changes compile and the only test failure is pre-existing and unrelated. Here's a summary of the remediation.

## Vulnerability

**Missing Authentication (CWE-306)** — `cli/cmd/configserver/configserver.go`.

The CLI's `configserver` exposes the project's full configuration **including secrets** over a GraphQL/HTTP API with no authentication (the resolver runs behind `dummyMiddleware`/`dummyMiddleware2`, which are pass-throughs). Its only access control was CORS, and it used `cors.Default()` from the vendored `github.com/rs/cors/wrapper/gin` package, which sets `Access-Control-Allow-Origin: *`.

Because the server binds on the developer's machine and allows **any** origin, any website a developer visited could issue cross-origin `fetch`/XHR requests to the local configserver and read back the project's secrets and config.

## Fix

Replaced the permissive wildcard CORS with the project's own restrictive CORS middleware (`internal/lib/oapi/middleware`), scoped to the trusted dashboard origin — which is in fact the *only* legitimate consumer (the dashboard talks to the configserver at its own host/path, so the legitimate flow is same-origin and keeps working unchanged).

- **`cli/cmd/configserver/configserver.go`**: dropped the `rs/cors` import; added a `cors-allowed-origins` flag (env `CORS_ALLOWED_ORIGINS`); built `middleware.CORS(...)` restricted to the configured origins with `AllowCredentials: false`. A nil origins list is normalized to an empty (deny-all) slice so a misconfiguration fails closed rather than re-opening the wildcard.
- **`cli/dockercompose/configserver.go`**: the generated container now passes `--cors-allowed-origins=<dashboard URL>`, computed via `URL(subdomain, "dashboard", httpPort, useTLS)`.
- **`cli/dockercompose/compose.go`** and **`compose_cloud.go`**: thread `subdomain`/`httpPort` into the `configserver()` builder at both call sites.

Behavior is preserved: the dashboard (same-origin / allowlisted origin) still works, while arbitrary cross-origin sites can no longer read the response.

Note: I left the now-unused vendored `rs/cors` files in place — removing them isn't part of the remediation and would require a `go mod tidy`/`vendor` regeneration that could destabilize the build. The vulnerability was the *use* of `cors.Default()`, which is now gone (no non-vendor code imports `rs/cors` anymore).

*turns 40 · cost $1.942*
