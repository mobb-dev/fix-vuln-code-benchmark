**Codex:** I’ll inspect the finding first, then trace the affected code and make the smallest source change that removes the vulnerability without changing normal behavior.

**→ shell:** `/bin/bash -lc 'pwd && ls'`
```
/work
CLAUDE.md
CODE_OF_CONDUCT.md
CONTRIBUTING.md
FINDING.txt
LICENSE
Makefile
README.md
SECURITY.md
assets
audit-ci.jsonc
biome.json
build
changelog_summary.sh
cli
cliff.toml
dashboard
docs
envrc.sample
examples
flake.lock
flake.nix
go.mod
go.sum
govulncheck.yaml
internal
nixops
observability
package.json
packages
pnpm-lock.yaml
pnpm-workspace.yaml
services
tools
turbo.json
vendor

```
**→ shell:** `/bin/bash -lc "sed -n '1,220p' FINDING.txt"`
```
Project: nhost/nhost
Vulnerability type: Missing Authentication (CWE-306)

Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):

  cli/clienv/filesystem.go
    - lines 71-76   in: func (p PathStructure) DockerCompose() string {

  cli/cmd/configserver/configserver.go
    - lines 3-17   in: package configserver
    - lines 24-32   in: const (
    - lines 75-85   in: func Command() *cli.Command {
    - lines 144-150   in: func serve(_ context.Context, cmd *cli.Comm  …(+2433 more chars)
```
**Codex:** The finding points at the local config server plumbing and the compose files that expose it. I’m going to inspect those paths together so the fix lines up with the project’s existing CLI/config patterns.

**→ shell:** `/bin/bash -lc "sed -n '1,820p' cli/dockercompose/configserver.go"`
```
package dockercompose

import (
	"fmt"
	"path/filepath"
	"slices"
)

func configserver( //nolint: funlen
	image,
	rootPath,
	nhostPath,
	projectName string,
	useTLS bool,
	runServices ...*RunService,
) (*Service, error) {
	bindings := make([]Volume, 0, len(runServices))
	extraArgs := make([]string, len(runServices))

	mountedVolumes := make([]string, 0, len(runServices))
	for i, runService := range runServices {
		source := filepath.Dir(runService.Path)
		target := filepath.Join("/tmp", source)
  …(+1971 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,240p' cli/cmd/configserver/local.go"`
```
package configserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/nhost/be/services/mimir/graph"
	"github.com/nhost/be/services/mimir/model"
	"github.com/nhost/nhost/cli/project/env"
	"github.com/pelletier/go-toml/v2"
	"github.com/sirupsen/logrus"
)

const zeroUUID = "00000000-0000-0000-0000-000000000000"

var ErrNotImpl = errors.New("not implemented")

type Local struct {
	// we use paths instead of readers/writers because the intention is that these
	//  …(+5067 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,820p' cli/dockercompose/compose.go"`
```
package dockercompose

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/nhost/be/services/mimir/model"
	"github.com/nhost/nhost/cli/ssl"
)

const (
	authPort         = 4000
	mailhogPort      = 8025
	dashboardPort    = 3000
	storagePort      = 5000
	functionsPort    = 3000
	hasuraPort       = 8080
	consolePort      = 9695
	postgresPort     = 5432
	configserverPort = 8088
)

const (
	minimumHasuraVerson = "v2.18.0"
)

func rootNodeMod  …(+19078 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,240p' cli/cmd/configserver/configserver.go"`
```
package configserver

import (
	"context"
	"fmt"
	"os"

	"github.com/99designs/gqlgen/graphql"
	"github.com/docker/docker/client"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhost/be/services/mimir/graph"
	"github.com/nhost/nhost/cli/cmd/configserver/logsapi"
	cors "github.com/rs/cors/wrapper/gin"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

const (
	bindFlag                    = "bind"
	debugFlag                   = "debug"
	logFormatJSONFlag           = "  …(+4215 more chars)
```
**Codex:** The server currently mounts GraphQL and logs routes with only CORS/recovery middleware, while compose publishes both through the dashboard host. I’m checking the cloud/local variants and dashboard env use now to choose a compatible authentication mechanism instead of only hiding a port.

**→ shell:** `/bin/bash -lc "sed -n '420,500p' cli/cmd/dev/up.go"`
```
	ctx, cancel := context.WithCancel(ctx)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)

	go func() {
		<-sigChan
		cancel()
	}()

	var secrets model.Secrets
	if err := clienv.UnmarshalFile(ce.Path.Secrets(), &secrets, env.Unmarshal); err != nil {
		return fmt.Errorf(
			"failed to parse secrets, make sure secret values are between quotes: %w",
			err,
		)
	}

	cfg, err := config.Validate(ce, "local", secrets)
	if err != nil {
		return   …(+1498 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '160,240p' cli/cmd/dev/cloud.go"`
```
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)

	go func() {
		<-sigChan
		cancel()
	}()

	ce.Infoln("Validating configuration...")

	cfg, cfgSecrets, err := config.ValidateRemote(
		ctx,
		ce,
		proj.GetSubdomain(),
		proj.GetID(),
	)
	if err != nil {
		return fmt.Errorf("failed to validate configuration: %w", err)
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, 5*time.Second) //nolint:mnd
	defer cancel()

	ce.Infoln("Checking   …(+1516 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,260p' cli/dockercompose/compose_cloud.go"`
```
package dockercompose

import (
	"fmt"

	"github.com/nhost/be/services/mimir/model"
)

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

func dashboardCloud(
	cfg *model.ConfigConfig,
	subdomain string,
	cloudSubdomain string,
	cloudRegion string,
	cloudAdminSecret string,
	httpPort uint,
	useTLS bool,
	dashboardVersion string,
) *Service {
	dashboard := dashboard(cfg, subdomain, dashboardVersion, httpPort, useTLS)

	dashboard.Environment["NEXT_PUBLIC_NHOST_ADMIN_SECRET"] = cloudAdminSecre  …(+3835 more chars)
```
**→ shell:** `/bin/bash -lc 'rg -n "CONFIGSERVER|configserver|LOGS_GRAPHQL|NHOST_ADMIN_SECRET|NEXT_PUBLIC_NHOST_ADMIN_SECRET|x-hasura-admin-secret|admin secret" -S dashboard packages cli services internal | head -n  …(+5 more chars)`
```
dmin secret')
dashboard/src/pages/orgs/[orgSlug]/projects/[appSubdomain]/hasura.tsx:94:                  aria-label="Copy admin secret"
packages/stripe-graphql-js/src/server.ts:19:    // check if using correct `x-hasura-admin-secret` header
packages/stripe-graphql-js/src/server.ts:20:    const adminSecretFromHeader = request.headers.get('x-hasura-admin-secret');
packages/stripe-graphql-js/src/server.ts:21:    const adminSecret = process.env['NHOST_ADMIN_SECRET'];
packages/stripe-graphql-js/READM  …(+17152 more chars)
```
**Codex:** The dashboard already receives the project admin secret in local/dev compose, so using that as the shared credential should preserve behavior for legitimate dashboard calls. I’m locating the specific GraphQL clients for config and logs to add the header where those requests are made.

**→ shell:** `/bin/bash -lc "sed -n '1,140p' dashboard/src/utils/env/env.ts"`
```
/**
 * Determines whether the Nhost Dashboard is running in a cloud environment.
 */
export function isPlatform() {
  return process.env.NEXT_PUBLIC_NHOST_PLATFORM === 'true';
}

/**
 * Admin secret for Hasura.
 */
export function getHasuraAdminSecret() {
  return process.env.NEXT_PUBLIC_NHOST_ADMIN_SECRET || 'nhost-admin-secret';
}

/**
 * Custom URL of the Auth service.
 */
export function getAuthServiceUrl() {
  return (
    process.env.NEXT_PUBLIC_NHOST_AUTH_URL ||
    'https://local.auth.lo  …(+2295 more chars)
```
**→ shell:** `/bin/bash -lc "find dashboard/src -type f \\( -name '*.ts' -o -name '*.tsx' \\) | wc -l"`
```
2792

```
**→ shell:** `/bin/bash -lc 'rg -n "getConfigServer|ConfigServer|configserver|NHOST_CONFIGSERVER|LOGS_GRAPHQL|logs" dashboard/src -S | head -n 200'`
```
: 'Metrics', value: any }, functionsDuration: { __typename?: 'Metrics', value: any }, postgresVolumeCapacity: { __typename?: 'Metrics', value: any }, postgresVolumeUsage: { __typename?: 'Metrics', value: any }, totalRequests: { __typename?: 'Metrics', value: any }, egressVolume: { __typename?: 'Metrics', value: any } };
dashboard/src/utils/__generated__/graphql.ts:31399:export type GetProjectLogsQuery = { __typename?: 'query_root', logs: Array<{ __typename?: 'Log', log: string, service: string,   …(+19169 more chars)
```
**Codex:** I found the local dashboard GraphQL split and logs clients. Next I’m checking how Apollo links are built so the auth header is added once in the client layer rather than scattered across pages.

**→ shell:** `/bin/bash -lc "sed -n '1,180p' dashboard/src/utils/splitGraphqlClient/splitGraphqlClient.ts"`
```
import {
  ApolloClient,
  createHttpLink,
  InMemoryCache,
  split,
} from '@apollo/client';
import { setContext } from '@apollo/client/link/context';
import { GraphQLWsLink } from '@apollo/client/link/subscriptions';
import { getMainDefinition } from '@apollo/client/utilities';
import { createClient } from 'graphql-ws';
import { nhost } from '@/utils/nhost';

const getAuthHeaders = async () => {
  // add headers
  const session = await nhost.refreshSession(60);
  const token = session?.accessT  …(+1318 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,180p' dashboard/src/utils/localLogsClient/localLogsClient.ts"`
```
import {
  ApolloClient,
  createHttpLink,
  InMemoryCache,
  split,
} from '@apollo/client';
import { GraphQLWsLink } from '@apollo/client/link/subscriptions';
import { getMainDefinition } from '@apollo/client/utilities';
import { createClient } from 'graphql-ws';
import { getGraphqlLogsServiceUrl, getLogsWebsocketUrl } from '@/utils/env';

const httpLink = createHttpLink({ uri: getGraphqlLogsServiceUrl() });

const wsLink = new GraphQLWsLink(
  createClient({
    url: getLogsWebsocketUrl(),
    …(+661 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,120p' cli/cmd/configserver/logsapi/router.go"`
```
package logsapi

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/extension"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	nhhandler "github.com/nhost/be/lib/graphql/handler"
	"github.com/nhost/nhost/cli/cmd/configserver/logsapi/generated"
)

const (
	graphQLPath           = "/graphql"
	wsKeepAlivePingPeriod = 10 * time.Second
)

  …(+1578 more chars)
```
**→ shell:** `/bin/bash -lc 'rg -n "ApolloClient|HttpLink|GraphQLWsLink|createClient|graphql-ws|x-hasura-admin-secret" dashboard/src -S | head -n 160'`
```
dashboard/src/utils/localLogsClient/localLogsClient.ts:2:  ApolloClient,
dashboard/src/utils/localLogsClient/localLogsClient.ts:3:  createHttpLink,
dashboard/src/utils/localLogsClient/localLogsClient.ts:7:import { GraphQLWsLink } from '@apollo/client/link/subscriptions';
dashboard/src/utils/localLogsClient/localLogsClient.ts:9:import { createClient } from 'graphql-ws';
dashboard/src/utils/localLogsClient/localLogsClient.ts:12:const httpLink = createHttpLink({ uri: getGraphqlLogsServiceUrl() });
  …(+19922 more chars)
```
**Codex:** For logs subscriptions, HTTP middleware alone would not cover the WebSocket path after upgrade unless the connection is checked at init. I’m checking the gqlgen transport API in the vendored/module code so the WebSocket auth is enforced server-side too.

**→ shell:** `/bin/bash -lc 'rg -n "type InitPayload|Authorization|headers" $(go env GOPATH 2>/dev/null)/pkg/mod/github.com/99designs/gqlgen* -S 2>/dev/null | head -n 120'`
**→ shell:** `/bin/bash -lc "rg -n \"func SetupRouter|SetupRouter\\(\" "'$(go env GOPATH 2>/dev/null)/pkg/mod/github.com/nhost/be* vendor/github.com/nhost/be cli -S 2>/dev/null | head -n 80'`
```
vendor/github.com/nhost/be/services/mimir/graph/router.go:22:func SetupRouter(
cli/cmd/configserver/configserver.go:161:	r := graph.SetupRouter(

```
**→ shell:** `/bin/bash -lc 'rg -n "type Websocket|InitFunc|InitPayload|WebsocketInit" $(go env GOPATH 2>/dev/null)/pkg/mod/github.com/99designs/gqlgen* vendor github.com 2>/dev/null | head -n 80'`
```
vendor/github.com/blevesearch/bleve/v2/index/scorch/scorch.go:751:type customAnalyzerPluginInitFunc func(field index.Field)
vendor/github.com/blevesearch/bleve/v2/index/scorch/scorch.go:764:func analyze(d index.Document, fn customAnalyzerPluginInitFunc) {
vendor/github.com/99designs/gqlgen/graphql/handler/transport/websocket_init.go:11:// InitPayload is a structure that is parsed from the websocket init message payload. TO use
vendor/github.com/99designs/gqlgen/graphql/handler/transport/websocke  …(+3278 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,140p' vendor/github.com/99designs/gqlgen/graphql/handler/transport/websocket_init.go"`
```
package transport

import "context"

type key string

const (
	initpayload key = "ws_initpayload_context"
)

// InitPayload is a structure that is parsed from the websocket init message payload. TO use
// request headers for non-websocket, instead wrap the graphql handler in a middleware.
type InitPayload map[string]any

// GetString safely gets a string value from the payload. It returns an empty string if the
// payload is nil or the value isn't set.
func (p InitPayload) GetString(key string)   …(+869 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,140p' vendor/github.com/nhost/be/services/mimir/graph/router.go"`
```
package graph

import (
	"context"

	"github.com/99designs/gqlgen/graphql"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/extension"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/gin-gonic/gin"
	nhgraphql "github.com/nhost/be/lib/graphql"
	nhhandler "github.com/nhost/be/lib/graphql/handler"
	nhmiddleware "github.com/nhost/be/lib/graphql/middleware"
	"github.com/nhost/be/services/mimir/graph/generated"
	"github.com/prometheus/c  …(+1347 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,130p' vendor/github.com/nhost/be/lib/graphql/context/gin.go"`
```
package nhcontext

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/gin-gonic/gin"
)

type contextKey string

const (
	ginContextKey         = contextKey("gin.Context")
	initPayloadHeadersKey = contextKey("init_payload_http_headers")
)

// GinContextToContextMiddleware is a gin middleware to store the gin.Context in the context.
// The purpose is to be able to retrieve the gin.Context from other parts
// in the graphql code a  …(+2330 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,180p' internal/lib/oapi/middleware/cors.go"`
```
package middleware

import (
	"net/http"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
)

// CORSOptions configures the CORS middleware behavior.
//
// The middleware supports three strategies for handling Access-Control-Allow-Headers:
//   - nil (default): Reflects the Access-Control-Request-Headers from the client
//   - empty slice: Denies all headers (no Access-Control-Allow-Headers header is set)
//   - non-empty slice: Uses the specified headers
type CORSOptions struct {
	// AllowedOri  …(+3850 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,120p' vendor/github.com/rs/cors/wrapper/gin/gin.go"`
```
// Package cors/wrapper/gin provides gin.HandlerFunc to handle CORS related
// requests as a wrapper of github.com/rs/cors handler.
package gin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/cors"
)

// Options is a configuration container to setup the CORS middleware.
type Options = cors.Options

// corsWrapper is a wrapper of cors.Cors handler which preserves information
// about configured 'optionPassthrough' option.
type corsWrapper struct {
	*cors.Cors
	optionsSuccessSta  …(+1252 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"AllowedHeaders|Default\\(\\)|AllowAll|rs/cors\" vendor/github.com/rs/cors/cors.go -n && sed -n '120,220p' vendor/github.com/rs/cors/cors.go"`
```
30:	"github.com/rs/cors/internal"
68:	// AllowedHeaders is list of non simple headers the client is allowed to use with
72:	AllowedHeaders []string
195:	if len(options.AllowedHeaders) == 0 {
199:		normalized := convert(options.AllowedHeaders, strings.ToLower)
201:		for _, h := range options.AllowedHeaders {
248:func Default() *Cors {
252:// AllowAll create a new Cors handler with permissive configuration allowing all
254:func AllowAll() *Cors {
265:		AllowedHeaders:   []string{"*"},
338:	// see   …(+3679 more chars)
```
**Codex:** I’m going to add a server-side admin-secret gate to the config server, pass that secret into the container from compose, and teach the local dashboard clients to send it. The WebSocket route will authenticate during `connection_init`, since browsers cannot attach arbitrary headers to the upgrade request.

**→ shell:** `/bin/bash -lc "sed -n '1,80p' dashboard/src/features/orgs/projects/hooks/useLocalMimirClient/useLocalMimirClient.ts"`
```
import { ApolloClient, HttpLink, InMemoryCache } from '@apollo/client';
import { useMemo } from 'react';
import { getConfigServerUrl } from '@/utils/env';

/**
 * It creates a new Apollo Client instance that connects to the local mimir when running the a local nhost project
 * @returns A function that returns a new ApolloClient instance.
 */
export default function useLocalMimirClient() {
  return useMemo(
    () =>
      new ApolloClient({
        cache: new InMemoryCache(),
        link: new H  …(+84 more chars)
```
**→ shell:** `/bin/bash -lc "ls cli/cmd/configserver && sed -n '1,340p' cli/cmd/configserver/local_test.go"`
```
configserver.go
dockerlogs.go
dockerlogs_test.go
local.go
local_test.go
logger.go
logsapi
querier.go
package configserver_test

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/nhost/be/services/mimir/graph"
	"github.com/nhost/be/services/mimir/model"
	"github.com/nhost/nhost/cli/cmd/configserver"
)

const rawConfig = `[hasura]
adminSecret = 'hasuraAdminSecret'
webhookSecret = 'webhookSecret'

[[hasura.jwtSecrets]]
type = 'HS256'
key  …(+5867 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"AddRoutes\\(r, \\\"/v1/logs|logsapi.AddRoutes|NewLocal\\(|configserver\\(\" cli/cmd cli/dockercompose -S"`
```
cli/dockercompose/compose_cloud.go:126:	cs, err := configserver(
cli/dockercompose/configserver.go:9:func configserver( //nolint: funlen
cli/dockercompose/compose.go:625:	cs, err := configserver(
cli/cmd/configserver/local.go:32:func NewLocal(config, secrets string, runServices map[string]string) *Local {
cli/cmd/configserver/local_test.go:124:			st := configserver.NewLocal(
cli/cmd/configserver/local_test.go:187:			st := configserver.NewLocal(
cli/cmd/configserver/local_test.go:257:			st := con  …(+231 more chars)
```
**Codex:** I’m editing the config server package first: adding constant-time admin-secret validation, preserving unauthenticated health checks and preflights, and wiring WebSocket init auth for logs.

**✎ files:** update `/work/cli/cmd/configserver/configserver.go`

**Codex:** The server gate is in place. I’m updating the logs router signature next so subscription connections are rejected unless the dashboard supplies the same secret during GraphQL WebSocket initialization.

**✎ files:** update `/work/cli/cmd/configserver/logsapi/router.go`

**Codex:** Now I’m wiring compose generation so both local and cloud dev start the config server with the exact admin secret the dashboard already uses.

**✎ files:** update `/work/cli/dockercompose/configserver.go`

**✎ files:** update `/work/cli/dockercompose/compose.go`

**✎ files:** update `/work/cli/dockercompose/compose_cloud.go`

**Codex:** The container will now require a secret. I’m updating the dashboard’s local config and logs clients to send that header on HTTP requests and in WebSocket connection params.

**✎ files:** update `/work/dashboard/src/features/orgs/projects/hooks/useLocalMimirClient/useLocalMimirClient.ts`

**✎ files:** update `/work/dashboard/src/utils/localLogsClient/localLogsClient.ts`

**Codex:** I’m adding focused Go tests around the auth middleware and WebSocket init function, then I’ll run the affected Go package tests and TypeScript formatting/lint checks where practical.

**✎ files:** add `/work/cli/cmd/configserver/auth_test.go`

**Codex:** The focused tests are in place. I’m formatting the Go changes and running the affected test suites now; if generated compose snapshots or lint rules need adjustment, I’ll handle those next.

**→ shell:** `/bin/bash -lc 'gofmt -w cli/cmd/configserver/configserver.go cli/cmd/configserver/logsapi/router.go cli/cmd/configserver/auth_test.go cli/dockercompose/configserver.go cli/dockercompose/compose.go cli  …(+32 more chars)`
```
/bin/bash: line 1: gofmt: command not found

```
**→ shell:** `/bin/bash -lc 'git diff -- cli/cmd/configserver/configserver.go cli/cmd/configserver/logsapi/router.go cli/dockercompose/configserver.go cli/dockercompose/compose.go cli/dockercompose/compose_cloud.go  …(+176 more chars)`
```
diff --git a/cli/cmd/configserver/configserver.go b/cli/cmd/configserver/configserver.go
index 18fa8273..79cc8b52 100644
--- a/cli/cmd/configserver/configserver.go
+++ b/cli/cmd/configserver/configserver.go
@@ -2,10 +2,15 @@ package configserver
 
 import (
 	"context"
+	"crypto/subtle"
+	"errors"
 	"fmt"
+	"net/http"
 	"os"
+	"strings"
 
 	"github.com/99designs/gqlgen/graphql"
+	"github.com/99designs/gqlgen/graphql/handler/transport"
 	"github.com/docker/docker/client"
 	"github.com/gin-gonic/g  …(+9163 more chars)
```
**Codex:** `gofmt` is not on the base PATH in this workspace, so I’m checking the project’s available toolchain wrappers before falling back to minimal manual formatting.

**→ shell:** `/bin/bash -lc 'which go || true; which nix || true; which biome || true; which pnpm || true'`
**→ shell:** `/bin/bash -lc "sed -n '1,140p' cli/cmd/configserver/auth_test.go"`
```
package configserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/gin-gonic/gin"
)

func TestAdminSecretAuth(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	cases := []struct {
		name       string
		path       string
		method     string
		header     string
		wantStatus int
	}{
		{
			name:       "allows matching admin secret",
			path:       "/v1/configserver/graphql",
			method:     http.MethodPost,
			h  …(+1745 more chars)
```
**→ shell:** `/bin/bash -lc 'find /work -maxdepth 3 -name gofmt -o -name go | head -n 20'`
```
/work/services/auth/go
/work/vendor/cuelang.org/go
/work/nixops/lib/go

```
**Codex:** The base environment does not expose `go`, `gofmt`, `pnpm`, or `nix`, so I can’t execute the normal test/format commands here. I’m still doing static checks available in the shell, including whitespace checks and targeted diffs.

**→ shell:** `/bin/bash -lc 'git diff -- cli/cmd/configserver/auth_test.go cli/cmd/configserver/configserver.go cli/cmd/configserver/logsapi/router.go cli/dockercompose/configserver.go cli/dockercompose/compose.go   …(+176 more chars)`
```
t
@@ -13,6 +13,9 @@ export default function useLocalMimirClient() {
         cache: new InMemoryCache(),
         link: new HttpLink({
           uri: getConfigServerUrl(),
+          headers: {
+            'x-hasura-admin-secret': getHasuraAdminSecret(),
+          },
         }),
       }),
     [],
diff --git a/dashboard/src/utils/localLogsClient/localLogsClient.ts b/dashboard/src/utils/localLogsClient/localLogsClient.ts
index db7748ff..cf6185d1 100644
--- a/dashboard/src/utils/localLogsClie  …(+971 more chars)
```
**→ shell:** `/bin/bash -lc 'git diff --check'`
**→ shell:** `/bin/bash -lc 'git diff --stat'`
```
 cli/cmd/configserver/configserver.go               | 113 ++++++++++++++++++++-
 cli/cmd/configserver/logsapi/router.go             |   2 +
 cli/dockercompose/compose.go                       |   1 +
 cli/dockercompose/compose_cloud.go                 |   1 +
 cli/dockercompose/configserver.go                  |   3 +
 .../useLocalMimirClient/useLocalMimirClient.ts     |   5 +-
 .../src/utils/localLogsClient/localLogsClient.ts   |  18 +++-
 7 files changed, 137 insertions(+), 6 deletions(-)

```
**Codex:** The whitespace check passes. I noticed the new test file is untracked, so I’m including it in the final review and checking the working tree status explicitly.

**→ shell:** `/bin/bash -lc "rg -n \"admin-secret|x-hasura-admin-secret|webSocketAdminSecretAuth|adminSecretAuth|AddRoutes\\(\" cli/cmd/configserver cli/dockercompose dashboard/src/features/orgs/projects/hooks/useL  …(+55 more chars)`
```
cli/cmd/configserver/logsapi/router.go:47:func AddRoutes(
cli/dockercompose/configserver.go:85:			"--admin-secret=" + adminSecret,
cli/cmd/configserver/configserver.go:29:	adminSecretFlag             = "admin-secret"
cli/cmd/configserver/configserver.go:34:	adminSecretHeader           = "x-hasura-admin-secret"
cli/cmd/configserver/configserver.go:135:func adminSecretAuth(adminSecret string) gin.HandlerFunc {
cli/cmd/configserver/configserver.go:181:func webSocketAdminSecretAuth(adminSecret strin  …(+662 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,320p' cli/cmd/configserver/configserver.go"`
```
package configserver

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/99designs/gqlgen/graphql"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/docker/docker/client"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhost/be/services/mimir/graph"
	"github.com/nhost/nhost/cli/cmd/configserver/logsapi"
	cors "github.com/rs/cors/wrapper/gin"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

const (
	b  …(+6795 more chars)
```
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M cli/cmd/configserver/configserver.go
 M cli/cmd/configserver/logsapi/router.go
 M cli/dockercompose/compose.go
 M cli/dockercompose/compose_cloud.go
 M cli/dockercompose/configserver.go
 M dashboard/src/features/orgs/projects/hooks/useLocalMimirClient/useLocalMimirClient.ts
 M dashboard/src/utils/localLogsClient/localLogsClient.ts
?? cli/cmd/configserver/auth_test.go

```
**Codex:** I’m tightening the CORS side as well: authenticated requests stay the key control, but browser origins should be limited to the local dashboard/localhost origins that are expected to call this service.

**✎ files:** update `/work/cli/cmd/configserver/configserver.go`

**✎ files:** update `/work/cli/cmd/configserver/auth_test.go`

**Codex:** The CORS restriction is added with a small origin helper and tests. I’m re-running whitespace/diff checks and reviewing the final touched files for formatting issues since `gofmt` is unavailable.

**→ shell:** `/bin/bash -lc "sed -n '1,180p' cli/cmd/configserver/auth_test.go"`
```
package configserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/gin-gonic/gin"
)

func TestAdminSecretAuth(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	cases := []struct {
		name       string
		path       string
		method     string
		header     string
		wantStatus int
	}{
		{
			name:       "allows matching admin secret",
			path:       "/v1/configserver/graphql",
			method:     http.MethodPost,
			h  …(+2449 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '110,300p' cli/cmd/configserver/configserver.go"`
```
	next graphql.Resolver,
	_ []string,
) (any, error) {
	return next(ctx)
}

func runServicesFiles(runServices ...string) map[string]string {
	m := make(map[string]string)

	for _, path := range runServices {
		id := uuid.NewString()
		m[id] = path
	}

	return m
}

func validAdminSecret(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func isWebSocketUpgrade(c *gin.Context) bool {
	return strings.EqualFold(c.GetHeader("Upgrade"), "websocket") &&
		stri  …(+3869 more chars)
```
**→ shell:** `/bin/bash -lc 'git diff --check'`
**→ shell:** `/bin/bash -lc "sed -n '1,80p' dashboard/src/utils/localLogsClient/localLogsClient.ts && sed -n '1,60p' dashboard/src/features/orgs/projects/hooks/useLocalMimirClient/useLocalMimirClient.ts"`
```
import {
  ApolloClient,
  createHttpLink,
  InMemoryCache,
  split,
} from '@apollo/client';
import { GraphQLWsLink } from '@apollo/client/link/subscriptions';
import { getMainDefinition } from '@apollo/client/utilities';
import { createClient } from 'graphql-ws';
import {
  getGraphqlLogsServiceUrl,
  getHasuraAdminSecret,
  getLogsWebsocketUrl,
} from '@/utils/env';

const getAdminSecretHeaders = () => ({
  'x-hasura-admin-secret': getHasuraAdminSecret(),
});

const httpLink = createHttpLink(  …(+1604 more chars)
```
**Codex:** I spotted a test hygiene issue: `gin.SetMode` mutates global state, so I’m removing parallelization from that specific test while keeping the pure helper tests parallel.

**✎ files:** update `/work/cli/cmd/configserver/auth_test.go`

**Codex:** The test parallelization issue is fixed. I’m doing one final status and whitespace pass, then I’ll summarize the exact remediation and the verification limitation.

**→ shell:** `/bin/bash -lc "sed -n '1,170p' cli/cmd/configserver/auth_test.go"`
```
package configserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/gin-gonic/gin"
)

func TestAdminSecretAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := []struct {
		name       string
		path       string
		method     string
		header     string
		wantStatus int
	}{
		{
			name:       "allows matching admin secret",
			path:       "/v1/configserver/graphql",
			method:     http.MethodPost,
			header:     "sec  …(+2417 more chars)
```
**→ shell:** `/bin/bash -lc 'git diff -- cli/cmd/configserver/configserver.go cli/cmd/configserver/logsapi/router.go cli/dockercompose/configserver.go cli/dockercompose/compose.go cli/dockercompose/compose_cloud.go  …(+142 more chars)`
```
/orgs/projects/hooks/useLocalMimirClient/useLocalMimirClient.ts
@@ -1,6 +1,6 @@
 import { ApolloClient, HttpLink, InMemoryCache } from '@apollo/client';
 import { useMemo } from 'react';
-import { getConfigServerUrl } from '@/utils/env';
+import { getConfigServerUrl, getHasuraAdminSecret } from '@/utils/env';
 
 /**
  * It creates a new Apollo Client instance that connects to the local mimir when running the a local nhost project
@@ -13,6 +13,9 @@ export default function useLocalMimirClient() {
  …(+1403 more chars)
```
**→ shell:** `/bin/bash -lc 'git diff --check && git status --short'`
```
 M cli/cmd/configserver/configserver.go
 M cli/cmd/configserver/logsapi/router.go
 M cli/dockercompose/compose.go
 M cli/dockercompose/compose_cloud.go
 M cli/dockercompose/configserver.go
 M dashboard/src/features/orgs/projects/hooks/useLocalMimirClient/useLocalMimirClient.ts
 M dashboard/src/utils/localLogsClient/localLogsClient.ts
?? cli/cmd/configserver/auth_test.go

```
**Codex:** No whitespace issues remain. I’m checking once more for any local Go/Node binaries under common paths, but the workspace appears to be source-only in this environment.

**→ shell:** `/bin/bash -lc 'command -v go || command -v gofmt || command -v pnpm || command -v npm || command -v node || true'`
```
/usr/bin/npm

```
**→ shell:** `/bin/bash -lc "find /usr /opt /nix /root -maxdepth 4 \\( -name gofmt -o -name go -o -name pnpm -o -name node \\) 2>/dev/null | head -n 50"`
```
/usr/include/node
/usr/local/go
/usr/local/go/src/go
/usr/local/go/bin/go
/usr/local/go/bin/gofmt
/usr/bin/node
/usr/share/doc/node

```
**Codex:** There is a Go toolchain under `/usr/local/go/bin`, just not on PATH. I’m using that directly to format and run the affected Go tests now, and I’ll run the available npm-based check for the touched dashboard files if the repo scripts support it.

**→ shell:** `/bin/bash -lc 'npm --version && node --version && npm exec -- biome check dashboard/src/features/orgs/projects/hooks/useLocalMimirClient/useLocalMimirClient.ts dashboard/src/utils/localLogsClient/loca  …(+15 more chars)`
```
10.9.8
v22.23.0
npm error code E403
npm error 403 403 blocked by egress allowlist - GET https://registry.npmjs.org/biome
npm error 403 In most cases, you or one of your dependencies are requesting
npm error 403 a package version that is forbidden by your security policy, or
npm error 403 on a server you do not have access to.
npm error A complete log of this run can be found in: /root/.npm/_logs/2026-06-30T19_03_56_700Z-debug-0.log

```
**Codex:** The dashboard check could not run because `npm exec` tried to fetch `biome` and registry egress is blocked. The Go test command is still running; I’m waiting for its result.

**→ shell:** `/bin/bash -lc '/usr/local/go/bin/gofmt -w cli/cmd/configserver/configserver.go cli/cmd/configserver/logsapi/router.go cli/cmd/configserver/auth_test.go cli/dockercompose/configserver.go cli/dockercomp  …(+153 more chars)`
```
ok  	github.com/nhost/nhost/cli/cmd/configserver	0.015s
ok  	github.com/nhost/nhost/cli/cmd/configserver/logsapi	0.004s
ok  	github.com/nhost/nhost/cli/dockercompose	0.003s

```
**Codex:** The affected Go tests pass after formatting. I’m doing the final working-tree and whitespace check now.

**→ shell:** `/bin/bash -lc "git diff -- cli/cmd/configserver/auth_test.go cli/cmd/configserver/configserver.go cli/cmd/configserver/logsapi/router.go cli/dockercompose/configserver.go cli/dockercompose/compose.go   …(+194 more chars)`
```
diff --git a/cli/cmd/configserver/configserver.go b/cli/cmd/configserver/configserver.go
index 18fa8273..d6d3cc78 100644
--- a/cli/cmd/configserver/configserver.go
+++ b/cli/cmd/configserver/configserver.go
@@ -2,10 +2,16 @@ package configserver
 
 import (
 	"context"
+	"crypto/subtle"
+	"errors"
 	"fmt"
+	"net/http"
+	"net/url"
 	"os"
+	"strings"
 
 	"github.com/99designs/gqlgen/graphql"
+	"github.com/99designs/gqlgen/graphql/handler/transport"
 	"github.com/docker/docker/client"
 	"github.com  …(+6905 more chars)
```
**→ shell:** `/bin/bash -lc 'git diff --stat'`
```
 cli/cmd/configserver/configserver.go               | 134 ++++++++++++++++++++-
 cli/cmd/configserver/logsapi/router.go             |   2 +
 cli/dockercompose/compose.go                       |   1 +
 cli/dockercompose/compose_cloud.go                 |   1 +
 cli/dockercompose/configserver.go                  |   3 +
 .../useLocalMimirClient/useLocalMimirClient.ts     |   5 +-
 .../src/utils/localLogsClient/localLogsClient.ts   |  18 ++-
 7 files changed, 158 insertions(+), 6 deletions(-)

```
**→ shell:** `/bin/bash -lc 'git diff --check && git status --short'`
```
 M cli/cmd/configserver/configserver.go
 M cli/cmd/configserver/logsapi/router.go
 M cli/dockercompose/compose.go
 M cli/dockercompose/compose_cloud.go
 M cli/dockercompose/configserver.go
 M dashboard/src/features/orgs/projects/hooks/useLocalMimirClient/useLocalMimirClient.ts
 M dashboard/src/utils/localLogsClient/localLogsClient.ts
?? cli/cmd/configserver/auth_test.go

```
**Codex:** The final checks are clean, and the Go package tests passed. I’m gathering line references for the summary.

**→ shell:** `/bin/bash -lc "nl -ba cli/cmd/configserver/configserver.go | sed -n '124,310p'"`
```
   124		return m
   125	}
   126	
   127	func validAdminSecret(got, want string) bool {
   128		return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
   129	}
   130	
   131	func isWebSocketUpgrade(c *gin.Context) bool {
   132		return strings.EqualFold(c.GetHeader("Upgrade"), "websocket") &&
   133			strings.Contains(strings.ToLower(c.GetHeader("Connection")), "upgrade")
   134	}
   135	
   136	func isAllowedDashboardOrigin(origin string) bool {
   137		if origin == "" {
   138			re  …(+5171 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba cli/dockercompose/configserver.go | sed -n '1,120p'"`
```
     1	package dockercompose
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
    15		adminSecret string,
    16		runServices ...*RunService,
    17	) (*Service, error) {
    18		bindings := make([]Volume, 0, len(runServices))
    19		extraArgs := make([]string, len(runServices))
    20	
    21		mountedVolum  …(+2882 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba dashboard/src/utils/localLogsClient/localLogsClient.ts | sed -n '1,60p'; nl -ba dashboard/src/features/orgs/projects/hooks/useLocalMimirClient/useLocalMimirClient.ts | sed -n '1,  …(+5 more chars)`
```
     1	import {
     2	  ApolloClient,
     3	  createHttpLink,
     4	  InMemoryCache,
     5	  split,
     6	} from '@apollo/client';
     7	import { GraphQLWsLink } from '@apollo/client/link/subscriptions';
     8	import { getMainDefinition } from '@apollo/client/utilities';
     9	import { createClient } from 'graphql-ws';
    10	import {
    11	  getGraphqlLogsServiceUrl,
    12	  getHasuraAdminSecret,
    13	  getLogsWebsocketUrl,
    14	} from '@/utils/env';
    15	
    16	const getAdminS  …(+2110 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba cli/cmd/configserver/auth_test.go | sed -n '1,170p'"`
```
     1	package configserver
     2	
     3	import (
     4		"net/http"
     5		"net/http/httptest"
     6		"testing"
     7	
     8		"github.com/99designs/gqlgen/graphql/handler/transport"
     9		"github.com/gin-gonic/gin"
    10	)
    11	
    12	func TestAdminSecretAuth(t *testing.T) {
    13		gin.SetMode(gin.TestMode)
    14	
    15		cases := []struct {
    16			name       string
    17			path       string
    18			method     string
    19			header     string
    20			wantStatus int
    21		}  …(+3362 more chars)
```
**Codex:** Implemented the remediation locally.

The config server now requires `x-hasura-admin-secret` for protected HTTP routes, uses constant-time comparison, keeps health/metrics and preflight behavior intact, and authenticates logs WebSocket subscriptions during GraphQL connection init. CORS is also restricted to local dashboard/localhost origins. See [configserver.go](/work/cli/cmd/configserver/configserver.go:127).

Compose generation now passes the same admin secret into the configserver container for local and cloud dev flows. See [configserver.go](/work/cli/dockercompose/configserver.go:81).

The dashboard local config and logs clients now send the admin secret on HTTP requests and logs WebSocket connection params. See [localLogsClient.ts](/work/dashboard/src/utils/localLogsClient/localLogsClient.ts:16) and [useLocalMimirClient.ts](/work/dashboard/src/features/orgs/projects/hooks/useLocalMimirClient/useLocalMimirClient.ts:15).

Added focused auth tests in [auth_test.go](/work/cli/cmd/configserver/auth_test.go:12).

Verification:
`/usr/local/go/bin/go test ./cli/cmd/configserver ./cli/cmd/configserver/logsapi ./cli/dockercompose` passes.

I could not run the dashboard Biome check because `npm exec -- biome ...` attempted to fetch from npm and registry egress was blocked with `E403`. `git diff --check` passes.


---
*tokens — input 1928795 (cached 1837952), output 13226, reasoning 3905*
