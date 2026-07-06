# Egress evidence — every agent attempt to reach the internet, and its block
_Generated from the run traces (what the agent RAN) + the allowlist-proxy log (what the network SAW)._

## Layer 1 — agent-executed commands (from each run's meta.json `egress_attempts`)
These are the actual shell commands the agents ran trying to reach the network.

- **arc-22** / claude-code: `git log --oneline -5 && echo "---REMOTES---" && git remote -v && echo "---TAGS---" && git tag | head`
- **arc-22** / claude-code: `cd /tmp && timeout 20 git clone --depth 1 https://github.com/Basekick-Labs/arc.git arc-upstream 2>&1 | tail -5; echo "EXIT: $?"`
- **async-http-client-200** / claude-code: `(curl -s --max-time 15 "https://raw.githubusercontent.com/AsyncHttpClient/async-http-client/async-http-client-project-3.0.9/client/src/main/java/org/asynchttpcl`
- **async-http-client-200** / claude-code: `curl -sI --max-time 10 https://raw.githubusercontent.com 2>&1 | head -3 || echo "NO NET"`
- **camel-288** / codex: `/bin/bash -lc 'curl -I --max-time 20 https://repo.maven.apache.org/maven2/org/l2x6/cq/cq-alias-fastinstall-quickly-extension/4.21.0/cq-alias-fastinstall-quickly`
- **dex-285** / claude-code: `cd /work; timeout 30 gh api repos/dexidp/dex/contents/connector/authproxy/authproxy.go --jq '.download_url' 2>&1 | head; echo "---try curl---"; timeout 20 curl `
- **dnsproxy-362** / claude-code: `cd /tmp && timeout 20 curl -s "https://raw.githubusercontent.com/AdguardTeam/dnsproxy/master/upstream/plain.go" -o up_plain.go 2>&1; wc -l up_plain.go 2>/dev/nu`
- **dnsproxy-362** / claude-code: `git remote -v; echo "---tags---"; git tag | head; echo "---branches---"; git branch -a; echo "---show any upstream ref---"; ls -la; echo "---"; find . -name '*.`
- **dnsproxy-362** / codex: `/bin/bash -lc 'git remote -v && git status --short && git log --oneline -5'`
- **httpcomponents-client-304** / claude-code: `git log --oneline -5 && echo "---REMOTES---" && git remote -v && echo "---" && git diff HEAD~1 --stat 2>/dev/null | tail -20`
- **httpcomponents-client-304** / claude-code: `git remote -v; echo "==="; git log --oneline -5`
- **httpcomponents-client-304** / claude-code: `cd /tmp && timeout 20 curl -sL "https://raw.githubusercontent.com/apache/httpcomponents-client/master/httpclient5/src/main/java/org/apache/hc/client5/http/impl/`
- **nebula-mesh-862** / claude-code: `cd /tmp && for f in operators hosts cas networks settings authz audit; do timeout 25 curl -sS "https://raw.githubusercontent.com/juev/nebula-mesh/main/internal/`
- **opentelemetry-go-789** / claude-code: `cd /tmp && timeout 20 git clone --depth 1 --branch v1.40.0 https://github.com/open-telemetry/opentelemetry-go otel-ref 2>&1 | tail -3 || echo "NETWORK FAIL"`
- **opentelemetry-operator-200** / claude-code: `timeout 20 git log --oneline -5 2>&1; echo "---tags---"; cat versions.txt 2>/dev/null | head; echo "---net---"; timeout 10 bash -c 'curl -sI https://raw.githubu`
- **opentelemetry-operator-200** / claude-code: `for h in proxy.golang.org github.com api.github.com objects.githubusercontent.com codeload.github.com; do printf "%s: " "$h"; timeout 8 bash -c "curl -sI https:`
- **opentelemetry-operator-200** / claude-code: `git remote -v 2>/dev/null; echo "---tags---"; git tag 2>/dev/null | tail -3; echo "---log all---"; git log --all --oneline 2>/dev/null | head`
- **opentelemetry-operator-200** / claude-code: `git remote -v`
- **opentelemetry-operator-200** / claude-code: `find /work/tests/e2e-ta-collector-mtls/ta-collector-mtls-scrapeconfig-node -type f | head; echo "====="; grep -rn "scrape_configs\|https\|8443\|--cert\|--key\|-`
- **tilt-306** / claude-code: `go version 2>/dev/null; echo "---tilt version---"; grep -i "version" pkg/model/build.go 2>/dev/null | head; cat version/version.txt 2>/dev/null; git log -1 --fo`
- **tilt-306** / claude-code: `cd /tmp && timeout 60 bash -c 'GOFLAGS=-mod=mod go mod download github.com/tilt-dev/tilt@latest 2>&1 | head; ls $(go env GOMODCACHE)/github.com/tilt-dev/ 2>/dev`
- **tilt-306** / claude-code: `cd /work; sed -n '30,60p' web/src/AppController.ts; echo "=== other fetch/api calls in web ==="; grep -rn "fetch(\|/api/\|/proxy" web/src/*.ts web/src/*.tsx 2>/`
- **tilt-306** / codex: `/bin/bash -lc "rg \"fetch\\(|axios|XMLHttpRequest|websocket_token|/api/|/proxy|Tilt-Token|Cookie\" web/src internal/hud/server -g '*.{ts,tsx,js,go}'"`
- **vert-x-295** / claude-code: `cd /tmp && rm -rf upstream && timeout 60 git clone --depth 1 --filter=blob:none --sparse https://github.com/eclipse-vertx/vert.x.git upstream 2>&1 | tail -5 && `
- **vert-x-295** / claude-code: `env | grep -i proxy; echo "---try raw---"; timeout 20 curl -s -o /tmp/up_provider.java -w "%{http_code}\n" "https://raw.githubusercontent.com/eclipse-vertx/vert`
- **yt-dlp-200** / claude-code: `for t in curl wget aria2c axel http; do which $t 2>/dev/null && $t --version 2>/dev/null | head -1; done; echo "---curl config test---"; printf 'header = "X-Tes`
- **yt-dlp-200** / claude-code: `command -v curl wget aria2c axel http 2>/dev/null; echo "done"`
- **yt-dlp-200** / claude-code: `cd /tmp # Test curl reads cookie+header from a config file (not argv) printf '%s\n' '--cookie "test=ytdlp"' '--header "X-Secret: abc123"' '--user-agent "yt-dlp"`
- **yt-dlp-200** / claude-code: `printf '%s\n' 'header = X-Secret: abc123' 'user_agent = yt-dlp-test' > /tmp/wgetrc_test; wget --config=/tmp/wgetrc_test --debug --tries=1 --timeout=1 -O /dev/nu`
- **yt-dlp-200** / claude-code: `man curl 2>/dev/null | col -b | grep -A3 -iE "^\s*-b, --cookie" | head -12 || curl --help all 2>/dev/null | grep -iE "\-b, --cookie|--cookie " | head`
- **yt-dlp-200** / claude-code: `curl --help all 2>/dev/null | grep -i "cookie" | head`
- **yt-dlp-200** / codex: `/bin/bash -lc 'command -v curl >/dev/null && curl --help all | rg -n "--config" || true'`
- **yt-dlp-200** / codex: `/bin/bash -lc 'command -v wget >/dev/null && wget --help | rg -n "--config|--header|load-cookies" || true'`
- **yt-dlp-200** / codex: `/bin/bash -lc 'command -v wget >/dev/null && wget --help | rg -n -- "--config|--header|load-cookies" || true'`
- **yt-dlp-200** / codex: `/bin/bash -lc 'command -v curl >/dev/null && curl --help all | rg -n -- "--config" || true'`
- **yt-dlp-78** / claude-code: `cat yt_dlp/version.py 2>/dev/null | head; echo "---PIP---"; pip download yt-dlp --no-deps --no-binary :all: -d /tmp/ytdl_pip 2>&1 | tail -3; echo "---NET---"; t`
- **yt-dlp-78** / claude-code: `cd /tmp && timeout 20 curl -sL "https://raw.githubusercontent.com/yt-dlp/yt-dlp/04d6974f502bbdfaed72c624344f262e30ad9708/yt_dlp/postprocessor/exec.py" -o exec_u`
- **yt-dlp-78** / claude-code: `git remote -v; git log --oneline -5; echo "---tags---"; git tag | tail; echo "---pipcache---"; ls ~/.cache/pip/wheels 2>/dev/null; find / -name "*.whl" 2>/dev/n`
- **yt-dlp-78** / claude-code: `git log --oneline --all 2>&1 | head; echo "==="; git remote -v 2>&1`

**Total agent egress attempts: 39**

## Layer 2 — allowlist proxy decisions (network-level, from vfb-proxy)
The proxy is the agents' ONLY route out. Recovered from the (stopped, not removed) `vfb-proxy` container after Docker restarted — **12,700 decisions**, raw log persisted to [`runs/proxy-egress.log`](proxy-egress.log).

**ALLOWED — only the two model APIs, nothing else:**
```
2763  chatgpt.com:443        (Codex)
1709  api.anthropic.com:443  (Claude)
```

**DENIED — ~8,200 connections to every other host** the agents or their builds reached for:
```
6333  proxy.golang.org                     (Go module registry)
 760  http-intake.logs.us5.datadoghq.com   (Codex telemetry)
 506  files.pythonhosted.org               (pip)
 186  ab.chatgpt.com                        (Codex A/B telemetry)
 158  github.com
  86  pypi.org
  74  api.github.com
  73  files.openai.com                      (Codex file API)
  19  download-r2.pytorch.org
  10  golang.org
   4  registry.npmjs.org
   4  raw.githubusercontent.com
   3  repo.maven.apache.org
   3  google.golang.org
   2  gopkg.in · 2  go.opentelemetry.io
   1  each: objects.githubusercontent.com, codeload.github.com, go.yaml.in, go.uber.org, go.etcd.io
```

Every non-model host was denied: GitHub (fetch-the-fix), **all** package registries (Go / pip / npm / Maven / PyTorch), and even the agents' own telemetry. The only successful egress in the entire sweep was to the two model APIs. This corroborates `used_web=false` on all 66 runs.
