# Security finding

> A code-security scan flagged the vulnerability below. No remediation is included; produce the fix yourself.

**Type:** Missing Authentication — CWE-306
**Project:** `tilt-dev/tilt`
**Primary location:** `internal/cli/flags.go`
**Other files possibly involved:** `internal/cli/utils.go`, `internal/hud/server/controller.go`, `internal/hud/server/gorilla/origin.go`, `internal/hud/server/server.go`, `internal/hud/server/websocket.go`

## Details

## Summary
The Tilt HUD HTTP server exposes state-changing and sensitive-read endpoints with no authentication. When the HUD is bound to a non-loopback address, a network attacker can trigger the developer's pre-defined Tiltfile resources, tamper with Tiltfile arguments, read full engine state including the session token, and reach the Tilt apiserver through a token-attaching proxy.

## Details
The HUD server registers its handlers on a `gorilla/mux` router with no authenticating middleware. The `cookieWrapper` helper emits the `Tilt-Token` cookie but never validates it, and is attached only to the static-asset prefix.

## Impact
An unauthenticated network caller can force any developer-defined resource to run on the host as the `tilt` user (choosing which and when, not the command text), set arbitrary Tiltfile arguments, disclose the session token and full engine state, and invoke apiserver resources via the loopback-token proxy. Because `tilt up` runs with the developer's privileges and credentials, the impact reaches the developer's environment and cluster.

### Conditions for exploitation
- HUD bound to a non-loopback address (`tilt up --host 0.0.0.0`, or `TILT_HOST` set).
- Network reachability to the listener (default port `10350`).

### Not affected
- The default loopback-only bind is not reachable from the network.
