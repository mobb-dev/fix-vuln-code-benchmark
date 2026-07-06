# Security finding

> A code-security scan flagged the vulnerability below. No remediation is included; produce the fix yourself.

**Type:** Information Exposure — CWE-200
**Project:** `open-telemetry/opentelemetry-operator`
**Primary location:** `apis/v1alpha1/opentelemetrycollector_types.go`
**Other files possibly involved:** `apis/v1beta1/targetallocator_types.go`, `cmd/otel-allocator/internal/config/config.go`, `cmd/otel-allocator/internal/watcher/promOperator.go`, `internal/manifests/targetallocator/configmap.go`

## Details

## Affected

Repository: github.com/open-telemetry/opentelemetry-operator
Component: cmd/otel-allocator (TargetAllocator)
Companion: Prometheus Operator API types (CRDs)

## Summary

OpenTelemetry Operator's TargetAllocator watches `ServiceMonitor` resources via the Prometheus Operator CR watcher and converts each selected endpoint into a Prometheus scrape configuration entry. The endpoint field `bearerTokenFile` is preserved through the conversion as `HTTPClientConfig.Authorization.CredentialsFile`. The OpenTelemetry Collector, configured with the Prometheus receiver, then loads that scrape config and, at scrape time, reads the file from its own pod filesystem and sends the contents as `Authorization: Bearer ...` to the scrape endpoint.

A tenant who can create or update a `ServiceMonitor` selected by TargetAllocator can set `bearerTokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token` and a scrape target the tenant controls. The Collector then ships its mounted service account JWT to that target on every scrape interval.

The Prometheus Operator project addressed the same primitive via the `ArbitraryFSAccessThroughSMs.Deny` admission/runtime guard.

## Preconditions

The OpenTelemetry Collector needs to be deployed with `targetAllocator.prometheusCR.enabled: true` and `serviceMonitorSelector` / `serviceMonitorNamespaceSelector` matching at least one namespace where the attacker can create or update `ServiceMonitor` (or paired with a TargetAllocator resource with the same respective settings). The Collector pod needs to have its service account token mounted. The Collector needs to be able to reach the scrape target chosen by the attacker.

## Impact

Tenant `ServiceMonitor` write becomes equivalent to the OpenTelemetry Collector pod's service account against the Kubernetes API. Real impact depends on what the Collector service account is granted in a given deployment. Typical cluster monitoring setups grant pod, node, endpoint, namespace, and service list across the cluster, which is enough to enumerate and identify further targets. The same primitive can read any file the Collector pod has on disk including mounted certificates and other tokens.
