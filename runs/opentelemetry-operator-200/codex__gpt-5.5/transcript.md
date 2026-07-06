**Codex:** I’ll inspect the finding and the affected code first, then patch only the local source needed to remediate it.

**→ shell:** `/bin/bash -lc "sed -n '1,220p' FINDING.txt"`
```
Project: open-telemetry/opentelemetry-operator
Vulnerability type: Information Exposure (CWE-200)

Where the vulnerability is (file -> vulnerable line ranges, with enclosing function):

  apis/v1alpha1/opentelemetrycollector_types.go
    - lines 411-416   in: type OpenTelemetryTargetAllocatorPrometheusCR struct {

  apis/v1beta1/targetallocator_types.go
    - lines 22-27   in: type TargetAllocatorPrometheusCR struct {

  cmd/otel-allocator/internal/config/config.go
    - lines 92-97   in: type P  …(+547 more chars)
```
**→ shell:** `/bin/bash -lc "pwd && rg --files -g 'FINDING.txt' -g 'AGENTS.md' -g 'go.mod' -g '*.go' | head -200"`
```
/work
pkg/featuregate/featuregate.go
pkg/featuregate/featuregate_test.go
pkg/sidecar/pod_test.go
pkg/sidecar/attributes_test.go
pkg/sidecar/podmutator.go
pkg/sidecar/pod.go
pkg/sidecar/annotation.go
pkg/sidecar/annotation_test.go
pkg/sidecar/attributes.go
pkg/collector/upgrade/versions.go
pkg/collector/upgrade/suite_test.go
pkg/collector/upgrade/v0_122_0_test.go
pkg/collector/upgrade/v0_24_0_test.go
pkg/collector/upgrade/v0_24_0.go
pkg/collector/upgrade/v0_105_0_test.go
pkg/collector/upgrade/v0_  …(+7989 more chars)
```
**Codex:** The finding points at Target Allocator Prometheus CR configuration flowing into generated config and watcher state. I’m reading those structs and the watcher implementation now to identify which exposed field needs to stop being surfaced.

**→ shell:** `/bin/bash -lc "sed -n '1,70p' apis/v1beta1/targetallocator_types.go"`
```
// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TargetAllocatorPrometheusCR configures Prometheus CustomResource handling in the Target Allocator.
type TargetAllocatorPrometheusCR struct {
	// Enabled indicates whether to use a PrometheusOperator custom resources as targets or not.
	// +optional
	Enabled bool `json:"enabled,omitempty"`
	// AllowNamespaces Namespaces to scope the interact  …(+3271 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '360,445p' apis/v1alpha1/opentelemetrycollector_types.go"`
```
	// controls how pods are spread across your cluster among failure-domains
	// such as regions, zones, nodes, and other user-defined topology domains
	// https://kubernetes.io/docs/concepts/workloads/pods/pod-topology-spread-constraints/
	// +optional
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	// Toleration embedded kubernetes pod configuration option,
	// controls how pods can be scheduled with matching taints
	// +optional
	Toleration  …(+3575 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '70,115p' cmd/otel-allocator/internal/config/config.go"`
```
	AllocationStrategy           string                `yaml:"allocation_strategy,omitempty"`
	AllocationFallbackStrategy   string                `yaml:"allocation_fallback_strategy,omitempty"`
	FilterStrategy               string                `yaml:"filter_strategy,omitempty"`
	PrometheusCR                 PrometheusCRConfig    `yaml:"prometheus_cr,omitempty"`
	HTTPS                        HTTPSServerConfig     `yaml:"https,omitempty"`
	CollectorNotReadyGracePeriod time.Duration         `yaml:"c  …(+2416 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '90,135p' internal/manifests/targetallocator/configmap.go"`
```
	if taSpec.PrometheusCR.Enabled {
		prometheusCRConfig := map[any]any{
			"enabled": true,
		}
		if taSpec.PrometheusCR.ScrapeInterval.Size() > 0 {
			prometheusCRConfig["scrape_interval"] = taSpec.PrometheusCR.ScrapeInterval.Duration
		}
		if taSpec.PrometheusCR.EvaluationInterval.Size() > 0 {
			prometheusCRConfig["evaluation_interval"] = taSpec.PrometheusCR.EvaluationInterval.Duration
		}
		if taSpec.PrometheusCR.ScrapeProtocols != nil {
			prometheusCRConfig["scrape_protocols"] = taSpec.Prom  …(+1509 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '130,190p;630,680p' cmd/otel-allocator/internal/watcher/promOperator.go"`
```

	resourceSelector, err = prometheus.NewResourceSelector(slogger, prom, store, nsMonInf, operatorMetrics, eventRecorder)
	if err != nil {
		logger.Error(err, "Failed to create resource selector in promOperator CRD watcher")
	}

	return &PrometheusCRWatcher{
		logger:                          slogger,
		kubeMonitoringClient:            monitoringclient,
		k8sClient:                       client,
		informers:                       monitoringInformers,
		nsInformer:                      nsMonInf,
	  …(+4220 more chars)
```
**Codex:** The line ranges line up with `secretNamespaces` and its propagation into the allocator ConfigMap/watcher. That exposes secret watch scope through non-secret config. I’m checking tests and generated references so the fix preserves current behavior as much as possible while removing that config surface.

**→ shell:** `/bin/bash -lc "nl -ba apis/v1beta1/targetallocator_types.go | sed -n '16,34p'"`
```
    16		// +optional
    17		AllowNamespaces []string `json:"allowNamespaces,omitempty"`
    18		// DenyNamespaces Namespaces to scope the interaction of the Target Allocator and the apiserver (deny list). This is mutually exclusive with AllowNamespaces.
    19		// +optional
    20		DenyNamespaces []string `json:"denyNamespaces,omitempty"`
    21		// SecretNamespaces Namespaces to scope the watching of secrets for the Target Allocator.
    22		// If not configured, defaults to the target allocat  …(+562 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba apis/v1alpha1/opentelemetrycollector_types.go | sed -n '400,422p'"`
```
   400		// +kubebuilder:pruning:PreserveUnknownFields
   401		ScrapeClasses []v1beta1.AnyConfig `json:"scrapeClasses,omitempty"`
   402		// PodMonitors to be selected for target discovery.
   403		// This is a map of {key,value} pairs. Each {key,value} in the map is going to exactly match a label in a
   404		// PodMonitor's meta labels. The requirements are ANDed.
   405		// Empty or nil map matches all pod monitors.
   406		// +optional
   407		PodMonitorSelector map[string]string `json:"podMo  …(+808 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,180p' cmd/otel-allocator/internal/watcher/promOperator.go"`
```
// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/blang/semver/v4"
	"github.com/go-logr/logr"
	promMonitoring "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	promv1alpha1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1alpha1"
	"github  …(+7589 more chars)
```
**→ shell:** `/bin/bash -lc 'rg -n "SecretNamespaces|secretNamespaces|secret_namespaces|SecretNamespace|secret namespace"'`
```
tests/e2e-targetallocator/targetallocator-prometheuscr-secrets/00-install.yaml:79:      secretNamespaces:
config/crd/bases/opentelemetry.io_targetallocators.yaml:2664:                  secretNamespaces:
config/crd/bases/opentelemetry.io_opentelemetrycollectors.yaml:8474:                      secretNamespaces:
CHANGELOG.md:18:- `target allocator`: Add `secretNamespaces` field to PrometheusCR configuration to make the namespaces watched for secrets configurable instead of hardcoding to the collect  …(+123 more chars)
```
**Codex:** There’s a helper that already defaults secret access to the allocator namespace when `secretNamespaces` is absent. The likely remediation is to remove the user-facing/API and ConfigMap field, and keep that default internally so secret informer behavior stays bounded.

**→ shell:** `/bin/bash -lc "sed -n '450,510p' cmd/otel-allocator/internal/config/config.go"`
```
		ClientAuth: tls.RequestClientCert,
		MinVersion: tls.VersionTLS12,
		// Use VerifyConnection for dynamic CA pool access
		// This allows the CA pool to be reloaded at runtime
		VerifyConnection: func(cs tls.ConnectionState) error {
			// Require client certificate
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no client certificate provided")
			}

			// Verify using current CA pool (which can be reloaded)
			opts := x509.VerifyOptions{
				Roots:         caReloader.GetClientCAs(  …(+1540 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '880,955p' cmd/otel-allocator/internal/config/config_test.go"`
```
		},
		{
			name:              "deny namespaces",
			promCRConfig:      PrometheusCRConfig{Enabled: true, DenyNamespaces: []string{"ns2"}},
			expectedAllowList: map[string]struct{}{v1.NamespaceAll: {}},
			expectedDenyList:  map[string]struct{}{"ns2": {}},
		},
		{
			name:              "both allow and deny namespaces",
			promCRConfig:      PrometheusCRConfig{Enabled: true, AllowNamespaces: []string{"ns1"}, DenyNamespaces: []string{"ns2"}},
			expectedAllowList: map[string]struct{}{"ns1": {}},  …(+2428 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"prometheus_cr:|secret_namespaces|secretNamespaces\" internal cmd tests apis config/crd bundle docs -g '*.go' -g '*.yaml' -g '*.md'"`
```
config/crd/bases/opentelemetry.io_targetallocators.yaml:2664:                  secretNamespaces:
config/crd/bases/opentelemetry.io_opentelemetrycollectors.yaml:8474:                      secretNamespaces:
docs/api/targetallocators.md:10488:        <td><b>secretNamespaces</b></td>
docs/api/opentelemetrycollectors.md:34983:        <td><b>secretNamespaces</b></td>

```
**Codex:** This is an API-surface change, so I’ll update the Go API types and the generated manifests/docs that publish that field. I’ll avoid touching unrelated generated content.

**→ shell:** `/bin/bash -lc 'rg -n "type OpenTelemetryTargetAllocator|PrometheusCR" apis/v1alpha1/opentelemetrycollector_types.go apis/v1beta1/*.go internal/manifests/targetallocator/configmap_test.go cmd/otel-allo  …(+37 more chars)`
```
apis/v1alpha1/opentelemetrycollector_types.go:309:type OpenTelemetryTargetAllocator struct {
apis/v1alpha1/opentelemetrycollector_types.go:347:	// PrometheusCR defines the configuration for the retrieval of PrometheusOperator CRDs ( servicemonitor.monitoring.coreos.com/v1 and podmonitor.monitoring.coreos.com/v1 )  retrieval.
apis/v1alpha1/opentelemetrycollector_types.go:350:	PrometheusCR OpenTelemetryTargetAllocatorPrometheusCR `json:"prometheusCR,omitempty"`
apis/v1alpha1/opentelemetrycollector  …(+6698 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '70,95p' tests/e2e-targetallocator/targetallocator-prometheuscr-secrets/00-install.yaml"`
```
          receivers: [prometheus]
          exporters: [prometheus, debug]
  mode: statefulset
  serviceAccount: collector
  targetAllocator:
    enabled: true
    prometheusCR:
      enabled: true
      scrapeInterval: 1s
      secretNamespaces:
      - ($namespace)
      serviceMonitorSelector: {}
      podMonitorSelector: {}
    serviceAccount: ta

```
**→ shell:** `/bin/bash -lc "sed -n '120,170p' internal/manifests/targetallocator/configmap_test.go; sed -n '210,250p' internal/manifests/targetallocator/configmap_test.go; sed -n '300,330p' internal/manifests/targ  …(+30 more chars)`
```
		expectedData := map[string]string{
			targetAllocatorFilename: `allocation_strategy: consistent-hashing
collector_selector:
  matchlabels:
    app.kubernetes.io/component: opentelemetry-collector
    app.kubernetes.io/instance: default.my-instance
    app.kubernetes.io/managed-by: opentelemetry-operator
    app.kubernetes.io/part-of: opentelemetry
  matchexpressions: []
config:
  global:
    scrape_interval: 30s
    scrape_protocols:
    - PrometheusProto
    - OpenMetricsText1.0.0
    - OpenM  …(+2850 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '990,1030p;1085,1110p;1150,1175p' cmd/otel-allocator/internal/config/config_test.go"`
```
			"--" + kubeConfigPathFlagName + "=" + kubeConfigPath,
		}

		// Load config using the full Load function
		config, err := Load(args)
		require.NoError(t, err)

		// Assert defaults are used
		assert.Equal(t, DefaultListenAddr, config.ListenAddr)
		assert.Equal(t, kubeConfigPath, config.KubeConfigFilePath)
		assert.Equal(t, DefaultHttpsListenAddr, config.HTTPS.ListenAddr)
		assert.Equal(t, DefaultAllocationStrategy, config.AllocationStrategy)
		assert.Equal(t, DefaultFilterStrategy, config.Fil  …(+2691 more chars)
```
**Codex:** I’m going to remove the configurable secret namespace list from the public TargetAllocator Prometheus CR config and from the allocator YAML config, then keep the watcher scoped to the allocator namespace via the existing helper.

**✎ files:** update `/work/apis/v1beta1/targetallocator_types.go`, update `/work/cmd/otel-allocator/internal/config/config.go`, update `/work/cmd/otel-allocator/internal/config/config_test.go`, update `/work/cmd/otel-allocator/internal/watcher/promOperator.go`, update `/work/internal/manifests/targetallocator/configmap.go`, update `/work/tests/e2e-targetallocator/targetallocator-prometheuscr-secrets/00-install.yaml`

**→ shell:** `/bin/bash -lc 'gofmt -w apis/v1beta1/targetallocator_types.go cmd/otel-allocator/internal/config/config.go cmd/otel-allocator/internal/config/config_test.go cmd/otel-allocator/internal/watcher/promOpe  …(+57 more chars)`
```
/bin/bash: line 1: gofmt: command not found

```
**→ shell:** `/bin/bash -lc 'rg -n "SecretNamespaces|secretNamespaces|secret_namespaces"'`
```
CHANGELOG.md:18:- `target allocator`: Add `secretNamespaces` field to PrometheusCR configuration to make the namespaces watched for secrets configurable instead of hardcoding to the collector namespace. (#4999)
CHANGELOG.md:21:  for secrets can be explicitly configured via `spec.prometheusCR.secretNamespaces`.
config/crd/bases/opentelemetry.io_targetallocators.yaml:2664:                  secretNamespaces:
config/crd/bases/opentelemetry.io_opentelemetrycollectors.yaml:8474:                      s  …(+191 more chars)
```
**Codex:** `gofmt` is not installed in this environment, so I can’t run the normal formatter locally. I’m continuing with focused text updates and will call that out in the verification results.

**→ shell:** `/bin/bash -lc 'which go || true; which gofmt || true; go version || true'`
```
/bin/bash: line 1: go: command not found

```
**→ shell:** `/bin/bash -lc 'git diff -- apis/v1beta1/targetallocator_types.go cmd/otel-allocator/internal/config/config.go cmd/otel-allocator/internal/config/config_test.go cmd/otel-allocator/internal/watcher/prom  …(+139 more chars)`
```
diff --git a/apis/v1beta1/targetallocator_types.go b/apis/v1beta1/targetallocator_types.go
index d0065a3..2f5253e 100644
--- a/apis/v1beta1/targetallocator_types.go
+++ b/apis/v1beta1/targetallocator_types.go
@@ -18,10 +18,6 @@ type TargetAllocatorPrometheusCR struct {
 	// DenyNamespaces Namespaces to scope the interaction of the Target Allocator and the apiserver (deny list). This is mutually exclusive with AllowNamespaces.
 	// +optional
 	DenyNamespaces []string `json:"denyNamespaces,omitemp  …(+6015 more chars)
```
**Codex:** Because Go tooling is absent, generated files won’t refresh automatically. I’m applying the minimal generated-output edits needed to keep the tree consistent with the source API removal.

**→ shell:** `/bin/bash -lc "nl -ba apis/v1beta1/zz_generated.deepcopy.go | sed -n '848,868p'"`
```
   848	func (in *TargetAllocatorPrometheusCR) DeepCopyInto(out *TargetAllocatorPrometheusCR) {
   849		*out = *in
   850		if in.AllowNamespaces != nil {
   851			in, out := &in.AllowNamespaces, &out.AllowNamespaces
   852			*out = make([]string, len(*in))
   853			copy(*out, *in)
   854		}
   855		if in.DenyNamespaces != nil {
   856			in, out := &in.DenyNamespaces, &out.DenyNamespaces
   857			*out = make([]string, len(*in))
   858			copy(*out, *in)
   859		}
   860		if in.SecretNamespaces != n  …(+302 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba config/crd/bases/opentelemetry.io_targetallocators.yaml | sed -n '2656,2674p'; nl -ba config/crd/bases/opentelemetry.io_opentelemetrycollectors.yaml | sed -n '8466,8485p'"`
```
  2656	                  scrapeInterval:
  2657	                    default: 30s
  2658	                    format: duration
  2659	                    type: string
  2660	                  scrapeProtocols:
  2661	                    items:
  2662	                      type: string
  2663	                    type: array
  2664	                  secretNamespaces:
  2665	                    items:
  2666	                      type: string
  2667	                    type: array
  2668	               …(+1202 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba bundle/community/manifests/opentelemetry.io_targetallocators.yaml | sed -n '2658,2675p'; nl -ba bundle/community/manifests/opentelemetry.io_opentelemetrycollectors.yaml | sed -n   …(+212 more chars)`
```
  2658	                  scrapeInterval:
  2659	                    default: 30s
  2660	                    format: duration
  2661	                    type: string
  2662	                  scrapeProtocols:
  2663	                    items:
  2664	                      type: string
  2665	                    type: array
  2666	                  secretNamespaces:
  2667	                    items:
  2668	                      type: string
  2669	                    type: array
  2670	               …(+2628 more chars)
```
**→ shell:** `/bin/bash -lc "nl -ba docs/api/targetallocators.md | sed -n '10480,10498p'; nl -ba docs/api/opentelemetrycollectors.md | sed -n '34975,34993p'"`
```
 10480	        <td><b>scrapeProtocols</b></td>
 10481	        <td>[]string</td>
 10482	        <td>
 10483	          ScrapeProtocols define the protocols to negotiate during a scrape. It tells clients the
 10484	protocols supported by Prometheus in order of preference (from most to least preferred).<br/>
 10485	        </td>
 10486	        <td>false</td>
 10487	      </tr><tr>
 10488	        <td><b>secretNamespaces</b></td>
 10489	        <td>[]string</td>
 10490	        <td>
 10491	          Se  …(+1386 more chars)
```
**Codex:** I found the stale schema/docs entries. I’m removing just the `secretNamespaces` blocks and the stale deepcopy copy branch.

**✎ files:** update `/work/apis/v1beta1/zz_generated.deepcopy.go`, update `/work/bundle/community/manifests/opentelemetry.io_opentelemetrycollectors.yaml`, update `/work/bundle/community/manifests/opentelemetry.io_targetallocators.yaml`, update `/work/bundle/openshift/manifests/opentelemetry.io_opentelemetrycollectors.yaml`, update `/work/bundle/openshift/manifests/opentelemetry.io_targetallocators.yaml`, update `/work/config/crd/bases/opentelemetry.io_opentelemetrycollectors.yaml`, update `/work/config/crd/bases/opentelemetry.io_targetallocators.yaml`, update `/work/docs/api/opentelemetrycollectors.md`, update `/work/docs/api/targetallocators.md`

**→ shell:** `/bin/bash -lc "sed -n '900,945p' cmd/otel-allocator/internal/config/config_test.go; sed -n '476,494p' cmd/otel-allocator/internal/config/config.go"`
```
		})
	}
}

func TestGetSecretsAllowList(t *testing.T) {
	testCases := []struct {
		name                     string
		promCRConfig             PrometheusCRConfig
		collectorNamespace       string
		expectedSecretsAllowList map[string]struct{}
	}{
		{
			name:                     "no secrets namespaces configured, defaults to collector namespace",
			promCRConfig:             PrometheusCRConfig{Enabled: true},
			collectorNamespace:       "ta-namespace",
			expectedSecretsAllowList: map[string]str  …(+1657 more chars)
```
**→ shell:** `/bin/bash -lc 'rg -n "SecretNamespaces|secretNamespaces|secret_namespaces"'`
```
CHANGELOG.md:18:- `target allocator`: Add `secretNamespaces` field to PrometheusCR configuration to make the namespaces watched for secrets configurable instead of hardcoding to the collector namespace. (#4999)
CHANGELOG.md:21:  for secrets can be explicitly configured via `spec.prometheusCR.secretNamespaces`.

```
**→ shell:** `/bin/bash -lc 'git diff --stat && git diff --check'`
```
 apis/v1beta1/targetallocator_types.go                      |  4 ----
 apis/v1beta1/zz_generated.deepcopy.go                      |  5 -----
 .../opentelemetry.io_opentelemetrycollectors.yaml          |  4 ----
 .../manifests/opentelemetry.io_targetallocators.yaml       |  4 ----
 .../opentelemetry.io_opentelemetrycollectors.yaml          |  4 ----
 .../manifests/opentelemetry.io_targetallocators.yaml       |  4 ----
 cmd/otel-allocator/internal/config/config.go               | 10 ++--------
 cm  …(+628 more chars)
```
**Codex:** The active code/schema references are gone; only the historical changelog still mentions the removed field. I’m checking whitespace and then I’ll run the narrow tests that don’t require a full cluster, if the available toolchain allows it.

**Codex:** Whitespace checks passed. The Go toolchain is missing, so I can’t compile or regenerate; I’m doing static consistency checks across API, config generation, and CRD artifacts instead.

**→ shell:** `/bin/bash -lc "sed -n '10478,10492p' docs/api/targetallocators.md; sed -n '34973,34987p' docs/api/opentelemetrycollectors.md"`
```
        <td>false</td>
      </tr><tr>
        <td><b>scrapeProtocols</b></td>
        <td>[]string</td>
        <td>
          ScrapeProtocols define the protocols to negotiate during a scrape. It tells clients the
protocols supported by Prometheus in order of preference (from most to least preferred).<br/>
        </td>
        <td>false</td>
      </tr><tr>
        <td><b><a href="#targetallocatorspecprometheuscrservicemonitornamespaceselector">serviceMonitorNamespaceSelector</a></b></td>
     …(+900 more chars)
```
**→ shell:** `/bin/bash -lc 'git diff -- apis/v1beta1/zz_generated.deepcopy.go apis/v1beta1/targetallocator_types.go cmd/otel-allocator/internal/config/config.go internal/manifests/targetallocator/configmap.go'`
```
diff --git a/apis/v1beta1/targetallocator_types.go b/apis/v1beta1/targetallocator_types.go
index d0065a3..2f5253e 100644
--- a/apis/v1beta1/targetallocator_types.go
+++ b/apis/v1beta1/targetallocator_types.go
@@ -18,10 +18,6 @@ type TargetAllocatorPrometheusCR struct {
 	// DenyNamespaces Namespaces to scope the interaction of the Target Allocator and the apiserver (deny list). This is mutually exclusive with AllowNamespaces.
 	// +optional
 	DenyNamespaces []string `json:"denyNamespaces,omitemp  …(+3643 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '2658,2670p' config/crd/bases/opentelemetry.io_targetallocators.yaml; sed -n '8468,8480p' config/crd/bases/opentelemetry.io_opentelemetrycollectors.yaml"`
```
                    format: duration
                    type: string
                  scrapeProtocols:
                    items:
                      type: string
                    type: array
                  serviceMonitorNamespaceSelector:
                    default: {}
                    properties:
                      matchExpressions:
                        items:
                          properties:
                            key:
                        format: duration
     …(+464 more chars)
```
**→ shell:** `/bin/bash -lc "rg -n \"SecretNamespaces|secretNamespaces|secret_namespaces\" apis cmd internal config bundle docs tests -g '"'!CHANGELOG.md'"'"`
**Codex:** Static search confirms the removed config key is no longer present in API/config/manifests/docs/tests, excluding the historical changelog. I’m doing one final repository status check and an attempted narrow test command to document the environment limitation.

**→ shell:** `/bin/bash -lc 'make test'`
```
make: go: No such file or directory
/bin/sh: 1: go: not found
Installing gotest.tools/gotestsum@v1.13.0 -> /work/bin/gotestsum
make: *** [Makefile:780: gotestsum] Error 127

```
**→ shell:** `/bin/bash -lc 'git diff --check'`
**→ shell:** `/bin/bash -lc 'git status --short'`
```
 M apis/v1beta1/targetallocator_types.go
 M apis/v1beta1/zz_generated.deepcopy.go
 M bundle/community/manifests/opentelemetry.io_opentelemetrycollectors.yaml
 M bundle/community/manifests/opentelemetry.io_targetallocators.yaml
 M bundle/openshift/manifests/opentelemetry.io_opentelemetrycollectors.yaml
 M bundle/openshift/manifests/opentelemetry.io_targetallocators.yaml
 M cmd/otel-allocator/internal/config/config.go
 M cmd/otel-allocator/internal/config/config_test.go
 M cmd/otel-allocator/inter  …(+357 more chars)
```
**→ shell:** `/bin/bash -lc "sed -n '1,35p' CHANGELOG.md"`
```
# Changes by Version

<!-- next version -->

## 0.151.0

### 🛑 Breaking changes 🛑

- `auto-instrumentation`: Update default Java auto-instrumentation version from 1.33.6 to 2.27.0 (#4996)
  This is a breaking change due to HTTP semantic convention changes between versions.
  Existing Instrumentation CRs using a 1.x.x version will NOT be automatically upgraded.
  To upgrade, manually update the image in your Instrumentation CR after reviewing the migration guide.
  See https://github.com/open-tel  …(+1396 more chars)
```
**→ shell:** `/bin/bash -lc 'ls -la .chloggen 2>/dev/null | head -40; rg -n "secretNamespaces|secret namespaces|SecretNamespaces" .chloggen CHANGELOG.md'`
```
total 32
drwxrwxrwx 10 root root  320 Jun 30 09:36 .
drwxrwxrwx 50 root root 1600 Jun 30 22:06 ..
-rw-rw-rw-  1 root root  674 Jun 30 09:36 TEMPLATE.yaml
-rw-rw-rw-  1 root root 1562 Jun 30 09:36 crds_wip.yaml
-rw-rw-rw-  1 root root  758 Jun 30 09:36 events-receiver-role.yaml
-rw-rw-rw-  1 root root  855 Jun 30 09:36 fix_jaeger-query-ext-grpc-port.yaml
-rw-rw-rw-  1 root root 1243 Jun 30 09:36 fix_preserve-telemetry-shape.yaml
-rw-rw-rw-  1 root root 1052 Jun 30 09:36 fix_ta-scrapeclass-tls-des  …(+491 more chars)
```
**Codex:** The remaining mention is in the current 0.151.0 changelog as an enhancement entry for the now-removed field, so I’m removing that stale release-note text too.

**✎ files:** update `/work/CHANGELOG.md`, update `/work/cmd/otel-allocator/internal/config/config_test.go`

**→ shell:** `/bin/bash -lc "sed -n '60,85p' cmd/otel-allocator/internal/watcher/promOperator.go; sed -n '904,934p' cmd/otel-allocator/internal/config/config_test.go"`
```
	if err != nil {
		return nil, err
	}
	allowList, denyList := cfg.PrometheusCR.GetAllowDenyLists()

	monitoringInformerFactory := informers.NewMonitoringInformerFactories(allowList, denyList, monitoringclient, allocatorconfig.DefaultResyncTime, nil)

	// Scope the metadata informer factory to the target allocator namespace for secrets access.
	// This avoids requiring cluster-wide secrets list/watch RBAC.
	secretsAllowList := cfg.PrometheusCR.GetSecretsAllowList(cfg.CollectorNamespace)
	metaData  …(+1875 more chars)
```
**→ shell:** `/bin/bash -lc 'rg -n "SecretNamespaces|secretNamespaces|secret_namespaces"'`
**→ shell:** `/bin/bash -lc 'git diff --check && git status --short && git diff --stat'`
```
 M CHANGELOG.md
 M apis/v1beta1/targetallocator_types.go
 M apis/v1beta1/zz_generated.deepcopy.go
 M bundle/community/manifests/opentelemetry.io_opentelemetrycollectors.yaml
 M bundle/community/manifests/opentelemetry.io_targetallocators.yaml
 M bundle/openshift/manifests/opentelemetry.io_opentelemetrycollectors.yaml
 M bundle/openshift/manifests/opentelemetry.io_targetallocators.yaml
 M cmd/otel-allocator/internal/config/config.go
 M cmd/otel-allocator/internal/config/config_test.go
 M cmd/otel  …(+1543 more chars)
```
**Codex:** One config test had become redundant after removing the override path, so I’m trimming that duplicate case before the final status.

**✎ files:** update `/work/cmd/otel-allocator/internal/config/config_test.go`

**Codex:** I’m running the final static checks now.

**→ shell:** `/bin/bash -lc 'git diff -- cmd/otel-allocator/internal/config/config_test.go CHANGELOG.md'`
```
diff --git a/CHANGELOG.md b/CHANGELOG.md
index 933f83b..7faefea 100644
--- a/CHANGELOG.md
+++ b/CHANGELOG.md
@@ -15,12 +15,6 @@
 
 ### 💡 Enhancements 💡
 
-- `target allocator`: Add `secretNamespaces` field to PrometheusCR configuration to make the namespaces watched for secrets configurable instead of hardcoding to the collector namespace. (#4999)
-  Previously, the Target Allocator always watched the collector namespace for secrets used in
-  ServiceMonitor/PodMonitor basicAuth and other secret  …(+1804 more chars)
```
**→ shell:** `/bin/bash -lc 'git diff --check'`
**→ shell:** `/bin/bash -lc 'git diff --stat'`
```
 CHANGELOG.md                                           |  6 ------
 apis/v1beta1/targetallocator_types.go                  |  4 ----
 apis/v1beta1/zz_generated.deepcopy.go                  |  5 -----
 .../opentelemetry.io_opentelemetrycollectors.yaml      |  4 ----
 .../manifests/opentelemetry.io_targetallocators.yaml   |  4 ----
 .../opentelemetry.io_opentelemetrycollectors.yaml      |  4 ----
 .../manifests/opentelemetry.io_targetallocators.yaml   |  4 ----
 cmd/otel-allocator/internal/config  …(+640 more chars)
```
**→ shell:** `/bin/bash -lc 'rg -n "SecretNamespaces|secretNamespaces|secret_namespaces"'`
**Codex:** Implemented the remediation locally.

Changed:
- Removed `secretNamespaces` / `secret_namespaces` from TargetAllocator Prometheus CR API/config surfaces.
- Stopped writing that field into the Target Allocator ConfigMap.
- Kept secret watching scoped to the Target Allocator namespace via `GetSecretsAllowList`.
- Updated tests, CRDs, bundles, API docs, and changelog text so the removed field is no longer advertised.
- Removed the stale e2e usage of `secretNamespaces`.

Verification:
- `rg "SecretNamespaces|secretNamespaces|secret_namespaces"` returns no matches.
- `git diff --check` passes.
- `make test` could not run because this environment does not have Go installed: `go: not found`. `gofmt` is also unavailable for the same reason.


---
*tokens — input 737923 (cached 646144), output 7966, reasoning 1931*
