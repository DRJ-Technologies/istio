// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package helm

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"helm.sh/helm/v4/pkg/chart/common"
	commonutil "helm.sh/helm/v4/pkg/chart/common/util"
	"helm.sh/helm/v4/pkg/engine"
	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/yaml"

	"istio.io/istio/istioctl/pkg/install/k8sversion"
	"istio.io/istio/manifests"
	"istio.io/istio/operator/pkg/manifest"
	operatortest "istio.io/istio/operator/pkg/test"
	"istio.io/istio/operator/pkg/util"
	"istio.io/istio/operator/pkg/values"
	tutil "istio.io/istio/pilot/test/util"
	"istio.io/istio/pkg/test/util/yml"
)

type testCase struct {
	desc        string
	releaseName string
	namespace   string
	chartName   string
	diffSelect  string
	isUpgrade   bool
}

func renderWithOptions(releaseName, namespace, directory string, iop values.Map, isUpgrade bool) ([]manifest.Manifest, util.Errors, error) {
	vals, _ := iop.GetPathMap("spec.values")
	installPackagePath := iop.GetPathString("spec.installPackagePath")
	f := manifests.BuiltinOrDir(installPackagePath)
	path := pathJoin("charts", directory)
	chrt, err := loadChart(f, path)
	if err != nil {
		return nil, nil, fmt.Errorf("load chart: %v", err)
	}

	options := common.ReleaseOptions{
		Name:      releaseName,
		Namespace: namespace,
		IsUpgrade: isUpgrade,
		IsInstall: !isUpgrade,
	}

	caps := *common.DefaultCapabilities
	operatorVersion, _ := common.ParseKubeVersion("1." + strconv.Itoa(k8sversion.MinK8SVersion) + ".0")
	caps.KubeVersion = *operatorVersion

	helmVals, err := commonutil.ToRenderValues(chrt, vals, options, &caps)
	if err != nil {
		return nil, nil, fmt.Errorf("converting values: %v", err)
	}

	files, err := engine.Render(chrt, helmVals)
	if err != nil {
		return nil, nil, err
	}

	var warnings Warnings
	keys := make([]string, 0, len(files))
	for k, v := range files {
		if strings.HasSuffix(k, NotesFileNameSuffix) {
			warnings = extractWarnings(v)
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	results := make([]string, 0, len(keys))
	for _, k := range keys {
		results = append(results, yml.SplitString(files[k])...)
	}

	mfs, err := manifest.Parse(results)
	return mfs, warnings, err
}

func TestRender(t *testing.T) {
	cases := []testCase{
		{
			desc:        "gateway-deployment",
			releaseName: "istio-ingress",
			namespace:   "istio-ingress",
			chartName:   "gateway",
			diffSelect:  "Deployment:*:istio-ingress",
		},
		{
			desc:        "gateway-env-var-from",
			releaseName: "istio-ingress",
			namespace:   "istio-ingress",
			chartName:   "gateway",
			diffSelect:  "Deployment:*:istio-ingress",
		},
		{
			desc:        "gateway-additional-containers",
			releaseName: "istio-ingress",
			namespace:   "istio-ingress",
			chartName:   "gateway",
			diffSelect:  "Deployment:*:istio-ingress",
		},
		{
			desc:        "gateway-init-containers",
			releaseName: "istio-ingress",
			namespace:   "istio-ingress",
			chartName:   "gateway",
			diffSelect:  "Deployment:*:istio-ingress",
		},
		{
			desc:        "gateway-service-selector-labels",
			releaseName: "istio-ingress",
			namespace:   "istio-ingress",
			chartName:   "gateway",
			diffSelect:  "Service:*:istio-ingress",
		},
		{
			desc:        "istiod-traffic-distribution",
			releaseName: "istiod",
			namespace:   "istio-system",
			chartName:   "istio-control/istio-discovery",
			diffSelect:  "Service:*:istiod",
		},
		{
			desc:        "istiod-pdb-default",
			releaseName: "istiod",
			namespace:   "istio-system",
			chartName:   "istio-control/istio-discovery",
			diffSelect:  "PodDisruptionBudget:*:istiod",
		},
		{
			desc:        "istiod-pdb-max-unavailable",
			releaseName: "istiod",
			namespace:   "istio-system",
			chartName:   "istio-control/istio-discovery",
			diffSelect:  "PodDisruptionBudget:*:istiod",
		},
		{
			desc:        "istiod-pdb-unhealthy-pod-eviction-policy",
			releaseName: "istiod",
			namespace:   "istio-system",
			chartName:   "istio-control/istio-discovery",
			diffSelect:  "PodDisruptionBudget:*:istiod",
		},
		{
			desc:        "istiod-pdb-2replicas",
			releaseName: "istiod",
			namespace:   "istio-system",
			chartName:   "istio-control/istio-discovery",
			diffSelect:  "PodDisruptionBudget:*:istiod",
		},
		{
			desc:        "istiod-pdb-autoscaleMin2",
			releaseName: "istiod",
			namespace:   "istio-system",
			chartName:   "istio-control/istio-discovery",
			diffSelect:  "PodDisruptionBudget:*:istiod",
		},
		{
			desc:        "gateway-pdb-default",
			releaseName: "istio-ingress",
			namespace:   "istio-ingress",
			chartName:   "gateway",
			diffSelect:  "PodDisruptionBudget:*:istio-ingress",
		},
		{
			desc:        "gateway-pdb-2replicas",
			releaseName: "istio-ingress",
			namespace:   "istio-ingress",
			chartName:   "gateway",
			diffSelect:  "PodDisruptionBudget:*:istio-ingress",
		},
		{
			desc:        "gateway-pdb-autoscaleMin2",
			releaseName: "istio-ingress",
			namespace:   "istio-ingress",
			chartName:   "gateway",
			diffSelect:  "PodDisruptionBudget:*:istio-ingress",
		},
		{
			desc:        "gateway-service-default",
			releaseName: "istio-ingress",
			namespace:   "istio-ingress",
			chartName:   "gateway",
			diffSelect:  "Service:*:istio-ingress",
		},
		{
			desc:        "gateway-network-gateway-default",
			releaseName: "istio-eastwest",
			namespace:   "istio-system",
			chartName:   "gateway",
			diffSelect:  "Service:*:istio-eastwest",
		},
		{
			desc:        "gateway-network-gateway-port-override",
			releaseName: "istio-eastwest",
			namespace:   "istio-system",
			chartName:   "gateway",
			diffSelect:  "Service:*:istio-eastwest",
		},
		{
			desc:        "gateway-dns-config",
			releaseName: "istio-ingress",
			namespace:   "istio-ingress",
			chartName:   "gateway",
			diffSelect:  "Deployment:*:istio-ingress",
		},
		{
			desc:        "ztunnel-dns-config",
			releaseName: "ztunnel",
			namespace:   "istio-system",
			chartName:   "ztunnel",
			diffSelect:  "DaemonSet:*:ztunnel",
		},
		{
			desc:        "istiod-webhook-install",
			releaseName: "istiod",
			namespace:   "istio-system",
			chartName:   "istio-control/istio-discovery",
			diffSelect:  "ValidatingWebhookConfiguration:*:istio-validator-istio-system",
		},
		{
			desc:        "istiod-webhook-upgrade",
			releaseName: "istiod",
			namespace:   "istio-system",
			chartName:   "istio-control/istio-discovery",
			diffSelect:  "ValidatingWebhookConfiguration:*:istio-validator-istio-system",
			isUpgrade:   true,
		},
		{
			desc:        "istiod-webhook-failure-policy",
			releaseName: "istiod",
			namespace:   "istio-system",
			chartName:   "istio-control/istio-discovery",
			diffSelect:  "ValidatingWebhookConfiguration:*:istio-validator-istio-system",
		},
		{
			desc:        "istiod-webhook-upgrade-failure-policy",
			releaseName: "istiod",
			namespace:   "istio-system",
			chartName:   "istio-control/istio-discovery",
			diffSelect:  "ValidatingWebhookConfiguration:*:istio-validator-istio-system",
			isUpgrade:   true,
		},
		{
			desc:        "base-webhook-install",
			releaseName: "istio-base",
			namespace:   "istio-system",
			chartName:   "base",
			diffSelect:  "ValidatingWebhookConfiguration:*:istiod-default-validator",
		},
		{
			desc:        "base-webhook-upgrade",
			releaseName: "istio-base",
			namespace:   "istio-system",
			chartName:   "base",
			diffSelect:  "ValidatingWebhookConfiguration:*:istiod-default-validator",
			isUpgrade:   true,
		},
		{
			desc:        "base-webhook-failure-policy",
			releaseName: "istio-base",
			namespace:   "istio-system",
			chartName:   "base",
			diffSelect:  "ValidatingWebhookConfiguration:*:istiod-default-validator",
		},
		{
			desc:        "base-webhook-upgrade-failure-policy",
			releaseName: "istio-base",
			namespace:   "istio-system",
			chartName:   "base",
			diffSelect:  "ValidatingWebhookConfiguration:*:istiod-default-validator",
			isUpgrade:   true,
		},
		{
			desc:        "istiod-webhook-upgrade-ignore",
			releaseName: "istiod",
			namespace:   "istio-system",
			chartName:   "istio-control/istio-discovery",
			diffSelect:  "ValidatingWebhookConfiguration:*:istio-validator-istio-system",
			isUpgrade:   true,
		},
		{
			desc:        "base-webhook-upgrade-ignore",
			releaseName: "istio-base",
			namespace:   "istio-system",
			chartName:   "base",
			diffSelect:  "ValidatingWebhookConfiguration:*:istiod-default-validator",
			isUpgrade:   true,
		},
		{
			desc:        "istiod-webhook-cabundle-policy",
			releaseName: "istiod",
			namespace:   "istio-system",
			chartName:   "istio-control/istio-discovery",
			diffSelect:  "ValidatingWebhookConfiguration:*:istio-validator-istio-system",
		},
		{
			desc:        "base-webhook-cabundle-policy",
			releaseName: "istio-base",
			namespace:   "istio-system",
			chartName:   "base",
			diffSelect:  "ValidatingWebhookConfiguration:*:istiod-default-validator",
		},
		{
			desc:        "default-webhook-failure-policy",
			releaseName: "istiod",
			namespace:   "istio-system",
			chartName:   "default",
			diffSelect:  "ValidatingWebhookConfiguration:*:istiod-default-validator",
		},
		{
			desc:        "default-webhook-upgrade",
			releaseName: "istiod",
			namespace:   "istio-system",
			chartName:   "default",
			diffSelect:  "ValidatingWebhookConfiguration:*:istiod-default-validator",
			isUpgrade:   true,
		},
		{
			desc:        "istiod-waypoint-workload-socket",
			releaseName: "istiod",
			namespace:   "istio-system",
			chartName:   "istio-control/istio-discovery",
			diffSelect:  "ConfigMap:*:istio-sidecar-injector",
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			inPath := filepath.Join("testdata", "input", tc.desc+".yaml")
			data, err := os.ReadFile(inPath)
			if err != nil {
				require.NoError(t, err)
			}
			var vals values.Map
			if err := yaml.Unmarshal(data, &vals); err != nil {
				t.Fatalf("error %s: %s", err, inPath)
			}
			m, _, err := renderWithOptions(tc.releaseName, tc.namespace, tc.chartName, vals, tc.isUpgrade)
			require.NoError(t, err)

			b := strings.Builder{}
			for _, mf := range m {
				b.WriteString(mf.Content)
				b.WriteString("\n---\n") // yaml separator
			}
			got := b.String()
			if len(tc.diffSelect) > 0 {
				got = operatortest.FilterManifest(t, got, tc.diffSelect)
			}

			if len(tc.diffSelect) == 0 {
				t.Skip("skipping test that has no diff select")
			}

			outPath := filepath.Join("testdata", "output", tc.desc+".golden.yaml")
			tutil.RefreshGoldenFile(t, []byte(got), outPath)

			want := string(tutil.ReadFile(t, outPath))
			if got != want {
				t.Fatal(cmp.Diff(got, want))
			}
		})
	}
}

func TestZtunnelTrustDomainsMount(t *testing.T) {
	for _, tc := range []struct {
		name string
		want string
	}{
		{want: "istio-trust-domains"},
		{name: "peer-trust-domains", want: "peer-trust-domains"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			iop := values.Map{"spec": map[string]any{"values": map[string]any{
				"trustDomainsConfigMapName": tc.name,
			}}}
			mfs, _, err := renderWithOptions("ztunnel", "istio-system", "ztunnel", iop, false)
			require.NoError(t, err)
			var ds appsv1.DaemonSet
			found := false
			for _, mf := range mfs {
				if mf.GetKind() == "DaemonSet" {
					require.NoError(t, yaml.Unmarshal([]byte(mf.Content), &ds))
					found = true
				}
			}
			require.True(t, found)
			foundVolume, foundMount, foundPath := false, false, false
			for _, v := range ds.Spec.Template.Spec.Volumes {
				if v.Name == "trust-domains" {
					require.NotNil(t, v.ConfigMap)
					require.Equal(t, tc.want, v.ConfigMap.Name)
					require.NotNil(t, v.ConfigMap.Optional)
					require.True(t, *v.ConfigMap.Optional)
					foundVolume = true
				}
			}
			for _, c := range ds.Spec.Template.Spec.Containers {
				if c.Name != "istio-proxy" {
					continue
				}
				for _, v := range c.VolumeMounts {
					if v.Name == "trust-domains" {
						require.Equal(t, "/var/run/secrets/istio/trust-domains", v.MountPath)
						require.True(t, v.ReadOnly)
						require.Empty(t, v.SubPath) // Projected updates must remain visible.
						foundMount = true
					}
				}
				for _, e := range c.Env {
					if e.Name == "TRUST_DOMAINS_PATH" {
						require.Equal(t, "/var/run/secrets/istio/trust-domains/trust-domains", e.Value)
						foundPath = true
					}
				}
			}
			require.True(t, foundVolume && foundMount && foundPath)
		})
	}
}
