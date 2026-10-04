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

package gatewaycommon

import (
	"path/filepath"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gateway "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/inject"
	"istio.io/istio/pkg/kube/kclient"
	"istio.io/istio/pkg/security"
	"istio.io/istio/pkg/test"
)

func TestDomainBundleNativeGatewayAndWaypointProjection(t *testing.T) {
	path := "/var/run/secrets/istio/trust-domains/spiffe-bundle-map.json"
	for _, name := range []string{"kube-gateway", "waypoint"} {
		for _, selected := range []bool{false, true} {
			t.Run(name+"/"+map[bool]string{false: "legacy", true: "mapped"}[selected], func(t *testing.T) {
				cfg := testInjectionConfig(t, "")()
				if selected {
					cfg.MeshConfig.DefaultConfig.ProxyMetadata = map[string]string{security.SPIFFEBundleMapPathEnv: path}
				}
				client := kube.NewFakeClient()
				d := &DeploymentController{configMaps: kclient.New[*corev1.ConfigMap](client), env: newTestEnv(),
					systemNamespace: "istio-system", injectConfig: func() inject.WebhookConfig { return cfg }}
				d.env.SetPushContext(&model.PushContext{ProxyConfigs: &model.ProxyConfigs{}})
				client.RunAndWait(test.NewStop(t))
				output, err := d.render(name, TemplateInput{
					Gateway:        &gateway.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "own", Namespace: "own"}, Spec: gateway.GatewaySpec{GatewayClassName: "istio"}},
					DeploymentName: "own", ServiceAccount: "own", KubeVersion: 134, ProxyUID: 1337, ProxyGID: 1337,
					GatewayClass: "istio", GatewayNameLabel: "gateway.networking.k8s.io/gateway-name", ControllerLabel: "istio.io-gateway-controller",
				})
				if err != nil {
					t.Fatal(err)
				}
				var pod *corev1.PodSpec
				for _, raw := range output {
					kind := struct{ Kind string }{}
					if err := yaml.Unmarshal([]byte(raw), &kind); err != nil {
						t.Fatal(err)
					}
					if kind.Kind == "Deployment" {
						deployment := &appsv1.Deployment{}
						if err := yaml.Unmarshal([]byte(raw), deployment); err != nil {
							t.Fatal(err)
						}
						pod = &deployment.Spec.Template.Spec
					}
				}
				if pod == nil {
					t.Fatal("native deployment controller did not render its workload")
				}
				mounts, environments, volumes := 0, 0, 0
				for _, container := range append(pod.Containers, pod.InitContainers...) {
					if container.Name != "istio-proxy" {
						continue
					}
					for _, e := range container.Env {
						if e.Name == security.SPIFFEBundleMapPathEnv {
							environments++
							if e.Value != path {
								t.Fatal("native gateway advertised a different input")
							}
						}
					}
					for _, mount := range container.VolumeMounts {
						if mount.Name == "istio-trust-domains" {
							mounts++
							if !mount.ReadOnly || filepath.Clean(mount.MountPath) != filepath.Dir(path) || mount.SubPath != "" || mount.SubPathExpr != "" {
								t.Fatal("native gateway map projection cannot observe atomic updates")
							}
						}
						if selected && mount.Name == "istio-ca-crl" && !mount.ReadOnly {
							t.Fatal("native public CRL mount is not read-only")
						}
					}
				}
				for _, volume := range pod.Volumes {
					if volume.Name == "istio-trust-domains" {
						volumes++
						cm := volume.ConfigMap
						if cm == nil || cm.Name != "istio-trust-domains" || cm.Optional == nil || !*cm.Optional || len(cm.Items) != 1 ||
							cm.Items[0].Key != "spiffe-bundle-map.json" || cm.Items[0].Path != filepath.Base(path) {
							t.Fatal("native owner/key/optional startup contract changed")
						}
					}
				}
				want := 0
				if selected {
					want = 1
				}
				if mounts != want || environments != want || volumes != want {
					t.Fatal("native gateway selected or duplicated map inconsistently")
				}
			})
		}
	}
}
