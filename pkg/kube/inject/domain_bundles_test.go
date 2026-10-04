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

package inject

import (
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"istio.io/istio/pkg/security"
	"istio.io/istio/pkg/util/protomarshal"
)

func TestDomainBundleNativeSidecarAndGatewayProjection(t *testing.T) {
	config, values, mesh := getInjectionSettings(t, nil, "")
	path := "/var/run/secrets/istio/trust-domains/spiffe-bundle-map.json"
	for _, name := range []string{SidecarTemplateName, "gateway"} {
		for _, selected := range []bool{false, true} {
			t.Run(name+"/"+map[bool]string{false: "legacy", true: "mapped"}[selected], func(t *testing.T) {
				proxy := protomarshal.Clone(mesh.DefaultConfig)
				if selected {
					proxy.ProxyMetadata = map[string]string{security.SPIFFEBundleMapPathEnv: path}
				}
				data := SidecarTemplateData{
					ObjectMeta:  metav1.ObjectMeta{Name: "own", Namespace: "own", Annotations: map[string]string{}, Labels: map[string]string{}},
					Spec:        corev1.PodSpec{ServiceAccountName: "own", SecurityContext: &corev1.PodSecurityContext{}, Containers: []corev1.Container{{Name: "application"}}},
					ProxyConfig: proxy, MeshConfig: mesh, Values: values.Map(), ProxyImage: "unchanged-proxy", ProxyInitImage: "unchanged-init", ProxyUID: 1337, ProxyGID: 1337,
				}
				template := config.Templates[name]
				if template == nil {
					t.Fatalf("native chart did not provide %s template", name)
				}
				output, err := runTemplate(template, data)
				if err != nil {
					t.Fatal(err)
				}
				pod := &corev1.Pod{}
				if err := yaml.Unmarshal(output.Bytes(), pod); err != nil {
					t.Fatal(err)
				}
				var proxyContainer *corev1.Container
				for i := range pod.Spec.Containers {
					if pod.Spec.Containers[i].Name == "istio-proxy" {
						proxyContainer = &pod.Spec.Containers[i]
					}
				}
				if proxyContainer == nil {
					t.Fatal("native proxy container missing")
				}
				mounts, environments, volumes := 0, 0, 0
				for _, e := range proxyContainer.Env {
					if e.Name == security.SPIFFEBundleMapPathEnv {
						environments++
						if e.Value != path {
							t.Fatal("template declared a different map input")
						}
					}
				}
				for _, mount := range proxyContainer.VolumeMounts {
					if mount.Name == "istio-trust-domains" {
						mounts++
						if !mount.ReadOnly || filepath.Clean(mount.MountPath) != filepath.Dir(path) || mount.SubPath != "" || mount.SubPathExpr != "" {
							t.Fatal("map projection does not observe native atomic directory updates")
						}
					}
					if selected && mount.Name == "istio-ca-crl" && !mount.ReadOnly {
						t.Fatal("native public CRL mount is not read-only")
					}
				}
				for _, volume := range pod.Spec.Volumes {
					if volume.Name == "istio-trust-domains" {
						volumes++
						cm := volume.ConfigMap
						if cm == nil || cm.Name != "istio-trust-domains" || cm.Optional == nil || !*cm.Optional || len(cm.Items) != 1 ||
							cm.Items[0].Key != "spiffe-bundle-map.json" || cm.Items[0].Path != filepath.Base(path) {
							t.Fatal("native map owner/key/optional startup contract changed")
						}
					}
				}
				want := 0
				if selected {
					want = 1
				}
				if mounts != want || environments != want || volumes != want {
					t.Fatal("map selected inconsistently or duplicated in native template")
				}
			})
		}
	}
}
