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

package bootstrap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/keycertbundle"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/aggregate"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller"
	tb "istio.io/istio/pilot/pkg/trustbundle"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/mesh/meshwatcher"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/env"
	"istio.io/istio/pkg/test/util/assert"
	"istio.io/istio/pkg/test/util/retry"
	"istio.io/istio/pkg/testcerts"
	"istio.io/istio/security/pkg/pki/ca"
	"istio.io/istio/security/pkg/pki/ra"
	"istio.io/istio/security/pkg/pki/util"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestWorkloadDomainBundleBootstrapWithoutPCDS(t *testing.T) {
	test.SetForTest(t, &features.MultiRootMesh, false)
	root, err := readSampleCertFromFile("root-cert.pem")
	assert.NoError(t, err)
	signing, err := readSampleCertFromFile("ca-cert.pem")
	assert.NoError(t, err)
	key, err := readSampleCertFromFile("ca-key.pem")
	assert.NoError(t, err)
	for _, source := range []string{"CA", "RA"} {
		t.Run(source, func(t *testing.T) {
			watcher := meshwatcher.NewTestWatcher(&meshconfig.MeshConfig{TrustDomain: "local.example"})
			s := &Server{environment: model.NewEnvironment(), workloadTrustBundle: tb.NewTrustBundle(nil, watcher), istiodCertBundleWatcher: keycertbundle.NewWatcher()}
			s.environment.Watcher = watcher
			s.environment.ServiceDiscovery = aggregate.NewController(aggregate.Options{})
			// This authenticates a custom DNS endpoint and is NOT a workload anchor.
			s.istiodCertBundleWatcher.SetAndNotify(nil, nil, testcerts.CACert)
			if source == "CA" {
				s.CA, err = ca.NewIstioCA(&ca.IstioCAOptions{KeyCertBundle: util.NewKeyCertBundleFromPem(signing, key, signing, root, nil), DefaultCertTTL: time.Hour, MaxCertTTL: time.Hour})
			} else {
				s.RA, err = ra.NewKubernetesRA(&ra.IstioRAOptions{CaCertFile: filepath.Join(env.IstioSrc, "samples/certs/root-cert.pem"), CaSigner: "example.com/signer"})
			}
			assert.NoError(t, err)
			assert.NoError(t, s.initWorkloadTrustBundle(&PilotArgs{Namespace: "istio-system"}))
			var doc struct {
				TrustDomains map[string]json.RawMessage `json:"trust_domains"`
			}
			assert.NoError(t, json.Unmarshal(s.workloadTrustBundle.GetDomainBundle().BundleMap(), &doc))
			if len(doc.TrustDomains) != 1 {
				t.Fatal("native local workload binding missing")
			}
			domain, err := spiffeid.TrustDomainFromString("local.example")
			assert.NoError(t, err)
			bundle, err := spiffebundle.Parse(domain, doc.TrustDomains["local.example"])
			assert.NoError(t, err)
			if len(bundle.X509Authorities()) != 1 {
				t.Fatal("DNS roots were pooled with workload authority")
			}
			expected, err := util.ParsePemEncodedCertificate(root)
			assert.NoError(t, err)
			if !bytes.Equal(expected.Raw, bundle.X509Authorities()[0].Raw) {
				t.Fatal("custom DNS/control-plane anchor substituted for native workload root")
			}
			args := &PilotArgs{}
			s.initKubeOptions(args)
			if args.RegistryOptions.KubeOptions.WorkloadTrustBundle != s.workloadTrustBundle {
				t.Fatal("controller did not receive local owned producer")
			}
			watcher.Set(&meshconfig.MeshConfig{TrustDomain: "local.example", CaCertificates: []*meshconfig.MeshConfig_CertificateData{{CertificateData: &meshconfig.MeshConfig_CertificateData_SpiffeBundleUrl{SpiffeBundleUrl: "https://unqualified.example"}, TrustDomains: []string{"foreign.example"}}}})
			if string(s.workloadTrustBundle.GetDomainBundle().BundleMap()) != `{"trust_domains":{}}` {
				t.Fatal("unsupported declaration retained native/last-good authority")
			}
		})
	}
}

func TestWorkloadDomainBundleInitialInvalidProjectionAndRecovery(t *testing.T) {
	test.SetForTest(t, &features.MultiRootMesh, false)
	root, err := readSampleCertFromFile("root-cert.pem")
	assert.NoError(t, err)
	valid := &meshconfig.MeshConfig{TrustDomain: "local.example", CaCertificates: []*meshconfig.MeshConfig_CertificateData{{
		CertificateData: &meshconfig.MeshConfig_CertificateData_Pem{Pem: string(root)}, TrustDomains: []string{"foreign.example"},
	}}}
	previous := tb.NewTrustBundle(nil, nil)
	assert.NoError(t, previous.AddMeshConfigUpdate(valid))
	previousSnapshot := previous.GetDomainBundle()
	for name, invalid := range map[string]*meshconfig.MeshConfig{
		"alias": {TrustDomain: "local.example", TrustDomainAliases: []string{"alias.example"}},
		"endpoint": {TrustDomain: "local.example", CaCertificates: []*meshconfig.MeshConfig_CertificateData{{
			CertificateData: &meshconfig.MeshConfig_CertificateData_SpiffeBundleUrl{SpiffeBundleUrl: "https://unqualified.example"},
		}}},
		"PEM": {TrustDomain: "local.example", CaCertificates: []*meshconfig.MeshConfig_CertificateData{{
			CertificateData: &meshconfig.MeshConfig_CertificateData_Pem{Pem: "malformed"},
		}}},
	} {
		t.Run(name, func(t *testing.T) {
			watcher := meshwatcher.NewTestWatcher(invalid)
			s := &Server{environment: model.NewEnvironment(), workloadTrustBundle: tb.NewTrustBundle(nil, watcher)}
			s.environment.Watcher = watcher
			assert.NoError(t, s.initWorkloadTrustBundle(&PilotArgs{Namespace: "istio-system"}))
			// Model a restart with persisted previous authority. Production setup
			// must reach controller Run and replace both keys, not exit early.
			client := kube.NewFakeClient(&v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "owned"}}, &v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: controller.TrustDomainsNamespaceConfigMap, Namespace: "owned"},
				Data: map[string]string{constants.SPIFFEBundleMapConfigMapDataName: string(previousSnapshot.BundleMap()),
					constants.TrustDomainsNamespaceConfigMapDataName: "foreign.example\n"},
			})
			stop := test.NewStop(t)
			c := controller.NewTrustDomainsController(client, watcher, s.workloadTrustBundle)
			client.RunAndWait(stop)
			go c.Run(stop)
			retry.UntilSuccessOrFail(t, func() error {
				cm := client.Kube().CoreV1().ConfigMaps("owned").Get
				value, err := cm(t.Context(), controller.TrustDomainsNamespaceConfigMap, metav1.GetOptions{})
				if err != nil {
					return err
				}
				if value.Data[constants.SPIFFEBundleMapConfigMapDataName] != `{"trust_domains":{}}` || value.Data[constants.TrustDomainsNamespaceConfigMapDataName] != "" {
					return fmt.Errorf("persisted authority was not cleared")
				}
				return nil
			})
			watcher.Set(valid)
			retry.UntilSuccessOrFail(t, func() error {
				value, err := client.Kube().CoreV1().ConfigMaps("owned").Get(t.Context(), controller.TrustDomainsNamespaceConfigMap, metav1.GetOptions{})
				if err != nil {
					return err
				}
				if value.Data[constants.TrustDomainsNamespaceConfigMapDataName] != "foreign.example\n" {
					return fmt.Errorf("valid local update did not recover initial empty projection")
				}
				return nil
			})
		})
	}
}

func TestWorkloadDomainBundleAbsentAndMalformedInitialRARoot(t *testing.T) {
	test.SetForTest(t, &features.MultiRootMesh, false)
	root, err := readSampleCertFromFile("root-cert.pem")
	assert.NoError(t, err)
	invalidFile := filepath.Join(t.TempDir(), "invalid-root.pem")
	assert.NoError(t, os.WriteFile(invalidFile, []byte("malformed nonempty root"), 0o600))
	for _, filename := range []string{"", invalidFile} {
		t.Run(filepath.Base(filename), func(t *testing.T) {
			watcher := meshwatcher.NewTestWatcher(&meshconfig.MeshConfig{TrustDomain: "local.example", CaCertificates: []*meshconfig.MeshConfig_CertificateData{{
				CertificateData: &meshconfig.MeshConfig_CertificateData_Pem{Pem: string(root)}, TrustDomains: []string{"foreign.example"},
			}}})
			s := &Server{environment: model.NewEnvironment(), workloadTrustBundle: tb.NewTrustBundle(nil, watcher)}
			s.environment.Watcher = watcher
			s.RA, err = ra.NewKubernetesRA(&ra.IstioRAOptions{CaCertFile: filename, CaSigner: "example.com/signer"})
			assert.NoError(t, err)
			assert.NoError(t, s.initWorkloadTrustBundle(&PilotArgs{Namespace: "istio-system"}))
			domains := s.workloadTrustBundle.GetDomainBundle().TrustDomains()
			if filename == "" {
				assert.Equal(t, domains, []string{"foreign.example"})
			} else if len(domains) != 0 {
				t.Fatal("malformed nonempty native root retained authority")
			}
		})
	}
}

func TestWorkloadDomainBundleNativeRootAdapterRecovery(t *testing.T) {
	root, err := readSampleCertFromFile("root-cert.pem")
	assert.NoError(t, err)
	for _, source := range []tb.Source{tb.SourceIstioCA, tb.SourceIstioRA} {
		t.Run(fmt.Sprint(source), func(t *testing.T) {
			bundle := tb.NewTrustBundle(nil, nil)
			assert.NoError(t, bundle.AddMeshConfigUpdate(&meshconfig.MeshConfig{TrustDomain: "local.example", CaCertificates: []*meshconfig.MeshConfig_CertificateData{{
				CertificateData: &meshconfig.MeshConfig_CertificateData_Pem{Pem: string(root)}, TrustDomains: []string{"foreign.example"},
			}}}))
			for _, missing := range [][]byte{nil, {}} {
				assert.NoError(t, bundle.UpdateTrustAnchor(nativeWorkloadRootUpdate(source, missing)))
				assert.Equal(t, bundle.GetDomainBundle().TrustDomains(), []string{"foreign.example"})
				assert.NoError(t, bundle.UpdateTrustAnchor(nativeWorkloadRootUpdate(source, root)))
				assert.Equal(t, bundle.GetDomainBundle().TrustDomains(), []string{"foreign.example", "local.example"})
				if err := bundle.UpdateTrustAnchor(nativeWorkloadRootUpdate(source, []byte("malformed nonempty"))); err == nil {
					t.Fatal("malformed native root accepted")
				}
				assert.Equal(t, string(bundle.GetDomainBundle().BundleMap()), `{"trust_domains":{}}`)
				assert.NoError(t, bundle.UpdateTrustAnchor(nativeWorkloadRootUpdate(source, missing)))
				assert.Equal(t, bundle.GetDomainBundle().TrustDomains(), []string{"foreign.example"})
			}
		})
	}
}
