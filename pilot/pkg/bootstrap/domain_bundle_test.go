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
	tb "istio.io/istio/pilot/pkg/trustbundle"
	"istio.io/istio/pkg/config/mesh/meshwatcher"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/env"
	"istio.io/istio/pkg/test/util/assert"
	"istio.io/istio/pkg/testcerts"
	"istio.io/istio/security/pkg/pki/ca"
	"istio.io/istio/security/pkg/pki/ra"
	"istio.io/istio/security/pkg/pki/util"
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
