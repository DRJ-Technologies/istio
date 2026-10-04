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

package istioagent

import (
	"testing"

	"google.golang.org/protobuf/proto"

	mesh "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pkg/security"
	"istio.io/istio/pkg/util/protomarshal"
)

func TestDomainBundleMetadataUsesActualAgentInputWithoutChangingEndpointTLS(t *testing.T) {
	config := &mesh.ProxyConfig{
		DiscoveryAddress:       "external-control.example:15012",
		ControlPlaneAuthPolicy: mesh.AuthenticationPolicy_MUTUAL_TLS,
		ProxyMetadata: map[string]string{
			security.SPIFFEBundleMapPathEnv: "stale mesh setting",
			"XDS_ROOT_CA":                   "/external/xds-root.pem",
			"CA_ROOT_CA":                    "/external/ca-root.pem",
		},
	}
	original := protomarshal.Clone(config)
	path := "/var/run/secrets/istio/trust-domains/spiffe-bundle-map.json"
	for _, actual := range []string{"", path} {
		derived := proxyConfigWithBundleMap(config, &security.Options{SPIFFEBundleMapPath: actual})
		if !proto.Equal(config, original) {
			t.Fatal("agent consumer mutated the shared input configuration")
		}
		if derived.ProxyMetadata[security.SPIFFEBundleMapPathEnv] != actual {
			t.Fatal("native metadata advertised a different consumer than the actual agent")
		}
		if actual == "" {
			if _, exists := derived.ProxyMetadata[security.SPIFFEBundleMapPathEnv]; exists {
				t.Fatal("unselected map remained advertised in native metadata")
			}
		}
		expected := protomarshal.Clone(original)
		if actual == "" {
			delete(expected.ProxyMetadata, security.SPIFFEBundleMapPathEnv)
		} else {
			expected.ProxyMetadata[security.SPIFFEBundleMapPathEnv] = actual
		}
		if !proto.Equal(derived, expected) {
			t.Fatal("map plumbing altered CA/xDS endpoints, trust inputs or other proxy settings")
		}
	}
}
