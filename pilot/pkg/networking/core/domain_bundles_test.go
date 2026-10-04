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

package core

import (
	"regexp"
	"strings"
	"testing"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	networking "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pilot/pkg/credentials"
	"istio.io/istio/pilot/pkg/model"
	istionetworking "istio.io/istio/pilot/pkg/networking"
	authnutils "istio.io/istio/pilot/pkg/security/authn/utils"
	secmodel "istio.io/istio/pilot/pkg/security/model"
	"istio.io/istio/pkg/config/host"
	"istio.io/istio/pkg/config/mesh"
	"istio.io/istio/pkg/config/protocol"
	"istio.io/istio/pkg/security"
)

func TestDomainBundleActualMeshContextConsumers(t *testing.T) {
	proxy := &model.Proxy{Type: model.Router, IPAddresses: []string{"10.0.0.1"}, Metadata: &model.NodeMetadata{}}
	config := mesh.DefaultProxyConfig()
	config.ProxyMetadata = map[string]string{security.SPIFFEBundleMapPathEnv: "/var/run/secrets/istio/trust-domains/spiffe-bundle-map.json"}
	proxy.Metadata.ProxyConfig = (*model.NodeMetaProxyConfig)(config)
	push := model.NewPushContext()
	push.Mesh = mesh.DefaultMeshConfig()
	push.Mesh.TrustDomainAliases = []string{"must-not-authorize.example"}
	peer := "spiffe://foreign.example/ns/target/sa/expected"
	assertMapped := func(context *tls.CommonTlsContext, exact string) {
		t.Helper()
		combined := context.GetCombinedValidationContext()
		if combined.GetValidationContextSdsSecretConfig().GetName() != secmodel.SDSRootResourceName {
			t.Fatal("mesh consumer lost native mapped ROOTCA")
		}
		validation := combined.GetDefaultValidationContext()
		if len(validation.MatchSubjectAltNames) != 0 || validation.TrustChainVerification != tls.CertificateValidationContext_VERIFY_TRUST_CHAIN {
			t.Fatal("mesh consumer retained legacy or insecure validation")
		}
		if exact == "" {
			if len(validation.MatchTypedSubjectAltNames) != 0 {
				t.Fatal("name-only domain/alias constraint became independent authority")
			}
		} else {
			if len(validation.MatchTypedSubjectAltNames) != 1 || validation.MatchTypedSubjectAltNames[0].SanType != tls.SubjectAltNameMatcher_URI ||
				validation.MatchTypedSubjectAltNames[0].Matcher.GetExact() != exact {
				t.Fatal("expected peer principal broadened through domain-prefix OR")
			}
		}
	}
	for _, mode := range []model.MutualTLSMode{model.MTLSStrict, model.MTLSPermissive} {
		context := authnutils.BuildInboundTLS(mode, proxy, istionetworking.ListenerProtocolTCP,
			push.Mesh.TrustDomainAliases, tls.TlsParameters_TLSv1_2, push.Mesh)
		assertMapped(context.CommonTlsContext, "")
		if !context.GetDisableStatelessSessionResumption() || !context.DisableStatefulSessionResumption {
			t.Fatal("sidecar inbound allows stale session resumption")
		}
	}
	for _, settings := range []*networking.ServerTLSSettings{
		{Mode: networking.ServerTLSSettings_ISTIO_MUTUAL, SubjectAltNames: []string{peer}},
		{Mode: networking.ServerTLSSettings_MUTUAL, CredentialName: credentials.BuiltinGatewaySecretTypeURI, SubjectAltNames: []string{peer}},
	} {
		context := BuildListenerTLSContext(settings, proxy, push, istionetworking.TransportProtocolTCP, true)
		assertMapped(context.CommonTlsContext, peer)
		if !context.GetRequireClientCertificate().GetValue() || !context.GetDisableStatelessSessionResumption() || !context.DisableStatefulSessionResumption {
			t.Fatal("gateway ROOTCA consumer lost mTLS or resumption constraints")
		}
	}
	cb := NewClusterBuilder(proxy, &model.PushRequest{Push: push}, model.DisabledCache{})
	for _, settings := range []*networking.ClientTLSSettings{
		{Mode: networking.ClientTLSSettings_ISTIO_MUTUAL, SubjectAltNames: []string{peer}},
		{Mode: networking.ClientTLSSettings_MUTUAL, CredentialName: credentials.BuiltinGatewaySecretTypeURI,
			SubjectAltNames: []string{peer}, InsecureSkipVerify: wrapperspb.Bool(true)},
	} {
		context, err := cb.buildUpstreamClusterTLSContext(&buildClusterOpts{
			mesh: push.Mesh, mutable: newClusterWrapper(&cluster.Cluster{Name: "native-peer"}), isDrWithSelector: true,
		}, settings)
		if err != nil || context == nil {
			t.Fatalf("native mesh upstream missing: %v", err)
		}
		assertMapped(context.CommonTlsContext, peer)
		if context.MaxSessionKeys == nil || context.MaxSessionKeys.Value != 0 {
			t.Fatal("mesh upstream allows stale session resumption")
		}
	}
	// Native HBONE peers retain exact destination URI matching. Accepted domain
	// entries do not supply broad prefix alternatives around that restriction.
	connect := cb.buildConnectOriginate("native-connect", proxy, push,
		&matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_Exact{Exact: peer}})
	upstream := &tls.UpstreamTlsContext{}
	if err := connect.TransportSocket.GetTypedConfig().UnmarshalTo(upstream); err != nil {
		t.Fatal(err)
	}
	assertMapped(upstream.CommonTlsContext, peer)
	if upstream.MaxSessionKeys == nil || upstream.MaxSessionKeys.Value != 0 {
		t.Fatal("HBONE upstream allows stale resumption")
	}
	common := buildCommonConnectTLSContext(proxy, push)
	assertMapped(common, "")
	if common.TlsParams.TlsMinimumProtocolVersion != tls.TlsParameters_TLSv1_3 {
		t.Fatal("HBONE minimum TLS version changed")
	}
	// Ordinary external DNS TLS continues to select a file-root resource.
	external, err := cb.buildUpstreamClusterTLSContext(&buildClusterOpts{
		mesh: push.Mesh, mutable: newClusterWrapper(&cluster.Cluster{Name: "external"}),
	}, &networking.ClientTLSSettings{Mode: networking.ClientTLSSettings_SIMPLE, CaCertificates: "/external/ca.pem", SubjectAltNames: []string{"external.example"}})
	if err != nil || external == nil {
		t.Fatalf("external native TLS missing: %v", err)
	}
	validation := external.CommonTlsContext.GetCombinedValidationContext()
	if validation.GetValidationContextSdsSecretConfig().GetName() == secmodel.SDSRootResourceName ||
		len(validation.DefaultValidationContext.MatchTypedSubjectAltNames) != 0 ||
		validation.DefaultValidationContext.MatchSubjectAltNames[0].GetExact() != "external.example" {
		t.Fatal("external DNS TLS became workload trust")
	}
}

func TestDomainBundleNativeGatewayRejectsOriginalPinInputs(t *testing.T) {
	proxy := &model.Proxy{Type: model.Router, Metadata: &model.NodeMetadata{}}
	config := mesh.DefaultProxyConfig()
	config.ProxyMetadata = map[string]string{security.SPIFFEBundleMapPathEnv: "/var/run/secrets/istio/trust-domains/spiffe-bundle-map.json"}
	proxy.Metadata.ProxyConfig = (*model.NodeMetaProxyConfig)(config)
	push := model.NewPushContext()
	push.Mesh = mesh.DefaultMeshConfig()
	for _, mode := range []networking.ServerTLSSettings_TLSmode{networking.ServerTLSSettings_ISTIO_MUTUAL, networking.ServerTLSSettings_MUTUAL} {
		for _, pin := range []string{"hash", "spki"} {
			settings := &networking.ServerTLSSettings{Mode: mode, SubjectAltNames: []string{"spiffe://foreign.example/ns/target/sa/expected"}}
			if mode == networking.ServerTLSSettings_MUTUAL {
				settings.CredentialName = credentials.BuiltinGatewaySecretTypeURI
			}
			if pin == "hash" {
				settings.VerifyCertificateHash = []string{strings.Repeat("0", 64)}
			} else {
				settings.VerifyCertificateSpki = []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
			}
			context := BuildListenerTLSContext(settings, proxy, push, istionetworking.TransportProtocolTCP, true)
			if err := context.ValidateAll(); err != nil {
				t.Fatalf("denying context would be rejected: %v", err)
			}
			validation := context.CommonTlsContext.GetCombinedValidationContext().DefaultValidationContext
			if len(validation.MatchTypedSubjectAltNames) != 1 || len(validation.VerifyCertificateHash) != 0 || len(validation.VerifyCertificateSpki) != 0 {
				t.Fatal("original pin input was lost or retained as an unsupported decode input")
			}
			match := validation.MatchTypedSubjectAltNames[0]
			if match.SanType != tls.SubjectAltNameMatcher_URI || match.Matcher.GetSafeRegex() == nil ||
				regexp.MustCompile(match.Matcher.GetSafeRegex().Regex).MatchString(settings.SubjectAltNames[0]) {
				t.Fatal("original pin input did not refuse the otherwise valid peer")
			}
		}
	}
}

func TestDomainBundleNativeCDSCacheSeparatesSelectedContexts(t *testing.T) {
	port := &model.Port{Name: "tcp", Port: 8080, Protocol: protocol.TCP}
	service := &model.Service{Hostname: host.Name("native.default.svc.cluster.local"), Ports: []*model.Port{port},
		Attributes: model.ServiceAttributes{Namespace: "default"}, Resolution: model.ClientSideLB}
	cg := NewConfigGenTest(t, TestOptions{Services: []*model.Service{service}})
	key := func(path string) any {
		config := mesh.DefaultProxyConfig()
		config.ProxyMetadata = map[string]string{security.SPIFFEBundleMapPathEnv: path}
		proxy := cg.SetupProxy(&model.Proxy{Metadata: &model.NodeMetadata{ProxyConfig: (*model.NodeMetaProxyConfig)(config)}})
		builder := NewClusterBuilder(proxy, &model.PushRequest{Push: cg.PushContext()}, model.DisabledCache{})
		entry := buildClusterKey(service, port, builder, proxy, nil)
		return entry.Key()
	}
	legacy, selected := key(""), key("/var/run/secrets/istio/trust-domains/spiffe-bundle-map.json")
	if legacy == selected {
		t.Fatal("native CDS cache can reuse an unselected TLS context for a mapped proxy")
	}
	if selected != key("/another/selected/map.json") {
		t.Fatal("runtime map paths created independent configuration/cache authority")
	}
}

func TestDomainBundleNativeQUICWithoutPeerValidationPreservesTLSContract(t *testing.T) {
	proxy := &model.Proxy{Type: model.Router, Metadata: &model.NodeMetadata{}}
	config := mesh.DefaultProxyConfig()
	proxy.Metadata.ProxyConfig = (*model.NodeMetaProxyConfig)(config)
	push := model.NewPushContext()
	push.Mesh = mesh.DefaultMeshConfig()
	settings := &networking.ServerTLSSettings{Mode: networking.ServerTLSSettings_ISTIO_MUTUAL}
	baseline := BuildListenerTLSContext(settings, proxy, push, istionetworking.TransportProtocolQUIC, false)
	config.ProxyMetadata = map[string]string{security.SPIFFEBundleMapPathEnv: "/var/run/secrets/istio/trust-domains/spiffe-bundle-map.json"}
	selected := BuildListenerTLSContext(settings, proxy, push, istionetworking.TransportProtocolQUIC, false)
	if err := selected.ValidateAll(); err != nil {
		t.Fatalf("native QUIC TLS context was invalidated: %v", err)
	}
	if !proto.Equal(baseline, selected) {
		t.Fatal("map selection changed the native QUIC TLS contract")
	}
	if len(selected.CommonTlsContext.TlsCertificateSdsSecretConfigs) != 1 ||
		selected.CommonTlsContext.TlsCertificateSdsSecretConfigs[0].Name != secmodel.SDSDefaultResourceName {
		t.Fatal("native QUIC server lost its workload certificate")
	}
	// Upstream QUIC client-certificate authentication is still unsupported.
	// Absence of CVC is not mapped peer authorization or integration proof.
	if selected.CommonTlsContext.GetCombinedValidationContext() != nil || selected.RequireClientCertificate.GetValue() {
		t.Fatal("consumer invented unsupported QUIC peer authentication")
	}
	tcp := BuildListenerTLSContext(settings, proxy, push, istionetworking.TransportProtocolTCP, true)
	if !tcp.RequireClientCertificate.GetValue() ||
		tcp.CommonTlsContext.GetCombinedValidationContext().GetValidationContextSdsSecretConfig().GetName() != secmodel.SDSRootResourceName {
		t.Fatal("native TCP mapped mutual TLS was loosened by the QUIC guard")
	}
}
