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

package model

import (
	"regexp"
	"testing"

	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/proto"

	mesh "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/security"
)

func mappedDomainProxy() *model.Proxy {
	return &model.Proxy{Metadata: &model.NodeMetadata{ProxyConfig: (*model.NodeMetaProxyConfig)(&mesh.ProxyConfig{
		ProxyMetadata: map[string]string{security.SPIFFEBundleMapPathEnv: "/var/run/secrets/istio/trust-domains/spiffe-bundle-map.json"},
	})}}
}

func TestDomainBundlePerServerCRLRefusesInsteadOfBeingIgnored(t *testing.T) {
	proxy := mappedDomainProxy()
	context := &tls.CommonTlsContext{}
	ApplyToCommonTLSContext(context, proxy, []string{"spiffe://local.example/ns/target/sa/expected"},
		"/arbitrary/server-crl.pem", nil, true, nil, false)
	ApplyMappedRootContext(proxy, context, "/arbitrary/server-crl.pem")
	validation := context.GetCombinedValidationContext().DefaultValidationContext
	if validation.Crl != nil || len(validation.MatchSubjectAltNames) != 0 || len(validation.MatchTypedSubjectAltNames) != 1 {
		t.Fatal("unsupported per-server CRL left an ignored CVC.crl or permissive OR alternative")
	}
	matcher := validation.MatchTypedSubjectAltNames[0]
	if err := matcher.ValidateAll(); err != nil {
		t.Fatalf("denying URI constraint would NACK: %v", err)
	}
	if matcher.SanType != tls.SubjectAltNameMatcher_URI ||
		regexp.MustCompile(matcher.Matcher.GetSafeRegex().Regex).MatchString("spiffe://local.example/ns/target/sa/expected") {
		t.Fatal("unsupported CRL input did not deny the canonical peer identity")
	}
	proxy.Metadata.TLSServerRootCert = "/external/server-ca.pem"
	external := &tls.CommonTlsContext{}
	ApplyToCommonTLSContext(external, proxy, []string{"external.example"}, "/external/server-crl.pem", nil, true, nil, false)
	before := proto.Clone(external)
	ApplyMappedRootContext(proxy, external, "/external/server-crl.pem")
	if !proto.Equal(before, external) || external.GetCombinedValidationContext().DefaultValidationContext.Crl.GetFilename() != "/external/server-crl.pem" {
		t.Fatal("external file-root CRL handling changed")
	}
}

func TestDomainBundleCommonContextKeepsExactURIPrincipalWithoutAliasAllowance(t *testing.T) {
	proxy := mappedDomainProxy()
	peer := "spiffe://foreign.example/ns/target/sa/expected"
	context := &tls.CommonTlsContext{}
	ApplyToCommonTLSContext(context, proxy, []string{peer}, "", []string{"alias.example"}, true, nil, true)
	validation := context.GetCombinedValidationContext().DefaultValidationContext
	if len(validation.MatchSubjectAltNames) != 0 || len(validation.MatchTypedSubjectAltNames) != 1 {
		t.Fatal("mapped roots require typed URI constraints without legacy/alias OR allowances")
	}
	matcher := validation.MatchTypedSubjectAltNames[0]
	if matcher.SanType != tls.SubjectAltNameMatcher_URI || matcher.Matcher.GetExact() != peer {
		t.Fatal("the native expected endpoint principal was broadened or replaced")
	}
	if validation.TrustChainVerification != tls.CertificateValidationContext_VERIFY_TRUST_CHAIN {
		t.Fatal("mapped root validation accepted an insecure-skip setting")
	}
	if context.GetCombinedValidationContext().ValidationContextSdsSecretConfig.Name != SDSRootResourceName ||
		len(context.TlsCertificateSdsSecretConfigs) != 1 || context.TlsCertificateSdsSecretConfigs[0].Name != SDSDefaultResourceName {
		t.Fatal("default certificate and ROOTCA resources lost their separate native ownership")
	}
	// A server with an explicit external file root retains its native DNS/SAN
	// validation even when this proxy also consumes the mesh bundle map.
	proxy.Metadata.TLSServerRootCert = "/external/server-ca.pem"
	external := &tls.CommonTlsContext{}
	ApplyToCommonTLSContext(external, proxy, []string{"external.example"}, "", nil, true, nil, false)
	validation = external.GetCombinedValidationContext().DefaultValidationContext
	if len(validation.MatchTypedSubjectAltNames) != 0 || len(validation.MatchSubjectAltNames) != 1 ||
		validation.MatchSubjectAltNames[0].GetExact() != "external.example" ||
		external.GetCombinedValidationContext().ValidationContextSdsSecretConfig.Name == SDSRootResourceName {
		t.Fatal("external file-root/DNS TLS was converted into workload-domain validation")
	}
}

func TestDomainBundleResumptionDisabledOnlyForSelectedMeshROOTCA(t *testing.T) {
	for _, resource := range []string{SDSRootResourceName, "file-root:/external/server-ca.pem"} {
		for _, mapped := range []bool{false, true} {
			proxy := mappedDomainProxy()
			if !mapped {
				proxy.Metadata.ProxyConfig.ProxyMetadata = nil
			}
			common := &tls.CommonTlsContext{ValidationContextType: &tls.CommonTlsContext_CombinedValidationContext{
				CombinedValidationContext: &tls.CommonTlsContext_CombinedCertificateValidationContext{
					DefaultValidationContext:         &tls.CertificateValidationContext{},
					ValidationContextSdsSecretConfig: ConstructSdsSecretConfig(resource),
				},
			}}
			upstream := &tls.UpstreamTlsContext{CommonTlsContext: common}
			downstream := &tls.DownstreamTlsContext{CommonTlsContext: common}
			beforeUpstream := proto.Clone(upstream)
			beforeDownstream := proto.Clone(downstream)
			DisableMappedUpstreamResumption(proxy, upstream)
			DisableMappedDownstreamResumption(proxy, downstream)
			if mapped && resource == SDSRootResourceName {
				if upstream.MaxSessionKeys == nil || upstream.MaxSessionKeys.Value != 0 ||
					!downstream.GetDisableStatelessSessionResumption() || !downstream.DisableStatefulSessionResumption {
					t.Fatal("mapped TLS allowed resumption to skip the current domain store")
				}
			} else if !proto.Equal(upstream, beforeUpstream) || !proto.Equal(downstream, beforeDownstream) {
				t.Fatal("resumption policy changed for an unselected or external TLS interface")
			}
		}
	}
}
