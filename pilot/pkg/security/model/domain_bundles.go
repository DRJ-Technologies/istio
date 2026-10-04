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
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking/util"
	"istio.io/istio/pkg/security"
)

// UsesWorkloadDomainBundles reports the sole map selector advertised by the
// native agent. It is a consumer-interface choice, not root authority.
func UsesWorkloadDomainBundles(proxy *model.Proxy) bool {
	return proxy != nil && proxy.Metadata != nil && proxy.Metadata.ProxyConfig != nil &&
		proxy.Metadata.ProxyConfig.ProxyMetadata[security.SPIFFEBundleMapPathEnv] != ""
}

func mappedRootTLS(proxy *model.Proxy, context *tls.CommonTlsContext) bool {
	if !UsesWorkloadDomainBundles(proxy) || context == nil {
		return false
	}
	root := context.GetValidationContextSdsSecretConfig()
	if root == nil {
		root = context.GetCombinedValidationContext().GetValidationContextSdsSecretConfig()
	}
	return root.GetName() == SDSRootResourceName
}

// ApplyMappedPeerIdentity preserves the existing exact endpoint principals as
// URI constraints. Domain names/aliases are never ORed into those constraints;
// the per-domain SDS store, rather than a name list, selects root authority.
func ApplyMappedPeerIdentity(validation *tls.CertificateValidationContext, subjectAltNames []string) {
	validation.MatchSubjectAltNames = nil
	validation.MatchTypedSubjectAltNames = nil
	for _, matcher := range util.StringToExactMatch(subjectAltNames) {
		validation.MatchTypedSubjectAltNames = append(validation.MatchTypedSubjectAltNames, &tls.SubjectAltNameMatcher{
			SanType: tls.SubjectAltNameMatcher_URI, Matcher: matcher,
		})
	}
	validation.TrustChainVerification = tls.CertificateValidationContext_VERIFY_TRUST_CHAIN
}

// An arbitrary server CRL filename cannot be carried into the selected SPIFFE
// store through CVC.crl. Refuse that unsupported input with an accepted URI
// constraint matching no canonical SPIFFE identity, rather than silently
// ignoring the requested revocation source or NACKing and retaining authority.
func denyMappedPeerIdentity(validation *tls.CertificateValidationContext) {
	validation.MatchSubjectAltNames = nil
	validation.MatchTypedSubjectAltNames = []*tls.SubjectAltNameMatcher{{
		SanType: tls.SubjectAltNameMatcher_URI,
		Matcher: &matcher.StringMatcher{MatchPattern: &matcher.StringMatcher_SafeRegex{
			SafeRegex: &matcher.RegexMatcher{Regex: "^$"},
		}},
	}}
}

// Credential aliases can resolve to the same native ROOTCA as ISTIO_MUTUAL.
// Apply the mapped policy to that resolved resource too, while leaving all
// external file/credential TLS contexts intact.
func ApplyMappedRootContext(proxy *model.Proxy, context *tls.CommonTlsContext, crl string) {
	if !mappedRootTLS(proxy, context) {
		return
	}
	validation := context.GetCombinedValidationContext().GetDefaultValidationContext()
	if validation == nil {
		return
	}
	for _, principal := range validation.MatchSubjectAltNames {
		validation.MatchTypedSubjectAltNames = append(validation.MatchTypedSubjectAltNames, &tls.SubjectAltNameMatcher{
			SanType: tls.SubjectAltNameMatcher_URI, Matcher: principal,
		})
	}
	validation.MatchSubjectAltNames = nil
	validation.TrustChainVerification = tls.CertificateValidationContext_VERIFY_TRUST_CHAIN
	validation.AllowExpiredCertificate = false
	if crl != "" || validation.Crl != nil || len(validation.VerifyCertificateHash) != 0 || len(validation.VerifyCertificateSpki) != 0 {
		// The SPIFFE loader does not implement these per-server native inputs.
		// Refuse rather than discard a requested validation constraint.
		denyMappedPeerIdentity(validation)
	}
	validation.Crl = nil
}

// Resumption would skip validation against the current domain snapshot. These
// controls cover new handshakes; existing connection revocation remains owned
// by the paired Envoy lifetime layer.
func DisableMappedDownstreamResumption(proxy *model.Proxy, context *tls.DownstreamTlsContext) {
	if !mappedRootTLS(proxy, context.GetCommonTlsContext()) {
		return
	}
	context.SessionTicketKeysType = &tls.DownstreamTlsContext_DisableStatelessSessionResumption{
		DisableStatelessSessionResumption: true,
	}
	context.DisableStatefulSessionResumption = true
}

func DisableMappedUpstreamResumption(proxy *model.Proxy, context *tls.UpstreamTlsContext) {
	if mappedRootTLS(proxy, context.GetCommonTlsContext()) {
		context.MaxSessionKeys = wrapperspb.UInt32(0)
	}
}
