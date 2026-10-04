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

package sds

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"sort"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"

	"istio.io/istio/pilot/pkg/util/protoconv"
	"istio.io/istio/pkg/security"
)

func domainBundleValidationContext(s *security.SecretItem) *tls.CertificateValidationContext {
	entries := make([]*tls.SPIFFECertValidatorConfig_TrustDomain, 0, len(s.TrustDomainBundles))
	names := make([]string, 0, len(s.TrustDomainBundles))
	for name := range s.TrustDomainBundles {
		names = append(names, name)
	}
	sort.Strings(names)
	var crls []*x509.RevocationList
	var crlErr error
	if s.WorkloadCRL != nil {
		crls, crlErr = security.ParseWorkloadCRLs(s.WorkloadCRL, time.Now())
	}
	if crlErr != nil {
		// Returning an SDS error would preserve old authority. Publish the
		// accepted explicit zero-anchor context instead of an invalid PEM store.
		sdsServiceLog.Errorf("invalid workload CRL; denying mapped authority: %v", crlErr)
	} else {
		for _, name := range names {
			roots := s.TrustDomainBundles[name]
			if len(roots) == 0 {
				continue
			}
			inline := bytes.Clone(roots)
			for _, crl := range crls {
				// CRLs confer no root authority. Native CRL_CHECK_ALL verifies
				// issuer/signature/time/serial/coverage against the peer chain
				// and this domain's anchors. Filtering only by root issuer here
				// would silently drop intermediate-issued revocation data. Missing
				// issuer coverage fails the native verification; never add issuer
				// certificates from another domain to make a CRL usable.
				inline = append(inline, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl.Raw})...)
			}
			entries = append(entries, domainTrustEntry(name, inline))
		}
	}
	if len(entries) == 0 {
		// Native trust_domains requires at least one entry. This known local
		// name is only a deny placeholder, with an explicit empty inline store.
		// It never restores native/local roots or another domain's authority.
		entries = append(entries, domainTrustEntry(s.LocalTrustDomain, []byte{}))
	}
	return &tls.CertificateValidationContext{CustomValidatorConfig: &core.TypedExtensionConfig{
		Name:        "envoy.tls.cert_validator.spiffe",
		TypedConfig: protoconv.MessageToAny(&tls.SPIFFECertValidatorConfig{TrustDomains: entries}),
	}}
}

func domainTrustEntry(name string, anchors []byte) *tls.SPIFFECertValidatorConfig_TrustDomain {
	return &tls.SPIFFECertValidatorConfig_TrustDomain{
		Name:        name,
		TrustBundle: &core.DataSource{Specifier: &core.DataSource_InlineBytes{InlineBytes: anchors}},
	}
}
