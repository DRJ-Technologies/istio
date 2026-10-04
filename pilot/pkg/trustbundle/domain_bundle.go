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

package trustbundle

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/util/sets"
)

// DomainBundleSnapshot is a complete, immutable SPIFFE Bundle Map. Empty maps
// revoke all authority. Compatibility names are derived from usable bundles in
// this same snapshot; names alone never grant authority to a root certificate.
type DomainBundleSnapshot struct {
	bundleMap []byte
	domains   []string
}

func (s DomainBundleSnapshot) BundleMap() []byte {
	return bytes.Clone(s.bundleMap)
}

func (s DomainBundleSnapshot) TrustDomains() []string {
	return slices.Clone(s.domains)
}

type domainBundleState struct {
	localDomain    string
	meshValid      bool
	meshRoots      map[string][]*x509.Certificate
	nativeRoots    map[Source][]*x509.Certificate
	invalidSources sets.Set[Source]
	snapshot       DomainBundleSnapshot
	nextHandler    uint64
	handlers       map[uint64]func()
}

func newDomainBundleState() domainBundleState {
	return domainBundleState{
		meshRoots:      map[string][]*x509.Certificate{},
		nativeRoots:    map[Source][]*x509.Certificate{},
		invalidSources: sets.New[Source](),
		snapshot:       emptyDomainBundle(),
		handlers:       map[uint64]func(){},
	}
}

func emptyDomainBundle() DomainBundleSnapshot {
	return DomainBundleSnapshot{bundleMap: []byte(`{"trust_domains":{}}`)}
}

func (tb *TrustBundle) GetDomainBundle() DomainBundleSnapshot {
	tb.mutex.RLock()
	defer tb.mutex.RUnlock()
	// The snapshot backing storage is never mutated and its accessors copy it.
	return tb.domains.snapshot
}

// AddDomainBundleHandler registers a change notification. Callers reconcile by
// reading the latest complete snapshot. Unregister on controller shutdown.
func (tb *TrustBundle) AddDomainBundleHandler(handler func()) func() {
	tb.mutex.Lock()
	tb.domains.nextHandler++
	id := tb.domains.nextHandler
	tb.domains.handlers[id] = handler
	tb.mutex.Unlock()
	return func() {
		tb.mutex.Lock()
		delete(tb.domains.handlers, id)
		tb.mutex.Unlock()
	}
}

func notifyDomainBundleHandlers(handlers []func()) {
	for _, handler := range handlers {
		handler()
	}
}

// refreshDomainBundleLocked publishes all domains together, never a partial
// update or last-good authority on invalid input. Only the config cluster's
// MeshConfig is passed to AddMeshConfigUpdate; remote optional mesh discovery
// cannot self-grant foreign-root authority in this producer.
func (tb *TrustBundle) refreshDomainBundleLocked() []func() {
	snapshot := emptyDomainBundle()
	if tb.domains.meshValid && len(tb.domains.invalidSources) == 0 {
		roots := make(map[string][]*x509.Certificate, len(tb.domains.meshRoots)+1)
		for domain, certs := range tb.domains.meshRoots {
			roots[domain] = slices.Clone(certs)
		}
		for _, certs := range tb.domains.nativeRoots {
			roots[tb.domains.localDomain] = append(roots[tb.domains.localDomain], certs...)
		}
		var err error
		snapshot, err = marshalDomainBundle(roots)
		if err != nil {
			trustBundleLog.Errorf("cannot marshal domain trust bundle: %v", err)
			snapshot = emptyDomainBundle()
		}
	}
	if bytes.Equal(tb.domains.snapshot.bundleMap, snapshot.bundleMap) {
		return nil
	}
	tb.domains.snapshot = snapshot
	handlers := make([]func(), 0, len(tb.domains.handlers))
	for _, handler := range tb.domains.handlers {
		handlers = append(handlers, handler)
	}
	return handlers
}

func canonicalTrustDomain(domain string) (spiffeid.TrustDomain, error) {
	td, err := spiffeid.TrustDomainFromString(domain)
	if err != nil || td.Name() != domain || domain == "" {
		return spiffeid.TrustDomain{}, fmt.Errorf("trust domain %q must be a canonical bare SPIFFE trust domain", domain)
	}
	return td, nil
}

// parseDomainTrustAnchors checks every PEM block, including trailing material.
// pem.Decode alone can skip a bad prefix or accept only the first good block.
func parseDomainTrustAnchors(inputs []string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, input := range inputs {
		rest := bytes.TrimSpace([]byte(input))
		if len(rest) == 0 {
			return nil, fmt.Errorf("empty PEM trust anchor")
		}
		for len(rest) > 0 {
			if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
				return nil, fmt.Errorf("unexpected material in PEM trust anchor")
			}
			end := bytes.Index(rest, []byte("-----END CERTIFICATE-----"))
			if end < 0 {
				return nil, fmt.Errorf("unterminated PEM certificate")
			}
			end += len("-----END CERTIFICATE-----")
			if bytes.Count(rest[:end], []byte("-----BEGIN")) != 1 {
				return nil, fmt.Errorf("nested or skipped PEM certificate block")
			}
			block, extra := pem.Decode(rest[:end])
			if block == nil || len(bytes.TrimSpace(extra)) != 0 || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				return nil, fmt.Errorf("invalid PEM certificate block")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("invalid X.509 trust anchor: %w", err)
			}
			if !cert.BasicConstraintsValid || !cert.IsCA || (cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0) {
				return nil, fmt.Errorf("trust anchor is not a signing CA certificate")
			}
			switch key := cert.PublicKey.(type) {
			case *rsa.PublicKey:
			case *ecdsa.PublicKey:
				if key.Curve != elliptic.P256() && key.Curve != elliptic.P384() && key.Curve != elliptic.P521() {
					return nil, fmt.Errorf("unsupported SPIFFE X509-SVID trust anchor curve")
				}
			default:
				return nil, fmt.Errorf("unsupported SPIFFE X509-SVID trust anchor key type")
			}
			certs = append(certs, cert)
			rest = bytes.TrimSpace(rest[end:])
		}
	}
	return certs, nil
}

func meshDomainTrustAnchors(cfg *meshconfig.MeshConfig) (string, map[string][]*x509.Certificate, error) {
	if cfg == nil {
		return "", nil, fmt.Errorf("missing local MeshConfig")
	}
	local := cfg.GetTrustDomain()
	if _, err := canonicalTrustDomain(local); err != nil {
		return "", nil, err
	}
	if len(cfg.GetTrustDomainAliases()) != 0 {
		return local, nil, fmt.Errorf("trustDomainAliases cannot authorize domain-bound trust anchors")
	}
	bindings := map[string][]*x509.Certificate{}
	for _, entry := range cfg.GetCaCertificates() {
		// Endpoint authentication and workload identity authority are different
		// scopes. This PEM producer does not implement bundle endpoint delivery.
		if entry == nil || entry.GetPem() == "" {
			return local, nil, fmt.Errorf("domain-bound caCertificates require PEM; bundle endpoints and signer declarations are unsupported")
		}
		certs, err := parseDomainTrustAnchors([]string{entry.GetPem()})
		if err != nil {
			return local, nil, err
		}
		domains := entry.GetTrustDomains()
		if len(domains) == 0 {
			// Unlabelled declarations bind only to the native local workload domain.
			domains = []string{local}
		}
		for _, domain := range domains {
			if _, err := canonicalTrustDomain(domain); err != nil {
				return local, nil, err
			}
			bindings[domain] = append(bindings[domain], certs...)
		}
	}
	return local, bindings, nil
}

func marshalDomainBundle(roots map[string][]*x509.Certificate) (DomainBundleSnapshot, error) {
	doc := struct {
		TrustDomains map[string]json.RawMessage `json:"trust_domains"`
	}{TrustDomains: map[string]json.RawMessage{}}
	names := make([]string, 0, len(roots))
	for domain, certs := range roots {
		if len(certs) == 0 {
			// Removing a domain is standard revocation, including the local domain.
			continue
		}
		td, err := canonicalTrustDomain(domain)
		if err != nil {
			return DomainBundleSnapshot{}, err
		}
		unique := map[string]*x509.Certificate{}
		for _, cert := range certs {
			unique[string(cert.Raw)] = cert
		}
		keys := make([]string, 0, len(unique))
		for der := range unique {
			keys = append(keys, der)
		}
		sort.Strings(keys)
		certs = make([]*x509.Certificate, 0, len(keys))
		for _, der := range keys {
			certs = append(certs, unique[der])
		}
		data, err := spiffebundle.FromX509Authorities(td, certs).Marshal()
		if err != nil {
			return DomainBundleSnapshot{}, err
		}
		doc.TrustDomains[domain] = data
		names = append(names, domain)
	}
	sort.Strings(names)
	data, err := json.Marshal(doc)
	return DomainBundleSnapshot{bundleMap: data, domains: names}, err
}
