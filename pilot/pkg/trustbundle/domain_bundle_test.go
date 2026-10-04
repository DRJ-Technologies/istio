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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pkg/slices"
)

type domainTestCA struct {
	pem  string
	root *x509.Certificate
	leaf *x509.Certificate
}

func newDomainTestCA(t *testing.T, domain string) domainTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "same-issuer-name"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse("spiffe://" + domain + "/ns/default/sa/default")
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs: []*url.URL{uri}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return domainTestCA{pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), root: root, leaf: leaf}
}

func domainPEM(pem string, domains ...string) *meshconfig.MeshConfig_CertificateData {
	return &meshconfig.MeshConfig_CertificateData{
		CertificateData: &meshconfig.MeshConfig_CertificateData_Pem{Pem: pem}, TrustDomains: domains,
	}
}

func snapshotAuthorities(t *testing.T, s DomainBundleSnapshot) map[string][]*x509.Certificate {
	t.Helper()
	var doc struct {
		TrustDomains map[string]json.RawMessage `json:"trust_domains"`
	}
	if err := json.Unmarshal(s.BundleMap(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.TrustDomains == nil {
		t.Fatal("missing standard trust_domains object")
	}
	roots := map[string][]*x509.Certificate{}
	for domain, data := range doc.TrustDomains {
		td, err := spiffeid.TrustDomainFromString(domain)
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := spiffebundle.Parse(td, data)
		if err != nil {
			t.Fatal(err)
		}
		roots[domain] = bundle.X509Authorities()
		var keys struct {
			Keys []map[string]json.RawMessage `json:"keys"`
		}
		if err := json.Unmarshal(data, &keys); err != nil {
			t.Fatal(err)
		}
		for _, key := range keys.Keys {
			if string(key["use"]) != `"x509-svid"` || (string(key["kty"]) != `"RSA"` && string(key["kty"]) != `"EC"`) || key["kid"] != nil {
				t.Fatalf("not a standard X509-SVID JWK: %s", data)
			}
			var chain []string
			if err := json.Unmarshal(key["x5c"], &chain); err != nil || len(chain) != 1 {
				t.Fatal("x5c must carry exactly one CA")
			}
		}
	}
	names := make([]string, 0, len(roots))
	for domain := range roots {
		names = append(names, domain)
	}
	slices.Sort(names)
	if !slices.Equal(names, s.TrustDomains()) {
		t.Fatalf("compatibility names %v differ from complete map %v", s.TrustDomains(), names)
	}
	return roots
}

func TestDomainBundleIndependentRootBindings(t *testing.T) {
	domains := []string{"local.example", "foreign.example", "build.example"}
	cas := make([]domainTestCA, len(domains))
	for i, domain := range domains {
		cas[i] = newDomainTestCA(t, domain)
	}
	tb := NewTrustBundle(nil, nil)
	cfg := &meshconfig.MeshConfig{TrustDomain: domains[0], CaCertificates: []*meshconfig.MeshConfig_CertificateData{
		domainPEM(cas[1].pem, domains[1]), domainPEM(cas[2].pem, domains[2]),
	}}
	if err := tb.AddMeshConfigUpdate(cfg); err != nil {
		t.Fatal(err)
	}
	if err := tb.UpdateTrustAnchor(&TrustAnchorUpdate{Source: SourceIstioCA, TrustAnchorConfig: TrustAnchorConfig{Certs: []string{cas[0].pem}}}); err != nil {
		t.Fatal(err)
	}
	roots := snapshotAuthorities(t, tb.GetDomainBundle())
	for i, domain := range domains {
		if len(roots[domain]) != 1 || !bytes.Equal(roots[domain][0].Raw, cas[i].root.Raw) {
			t.Fatalf("wrong anchors for %s", domain)
		}
		pool := x509.NewCertPool()
		for _, root := range roots[domain] {
			pool.AddCert(root)
		}
		for j, ca := range cas {
			for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth} {
				_, err := ca.leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{usage}})
				if (err == nil) != (i == j) {
					t.Fatalf("selected domain %s, issuer %s, usage %v: %v", domain, domains[j], usage, err)
				}
			}
		}
	}
	if flat := tb.GetTrustBundle(); len(flat) != 1 || flat[0] != cas[0].pem {
		t.Fatal("foreign roots leaked into local flat workload bundle")
	}
	// A legacy remote endpoint/flat source never creates a domain binding.
	if err := tb.UpdateTrustAnchor(&TrustAnchorUpdate{Source: sourceSpiffeEndpoints, TrustAnchorConfig: TrustAnchorConfig{Certs: []string{cas[1].pem}}}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(roots[domains[0]][0].Raw, snapshotAuthorities(t, tb.GetDomainBundle())[domains[0]][0].Raw) {
		t.Fatal("endpoint root granted local authority")
	}
}

func TestDomainBundleLocalUnlabelledRotationAndRemoval(t *testing.T) {
	local := newDomainTestCA(t, "local.example")
	rotated := newDomainTestCA(t, "foreign.example")
	tb := NewTrustBundle(nil, nil)
	cfg := &meshconfig.MeshConfig{TrustDomain: "local.example", CaCertificates: []*meshconfig.MeshConfig_CertificateData{
		domainPEM(local.pem), domainPEM(rotated.pem, "foreign.example"), domainPEM(local.pem+rotated.pem, "foreign.example"),
	}}
	if err := tb.AddMeshConfigUpdate(cfg); err != nil {
		t.Fatal(err)
	}
	roots := snapshotAuthorities(t, tb.GetDomainBundle())
	if len(roots["local.example"]) != 1 || len(roots["foreign.example"]) != 2 {
		t.Fatal("unlabelled root leaked or rotation anchors duplicated")
	}
	first := tb.GetDomainBundle()
	// Declaration order and PEM whitespace are not new authority.
	cfg.CaCertificates = []*meshconfig.MeshConfig_CertificateData{domainPEM(rotated.pem+local.pem, "foreign.example"), domainPEM("\n" + local.pem + "\n")}
	if err := tb.AddMeshConfigUpdate(cfg); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.BundleMap(), tb.GetDomainBundle().BundleMap()) {
		t.Fatal("declaration order changed native bundle")
	}
	cfg.CaCertificates = []*meshconfig.MeshConfig_CertificateData{domainPEM(rotated.pem, "foreign.example")}
	if err := tb.AddMeshConfigUpdate(cfg); err != nil {
		t.Fatal(err)
	}
	roots = snapshotAuthorities(t, tb.GetDomainBundle())
	if len(roots["local.example"]) != 0 || len(roots["foreign.example"]) != 1 {
		t.Fatal("local authority restored after removal")
	}
	cfg.CaCertificates = nil
	if err := tb.AddMeshConfigUpdate(cfg); err != nil {
		t.Fatal(err)
	}
	if string(tb.GetDomainBundle().BundleMap()) != `{"trust_domains":{}}` {
		t.Fatal("empty map did not revoke every domain")
	}
	if len(snapshotAuthorities(t, first)["local.example"]) != 1 {
		t.Fatal("old immutable snapshot mutated")
	}
	data := first.BundleMap()
	data[0] = 'X'
	names := first.TrustDomains()
	names[0] = "tampered.example"
	snapshotAuthorities(t, first)
}

func TestDomainBundleNativeCAAndRAFailClosed(t *testing.T) {
	ca := newDomainTestCA(t, "local.example")
	ra := newDomainTestCA(t, "local.example")
	tb := NewTrustBundle(nil, nil)
	if string(tb.GetDomainBundle().BundleMap()) != `{"trust_domains":{}}` {
		t.Fatal("startup granted authority")
	}
	update := &TrustAnchorUpdate{Source: SourceIstioCA, TrustAnchorConfig: TrustAnchorConfig{Certs: []string{ca.pem}}}
	if err := tb.UpdateTrustAnchor(update); err != nil {
		t.Fatal(err)
	}
	if len(tb.GetDomainBundle().TrustDomains()) != 0 {
		t.Fatal("native root guessed local domain before config")
	}
	cfg := &meshconfig.MeshConfig{TrustDomain: "local.example"}
	if err := tb.AddMeshConfigUpdate(cfg); err != nil {
		t.Fatal(err)
	}
	if err := tb.UpdateTrustAnchor(&TrustAnchorUpdate{Source: SourceIstioRA, TrustAnchorConfig: TrustAnchorConfig{Certs: []string{ra.pem}}}); err != nil {
		t.Fatal(err)
	}
	if len(snapshotAuthorities(t, tb.GetDomainBundle())["local.example"]) != 2 {
		t.Fatal("native CA/RA bindings missing")
	}
	// Caller slice mutation must not change the cached flat source.
	update.Certs[0] = "mutated"
	if len(tb.GetTrustBundle()) != 2 {
		t.Fatal("source slices aliased")
	}
	if err := tb.UpdateTrustAnchor(&TrustAnchorUpdate{Source: SourceIstioCA, TrustAnchorConfig: TrustAnchorConfig{Certs: []string{ca.pem + "invalid"}}}); err == nil {
		t.Fatal("bad native root accepted")
	}
	if len(tb.GetDomainBundle().TrustDomains()) != 0 {
		t.Fatal("native parse error retained authority")
	}
	if err := tb.AddMeshConfigUpdate(cfg); err != nil {
		t.Fatal(err)
	}
	if len(tb.GetDomainBundle().TrustDomains()) != 0 {
		t.Fatal("mesh update unmasked invalid native source")
	}
	// Repeating the prior good source clears its invalid state, despite equality.
	if err := tb.UpdateTrustAnchor(&TrustAnchorUpdate{Source: SourceIstioCA, TrustAnchorConfig: TrustAnchorConfig{Certs: []string{ca.pem}}}); err != nil {
		t.Fatal(err)
	}
	if len(snapshotAuthorities(t, tb.GetDomainBundle())["local.example"]) != 2 {
		t.Fatal("native source did not recover")
	}
	for _, source := range []Source{SourceIstioCA, SourceIstioRA} {
		if err := tb.UpdateTrustAnchor(&TrustAnchorUpdate{Source: source}); err != nil {
			t.Fatal(err)
		}
	}
	if len(tb.GetDomainBundle().TrustDomains()) != 0 {
		t.Fatal("native root removal retained authority")
	}
}

func TestDomainBundleRejectsInvalidCompleteConfiguration(t *testing.T) {
	good := newDomainTestCA(t, "local.example")
	pemInputs := []string{"", "prefix" + good.pem, good.pem + "suffix", good.pem + nonCaCert,
		good.pem + "-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----\n",
		"-----BEGIN CERTIFICATE-----\n!\n" + good.pem,
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("bad")})) + good.pem}
	cases := map[string]*meshconfig.MeshConfig{
		"nil":                nil,
		"alias":              {TrustDomain: "local.example", TrustDomainAliases: []string{"alias.example"}},
		"endpoint":           {TrustDomain: "local.example", CaCertificates: []*meshconfig.MeshConfig_CertificateData{{CertificateData: &meshconfig.MeshConfig_CertificateData_SpiffeBundleUrl{SpiffeBundleUrl: "https://bundles.example"}, TrustDomains: []string{"foreign.example"}}}},
		"nil declaration":    {TrustDomain: "local.example", CaCertificates: []*meshconfig.MeshConfig_CertificateData{nil}},
		"no PEM declaration": {TrustDomain: "local.example", CaCertificates: []*meshconfig.MeshConfig_CertificateData{{TrustDomains: []string{"foreign.example"}}}},
	}
	for i, input := range pemInputs {
		cases[fmt.Sprintf("PEM %d", i)] = &meshconfig.MeshConfig{TrustDomain: "local.example", CaCertificates: []*meshconfig.MeshConfig_CertificateData{domainPEM(input)}}
	}
	for _, domain := range []string{"", "*", "Local.example", "spiffe://foreign.example", "foreign.example/", "foreign.example:443"} {
		cases["local domain "+domain] = &meshconfig.MeshConfig{TrustDomain: domain}
		cases["bound domain "+domain] = &meshconfig.MeshConfig{TrustDomain: "local.example", CaCertificates: []*meshconfig.MeshConfig_CertificateData{domainPEM(good.pem, domain)}}
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			tb := NewTrustBundle(nil, nil)
			if err := tb.AddMeshConfigUpdate(&meshconfig.MeshConfig{TrustDomain: "local.example", CaCertificates: []*meshconfig.MeshConfig_CertificateData{domainPEM(good.pem)}}); err != nil {
				t.Fatal(err)
			}
			if err := tb.AddMeshConfigUpdate(cfg); err == nil {
				t.Fatal("invalid declaration accepted")
			}
			if string(tb.GetDomainBundle().BundleMap()) != `{"trust_domains":{}}` {
				t.Fatal("invalid declaration retained old/partial authority")
			}
		})
	}
}

func TestDomainBundleNotificationsAndConcurrentSnapshots(t *testing.T) {
	ca := newDomainTestCA(t, "local.example")
	cfg := &meshconfig.MeshConfig{TrustDomain: "local.example", CaCertificates: []*meshconfig.MeshConfig_CertificateData{domainPEM(ca.pem)}}
	tb := NewTrustBundle(nil, nil)
	var notifications atomic.Int32
	unregister := tb.AddDomainBundleHandler(func() { notifications.Add(1); _ = tb.GetDomainBundle() })
	if err := tb.AddMeshConfigUpdate(cfg); err != nil {
		t.Fatal(err)
	}
	if err := tb.AddMeshConfigUpdate(cfg); err != nil {
		t.Fatal(err)
	}
	if notifications.Load() != 1 {
		t.Fatal("unchanged snapshot notified or change missing")
	}
	unregister()
	if err := tb.AddMeshConfigUpdate(&meshconfig.MeshConfig{TrustDomain: "local.example"}); err != nil {
		t.Fatal(err)
	}
	if notifications.Load() != 1 {
		t.Fatal("unregistered listener notified")
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 30; j++ {
				switch i {
				case 0:
					_ = tb.AddMeshConfigUpdate(cfg)
				case 1:
					_ = tb.UpdateTrustAnchor(&TrustAnchorUpdate{Source: SourceIstioRA, TrustAnchorConfig: TrustAnchorConfig{Certs: []string{ca.pem}}})
				case 2:
					stop := tb.AddDomainBundleHandler(func() { _ = tb.GetDomainBundle() })
					stop()
				case 3:
					snapshotAuthorities(t, tb.GetDomainBundle())
				}
			}
		}(i)
	}
	wg.Wait()
	snapshotAuthorities(t, tb.GetDomainBundle())
}
