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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/protobuf/proto"

	"istio.io/istio/pilot/test/xdstest"
	"istio.io/istio/pkg/security"
	"istio.io/istio/pkg/testcerts"
	"istio.io/istio/security/pkg/nodeagent/cache"
)

func typedDomainStore(t *testing.T, secret *tls.Secret) *tls.SPIFFECertValidatorConfig {
	t.Helper()
	validation := secret.GetValidationContext()
	if validation == nil || validation.TrustedCa != nil || validation.Crl != nil {
		t.Fatal("mapped ROOTCA must use only the typed domain stores")
	}
	extension := validation.GetCustomValidatorConfig()
	if extension.GetName() != "envoy.tls.cert_validator.spiffe" {
		t.Fatal("missing native SPIFFE validator")
	}
	store := &tls.SPIFFECertValidatorConfig{}
	if err := extension.GetTypedConfig().UnmarshalTo(store); err != nil {
		t.Fatal(err)
	}
	if err := store.ValidateAll(); err != nil {
		t.Fatalf("native typed configuration rejected: %v", err)
	}
	return store
}

func TestDomainBundleSDSNativeCRLInputAndSelectedAnchorIsolation(t *testing.T) {
	now := time.Now()
	newCA := func(serial int64) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial),
			Subject: pkix.Name{CommonName: "same-issuer-name"}, SubjectKeyId: []byte{byte(serial)},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	issuer, key, roots := newCA(1)
	otherIssuer, _, otherRoots := newCA(2)
	crl := func(thisUpdate, nextUpdate time.Time) []byte {
		t.Helper()
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number: big.NewInt(1), ThisUpdate: thisUpdate, NextUpdate: nextUpdate,
			RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(99), RevocationTime: thisUpdate}},
		}, issuer, key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	}
	current := crl(now.Add(-time.Minute), now.Add(time.Hour))
	parsed, err := security.ParseWorkloadCRLs(current, now)
	if err != nil || len(parsed) != 1 {
		t.Fatalf("current public CRL was not parsed: %v", err)
	}
	if parsed[0].CheckSignatureFrom(issuer) != nil || parsed[0].CheckSignatureFrom(otherIssuer) == nil {
		t.Fatal("same-name wrong-key CRL fixture did not preserve issuer/signature isolation")
	}
	item := &security.SecretItem{ResourceName: security.RootCertReqResourceName,
		LocalTrustDomain: "local.example", TrustDomainBundles: map[string][]byte{
			"local.example": roots, "foreign.example": otherRoots}, WorkloadCRL: current}
	store := typedDomainStore(t, toEnvoySecret(item, "", nil))
	if len(store.TrustDomains) != 2 {
		t.Fatal("CRL update changed declared root-domain associations")
	}
	for _, entry := range store.TrustDomains {
		inline := entry.GetTrustBundle().GetInlineBytes()
		anchor, tail := pem.Decode(inline)
		want := roots
		if entry.Name == "foreign.example" {
			want = otherRoots
		}
		if anchor == nil || !bytes.Equal(pem.EncodeToMemory(anchor), want) {
			t.Fatal("CRL issuer or another domain anchor was promoted into the selected store")
		}
		revocation, tail := pem.Decode(tail)
		if revocation == nil || revocation.Type != "X509 CRL" || len(bytes.TrimSpace(tail)) != 0 {
			t.Fatal("native typed store lost the public CRL required for CRL_CHECK_ALL")
		}
	}
	for name, invalid := range map[string][]byte{
		"removed": {}, "malformed": []byte("not CRL PEM"), "wrong-material": roots,
		"expired":  crl(now.Add(-time.Hour), now.Add(-time.Minute)),
		"future":   crl(now.Add(time.Minute), now.Add(time.Hour)),
		"trailing": append(bytes.Clone(current), []byte("unexpected")...),
	} {
		t.Run(name, func(t *testing.T) {
			item.WorkloadCRL = invalid
			assertEmptyLocalStore(t, toEnvoySecret(item, "", nil))
		})
	}
	item.WorkloadCRL = current
	if len(typedDomainStore(t, toEnvoySecret(item, "", nil)).TrustDomains) != 2 {
		t.Fatal("valid native CRL recovery did not restore the declared stores")
	}
}

func assertEmptyLocalStore(t *testing.T, secret *tls.Secret) {
	t.Helper()
	store := typedDomainStore(t, secret)
	if len(store.TrustDomains) != 1 || store.TrustDomains[0].Name != "local.example" {
		t.Fatal("complete removal must retain exactly the known local denying entry")
	}
	entry := store.TrustDomains[0]
	if entry.WorkloadTrustDomain != "" {
		t.Fatal("deny placeholder must not introduce routing-based store selection")
	}
	inline, ok := entry.GetTrustBundle().GetSpecifier().(*core.DataSource_InlineBytes)
	if !ok || len(inline.InlineBytes) != 0 {
		t.Fatal("deny placeholder must select an explicit zero-anchor inline store")
	}
}

func TestDomainBundleSDSCompleteRemovalUsesAcceptedEmptyInlineStore(t *testing.T) {
	for _, roots := range []map[string][]byte{{}, {"foreign.example": nil}, {"local.example": {}}} {
		secret := toEnvoySecret(&security.SecretItem{
			ResourceName:       security.RootCertReqResourceName,
			LocalTrustDomain:   "local.example",
			TrustDomainBundles: roots,
			// This old flat material must never return after mapped removal.
			RootCert: testcerts.CACert,
		}, "", nil)
		assertEmptyLocalStore(t, secret)
		// An empty bytes oneof must survive the real protobuf wire encoding.
		wire, err := proto.Marshal(secret)
		if err != nil {
			t.Fatal(err)
		}
		decoded := &tls.Secret{}
		if err := proto.Unmarshal(wire, decoded); err != nil {
			t.Fatal(err)
		}
		assertEmptyLocalStore(t, decoded)
	}
}

func TestDomainBundleSDSPreservesDefaultAndExternalRootResources(t *testing.T) {
	defaultSecret := toEnvoySecret(&security.SecretItem{
		ResourceName:       security.WorkloadKeyCertResourceName,
		CertificateChain:   []byte("own public chain"),
		PrivateKey:         []byte("test key"),
		TrustDomainBundles: map[string][]byte{},
		LocalTrustDomain:   "local.example",
	}, "", nil)
	if defaultSecret.GetValidationContext() != nil || !bytes.Equal(defaultSecret.GetTlsCertificate().GetCertificateChain().GetInlineBytes(),
		[]byte("own public chain")) {
		t.Fatal("default workload identity was replaced by ROOTCA validation data")
	}
	for _, name := range []string{security.RootCertReqResourceName, "file-root:/external/ca.pem"} {
		item := &security.SecretItem{ResourceName: name, RootCert: testcerts.CACert}
		if name != security.RootCertReqResourceName {
			item.TrustDomainBundles = map[string][]byte{}
			item.LocalTrustDomain = "local.example"
		}
		secret := toEnvoySecret(item, "", nil)
		if secret.GetValidationContext().GetCustomValidatorConfig() != nil ||
			!bytes.Equal(secret.GetValidationContext().GetTrustedCa().GetInlineBytes(), testcerts.CACert) {
			t.Fatal("legacy or external file-root TLS was converted to mapped workload authority")
		}
	}
}

func TestDomainBundleSDSReferencedROOTCAUpdateDenyAndRecovery(t *testing.T) {
	// setupSDS changes cwd for its native relative UDS. Keep a restoration
	// handle so a later real-reader test cannot inherit a deleted directory.
	t.Chdir(t.TempDir())
	s := setupSDS(t)
	root := s.Connect()
	item := func(roots map[string][]byte) *security.SecretItem {
		return &security.SecretItem{ResourceName: security.RootCertReqResourceName,
			LocalTrustDomain: "local.example", TrustDomainBundles: roots}
	}
	verify := func(response *discovery.DiscoveryResponse, denied bool) {
		t.Helper()
		if len(response.Resources) != 1 {
			t.Fatal("referenced ROOTCA must be updated, never withdrawn")
		}
		secret := xdstest.ExtractTLSSecrets(t, response.Resources)[security.RootCertReqResourceName]
		if denied {
			assertEmptyLocalStore(t, secret)
			return
		}
		store := typedDomainStore(t, secret)
		if len(store.TrustDomains) != 1 || store.TrustDomains[0].Name != "foreign.example" ||
			!bytes.Equal(store.TrustDomains[0].GetTrustBundle().GetInlineBytes(), testcerts.CACert) {
			t.Fatal("valid recovery did not publish the exact per-domain store")
		}
	}
	s.UpdateSecret(security.RootCertReqResourceName, item(map[string][]byte{"foreign.example": testcerts.CACert}))
	response := root.RequestResponseAck(t, &discovery.DiscoveryRequest{ResourceNames: []string{security.RootCertReqResourceName}})
	verify(response, false)
	for _, roots := range []map[string][]byte{{}, {"foreign.example": testcerts.CACert}} {
		s.UpdateSecret(security.RootCertReqResourceName, item(roots))
		response = root.ExpectResponse(t)
		verify(response, len(roots) == 0)
		root.Request(t, &discovery.DiscoveryRequest{ResourceNames: []string{security.RootCertReqResourceName},
			ResponseNonce: response.Nonce, VersionInfo: response.VersionInfo})
		root.ExpectNoResponse(t)
	}
	// A new reference after removal must receive denial as well, not old roots.
	s.UpdateSecret(security.RootCertReqResourceName, item(map[string][]byte{}))
	verify(root.ExpectResponse(t), true)
	reconnected := s.Connect()
	verify(reconnected.RequestResponseAck(t, &discovery.DiscoveryRequest{ResourceNames: []string{security.RootCertReqResourceName}}), true)
}

func TestDomainBundleSDSRealProjectionReaderRemovalAndRecovery(t *testing.T) {
	block, _ := pem.Decode(testcerts.CACert)
	anchor, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	canonicalAnchor := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: anchor.Raw})
	bundle, err := spiffebundle.FromX509Authorities(spiffeid.RequireTrustDomainFromString("foreign.example"), []*x509.Certificate{anchor}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	granting, err := json.Marshal(map[string]any{"trust_domains": map[string]json.RawMessage{"foreign.example": bundle}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "projection", "spiffe-bundle-map.json")
	if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(granting)
	options := &security.Options{TrustDomain: "local.example", SPIFFEBundleMapPath: path, FileMountedCerts: true}
	reader, err := cache.NewSecretManagerClient(nil, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	// Reuse the native SDS test server/UDS interface with the actual file reader,
	// rather than DirectSecretManager.UpdateSecret. No arbitrary secret removal.
	t.Chdir(t.TempDir())
	server := NewServer(options, reader, nil)
	t.Cleanup(server.Stop)
	reader.RegisterSecretHandler(server.OnSecretUpdate)
	client := (&TestServer{t: t, server: server, udsPath: security.GetIstioSDSServerSocketPath()}).Connect()
	verify := func(response *discovery.DiscoveryResponse, deny bool) bool {
		t.Helper()
		if len(response.Resources) != 1 {
			t.Fatal("referenced ROOTCA was withdrawn instead of updated")
		}
		secret := xdstest.ExtractTLSSecrets(t, response.Resources)[security.RootCertReqResourceName]
		store := typedDomainStore(t, secret)
		if deny {
			if len(store.TrustDomains) != 1 || store.TrustDomains[0].Name != "local.example" ||
				len(store.TrustDomains[0].TrustBundle.GetInlineBytes()) != 0 {
				return false
			}
			assertEmptyLocalStore(t, secret)
			return true
		}
		if len(store.TrustDomains) != 1 || store.TrustDomains[0].Name != "foreign.example" ||
			!bytes.Equal(store.TrustDomains[0].TrustBundle.GetInlineBytes(), canonicalAnchor) {
			return false
		}
		return true
	}
	response := client.RequestResponseAck(t, &discovery.DiscoveryRequest{ResourceNames: []string{security.RootCertReqResourceName}})
	if !verify(response, false) {
		t.Fatal("wrong initial native projection authority")
	}
	for _, data := range [][]byte{[]byte(`{"trust_domains":{}}`), granting, []byte(`{"trust_domains":{"foreign.example":{},"foreign\u002eexample":{}}}`)} {
		write(data)
		// A second reader can observe the new state before native event dispatch.
		// The already-referenced first stream must still receive an actual update.
		if _, err := reader.GenerateSecret(security.RootCertReqResourceName); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			response = client.ExpectResponse(t)
			current := verify(response, !bytes.Equal(data, granting))
			client.Request(t, &discovery.DiscoveryRequest{ResourceNames: []string{security.RootCertReqResourceName},
				ResponseNonce: response.Nonce, VersionInfo: response.VersionInfo})
			if current {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("referenced stream did not converge on current authority")
			}
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		response = client.ExpectResponse(t)
		current := verify(response, true)
		client.Request(t, &discovery.DiscoveryRequest{ResourceNames: []string{security.RootCertReqResourceName},
			ResponseNonce: response.Nonce, VersionInfo: response.VersionInfo})
		if current {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native deletion did not update referenced ROOTCA")
		}
	}
}
