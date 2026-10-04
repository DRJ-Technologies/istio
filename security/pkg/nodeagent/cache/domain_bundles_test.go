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

package cache

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"istio.io/istio/pkg/queue"
	"istio.io/istio/pkg/security"
	"istio.io/istio/pkg/test/util/retry"
	"istio.io/istio/pkg/testcerts"
	pkiutil "istio.io/istio/security/pkg/pki/util"
)

func domainBundleProjection(t *testing.T, domain string) []byte {
	t.Helper()
	block, _ := pem.Decode(testcerts.CACert)
	anchor, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	td, err := spiffeid.TrustDomainFromString(domain)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := spiffebundle.FromX509Authorities(td, []*x509.Certificate{anchor}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := json.Marshal(map[string]any{"trust_domains": map[string]json.RawMessage{domain: bundle}})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func workloadDomainTestCA(t *testing.T) ([]byte, *x509.Certificate, crypto.PrivateKey) {
	t.Helper()
	root, key, err := pkiutil.GenCertKeyFromOptions(pkiutil.CertOptions{
		Host: "test-root", TTL: time.Hour, IsCA: true, IsSelfSigned: true, ECSigAlg: pkiutil.EcdsaSigAlg,
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := pkiutil.ParsePemEncodedCertificate(root)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := pkiutil.ParsePemEncodedKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return root, cert, priv
}

func TestDomainBundleFallbackQualifiesOnlyOwnNativeIdentityAndAnchors(t *testing.T) {
	root, issuer, key := workloadDomainTestCA(t)
	other, _, _ := workloadDomainTestCA(t)
	options := &security.Options{TrustDomain: "local.example", WorkloadNamespace: "own", ServiceAccount: "own"}
	for _, c := range []struct {
		name, identity        string
		client, server, valid bool
	}{
		{"own", "spiffe://local.example/ns/own/sa/own", true, true, true},
		{"foreign", "spiffe://foreign.example/ns/own/sa/own", true, true, false},
		{"other-namespace", "spiffe://local.example/ns/other/sa/own", true, true, false},
		{"other-account", "spiffe://local.example/ns/own/sa/other", true, true, false},
		{"DNS-only", "local.example", true, true, false},
		{"domain-root", "spiffe://local.example/", true, true, false},
		{"duplicate-URI", "spiffe://local.example/ns/own/sa/own,spiffe://local.example/ns/own/sa/own", true, true, false},
		{"mixed-URI", "spiffe://local.example/ns/own/sa/own,spiffe://foreign.example/ns/own/sa/own", true, true, false},
		{"client-only", "spiffe://local.example/ns/own/sa/own", true, false, false},
		{"server-only", "spiffe://local.example/ns/own/sa/own", false, true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			leaf, _, err := pkiutil.GenCertKeyFromOptions(pkiutil.CertOptions{
				Host: c.identity, TTL: time.Hour, SignerCert: issuer, SignerPriv: key,
				IsClient: c.client, IsServer: c.server, ECSigAlg: pkiutil.EcdsaSigAlg,
			})
			if err != nil {
				t.Fatal(err)
			}
			anchors := append(bytes.Clone(other), root...)
			got, err := qualifyLocalWorkloadRoots(append(bytes.Clone(leaf), root...), anchors, options)
			if c.valid {
				if err != nil || !bytes.Equal(got, root) {
					t.Fatalf("native own-chain qualification pooled unrelated roots: %v", err)
				}
				sc := &SecretManagerClient{configOptions: options, domainBundles: &workloadDomainBundles{}}
				sc.configOptions.SPIFFEBundleMapPath = filepath.Join(t.TempDir(), "absent.json")
				sc.cache.SetWorkload(&security.SecretItem{CertificateChain: leaf, RootCert: anchors, ExpireTime: time.Now().Add(time.Hour)})
				sc.configTrustBundle = other // PCDS cannot supply fallback authority.
				item := sc.domainBundleSecret()
				if len(item.TrustDomainBundles) != 1 || !bytes.Equal(item.TrustDomainBundles["local.example"], root) {
					t.Fatal("initial fallback did not retain only own qualified domain roots")
				}
			} else if len(got) != 0 {
				t.Fatal("unqualified own identity or TLS purpose became fallback authority")
			}
		})
	}
}

type gatedDomainCA struct {
	entered, release chan struct{}
	root             []byte
	issuer           *x509.Certificate
	key              crypto.PrivateKey
}

func (c *gatedDomainCA) CSRSign(csrPEM []byte, _ int64) ([]string, error) {
	close(c.entered)
	<-c.release
	csr, err := pkiutil.ParsePemEncodedCSR(csrPEM)
	if err != nil {
		return nil, err
	}
	der, err := pkiutil.GenCertFromCSR(csr, c.issuer, csr.PublicKey, c.key,
		[]string{"spiffe://local.example/ns/own/sa/own"}, time.Hour, false)
	if err != nil {
		return nil, err
	}
	return []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(c.root)}, nil
}
func (c *gatedDomainCA) GetRootCertBundle() ([]string, error) { return []string{string(c.root)}, nil }
func (c *gatedDomainCA) Close()                               {}

func TestDomainBundleAuthoritativeRemovalWinsInFlightLocalBootstrap(t *testing.T) {
	root, issuer, key := workloadDomainTestCA(t)
	ca := &gatedDomainCA{entered: make(chan struct{}), release: make(chan struct{}), root: root, issuer: issuer, key: key}
	path := filepath.Join(t.TempDir(), "spiffe-bundle-map.json")
	sc := &SecretManagerClient{caClient: ca, queue: queue.NewDelayed(queue.DelayQueueBuffer(1)),
		configOptions: &security.Options{SPIFFEBundleMapPath: path, TrustDomain: "local.example",
			WorkloadNamespace: "own", ServiceAccount: "own", ECCSigAlg: string(pkiutil.EcdsaSigAlg), SecretTTL: time.Hour},
		domainBundles: &workloadDomainBundles{directory: filepath.Dir(path)}}
	result := make(chan *security.SecretItem, 1)
	go func() { result <- sc.domainBundleSecret() }()
	select {
	case <-ca.entered:
	case <-time.After(time.Second * 5):
		t.Fatal("native bootstrap never requested an own SVID")
	}
	if err := os.WriteFile(path, []byte(`{"trust_domains":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	close(ca.release)
	select {
	case item := <-result:
		if item.TrustDomainBundles == nil || len(item.TrustDomainBundles) != 0 {
			t.Fatal("completed CSR restored local authority after mapped removal")
		}
		own := sc.cache.GetWorkload()
		if own == nil {
			t.Fatal("the native CSR did not complete")
		}
		if qualified, err := qualifyLocalWorkloadRoots(own.CertificateChain, own.RootCert, sc.configOptions); err != nil || len(qualified) == 0 {
			t.Fatalf("fixture did not provide otherwise valid native fallback: %v", err)
		}
	case <-time.After(time.Second * 5):
		t.Fatal("bootstrap did not return after CSR release")
	}
}

func TestDomainBundleNativeProjectionWatchDenyRecoveryAndCRLRemoval(t *testing.T) {
	parent := t.TempDir()
	directory := filepath.Join(parent, "projection")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "spiffe-bundle-map.json")
	if err := os.WriteFile(path, domainBundleProjection(t, "foreign.example"), 0o600); err != nil {
		t.Fatal(err)
	}
	updates := make(chan struct{}, 32)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	crlPath := filepath.Join(directory, "ca-crl.pem")
	sc := &SecretManagerClient{certWatcher: watcher, stop: make(chan struct{}), fileCerts: make(map[FileCert]struct{}),
		configOptions: &security.Options{SPIFFEBundleMapPath: path, TrustDomain: "local.example"},
		domainBundles: &workloadDomainBundles{directory: directory, crlPath: crlPath}}
	t.Cleanup(sc.Close)
	if err := sc.watchDomainBundleDirectories(); err != nil {
		t.Fatal(err)
	}
	sc.RegisterSecretHandler(func(name string) {
		if name == security.RootCertReqResourceName {
			select {
			case updates <- struct{}{}:
			default:
			}
		}
	})
	go sc.handleFileWatch()
	verify := func(want int, crl []byte) {
		t.Helper()
		retry.UntilSuccessOrFail(t, func() error {
			item := sc.domainBundleSecret()
			if len(item.TrustDomainBundles) != want || !bytes.Equal(item.WorkloadCRL, crl) || (item.WorkloadCRL == nil) != (crl == nil) {
				return fmt.Errorf("projection state has not converged")
			}
			return nil
		})
	}
	verify(1, nil)
	if err := os.WriteFile(crlPath, []byte("public CRL fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	verify(1, []byte("public CRL fixture"))
	// Capture notifications, not just a synchronous file read.
	select {
	case <-updates:
	case <-time.After(time.Second * 5):
		t.Fatal("native CRL change did not notify ROOTCA")
	}
	if err := os.Remove(crlPath); err != nil {
		t.Fatal(err)
	}
	verify(1, []byte{})
	if err := os.Rename(directory, directory+".old"); err != nil {
		t.Fatal(err)
	}
	verify(0, []byte{})
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, domainBundleProjection(t, "foreign.example"), 0o600); err != nil {
		t.Fatal(err)
	}
	verify(1, []byte{})
	// Failure to re-establish a watch must actively replace old authority.
	if err := sc.certWatcher.Close(); err != nil {
		t.Fatal(err)
	}
	if !sc.domainBundleFileEvent(fsnotify.Event{Name: path, Op: fsnotify.Write}) {
		t.Fatal("watch failure did not schedule denying update")
	}
	verify(0, []byte{})
}

func TestDomainBundleProjectionRemovalErrorRecoveryAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spiffe-bundle-map.json")
	newReader := func() *SecretManagerClient {
		return &SecretManagerClient{configOptions: &security.Options{
			SPIFFEBundleMapPath: path, TrustDomain: "local.example",
		}, domainBundles: &workloadDomainBundles{directory: filepath.Dir(path)}}
	}
	sc := newReader()
	if sc.refreshDomainBundles() || sc.domainBundles.mapped {
		t.Fatal("initial optional absence must not pretend a map was activated")
	}
	write := func(data []byte) {
		t.Helper()
		// Use atomic replacement, as a projection publisher would do.
		tmp := path + ".next"
		if err := os.WriteFile(tmp, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, path); err != nil {
			t.Fatal(err)
		}
	}
	assertStore := func(reader *SecretManagerClient, domain string) {
		t.Helper()
		item, err := reader.GenerateSecret(security.RootCertReqResourceName)
		if err != nil || item == nil || item.TrustDomainBundles == nil || item.LocalTrustDomain != "local.example" {
			t.Fatalf("mapped ROOTCA must publish an accepted complete snapshot: %v", err)
		}
		if len(item.RootCert) != 0 || len(item.PrivateKey) != 0 || len(item.CertificateChain) != 0 {
			t.Fatal("mapped validation snapshot borrowed flat roots or workload key material")
		}
		if domain == "" {
			if len(item.TrustDomainBundles) != 0 {
				t.Fatal("mapped removal or read failure retained authority")
			}
		} else if len(item.TrustDomainBundles) != 1 || len(item.TrustDomainBundles[domain]) == 0 {
			t.Fatal("domain-isolated valid authority did not recover")
		}
	}
	write(domainBundleProjection(t, "foreign.example"))
	assertStore(sc, "foreign.example")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	assertStore(sc, "")
	for _, invalid := range []string{
		`{"trust_domains":{"foreign.example":{"keys":[]},"foreign.\u0065xample":{"keys":[]}}}`,
		`not JSON`,
	} {
		write(domainBundleProjection(t, "foreign.example"))
		assertStore(sc, "foreign.example")
		write([]byte(invalid))
		assertStore(sc, "")
	}
	// An explicit empty projection is authoritative across agent restart.
	write([]byte(`{"trust_domains":{}}`))
	sc = newReader()
	assertStore(sc, "")
	write(domainBundleProjection(t, "local.example"))
	assertStore(sc, "local.example")
	// SDS owns an immutable copy, even while another caller mutates its copy.
	item := sc.domainBundleSecret()
	item.TrustDomainBundles["local.example"][0] ^= 0xff
	delete(item.TrustDomainBundles, "local.example")
	assertStore(sc, "local.example")
	// A mapped unreadable projection cannot return the initial native fallback.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	assertStore(sc, "")
}
