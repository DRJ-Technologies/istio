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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pkg/security"
	"istio.io/istio/pkg/spiffe"
)

type workloadDomainBundles struct {
	mu sync.Mutex
	// Once mapped, absence/error is an explicit empty snapshot, never fallback.
	mapped      bool
	watchFailed bool
	roots       map[string][]byte
	directory   string
	crlPath     string
	crl         []byte
}

func cloneDomainRoots(roots map[string][]byte) map[string][]byte {
	copy := make(map[string][]byte, len(roots))
	for name, anchors := range roots {
		copy[name] = bytes.Clone(anchors)
	}
	return copy
}

func sameDomainRoots(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for name, roots := range a {
		other, exists := b[name]
		if !exists || !bytes.Equal(roots, other) {
			return false
		}
	}
	return true
}

func (sc *SecretManagerClient) initializeDomainBundles() error {
	path := sc.configOptions.SPIFFEBundleMapPath
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("SPIFFE_BUNDLE_MAP_PATH must be a full path")
	}
	td, err := spiffeid.TrustDomainFromString(sc.configOptions.TrustDomain)
	if err != nil || td.Name() != sc.configOptions.TrustDomain || td.Name() == "" {
		return fmt.Errorf("mapped workload trust requires the canonical local trust domain")
	}
	sc.domainBundles = &workloadDomainBundles{directory: filepath.Dir(path)}
	if features.EnableCACRL {
		sc.domainBundles.crlPath = security.CACRLFilePath
	}
	// Reuse the existing watcher descriptor. Watching the projection directory
	// observes Kubernetes ..data replacement without relying on a subPath inode.
	if err := sc.watchDomainBundleDirectories(); err != nil {
		cacheLog.Errorf("cannot watch workload trust inputs; mapped authority denied: %v", err)
		sc.denyDomainBundles()
	}
	sc.refreshDomainBundles()
	return nil
}

func (sc *SecretManagerClient) refreshDomainBundles() bool {
	b := sc.domainBundles
	if b == nil {
		return false
	}
	// Serialize reads as well as swaps: an earlier file read must not overwrite
	// a later complete snapshot when SDS and watcher callbacks race.
	b.mu.Lock()
	defer b.mu.Unlock()
	crlChanged := sc.refreshWorkloadCRLLocked()
	if b.watchFailed {
		changed := !b.mapped || len(b.roots) != 0
		b.mapped, b.roots = true, map[string][]byte{}
		return changed || crlChanged
	}
	data, err := os.ReadFile(sc.configOptions.SPIFFEBundleMapPath)
	if os.IsNotExist(err) && !b.mapped {
		// Optional initial absence permits only own-chain-qualified local roots.
		return crlChanged
	}
	roots := map[string][]byte{}
	if err == nil {
		roots, err = spiffe.ParseBundleMap(data)
	}
	if err != nil {
		cacheLog.Errorf("cannot read valid workload bundle map; mapped authority denied: %v", err)
		roots = map[string][]byte{}
	}
	changed := !b.mapped || !sameDomainRoots(b.roots, roots)
	b.roots, b.mapped = roots, true
	return changed || crlChanged
}

// Both projections use the existing watcher descriptor. Watch a parent as
// well, so a removed directory can recover and an initially missing optional
// mount can appear. No directories/files are created by the trust consumer.
func (sc *SecretManagerClient) watchDomainBundleDirectories() error {
	directories := []string{sc.domainBundles.directory}
	if sc.domainBundles.crlPath != "" {
		directories = append(directories, filepath.Dir(sc.domainBundles.crlPath))
	}
	for _, directory := range directories {
		for _, candidate := range []string{filepath.Dir(directory), directory} {
			for {
				info, err := os.Stat(candidate)
				if err == nil {
					if !info.IsDir() {
						return fmt.Errorf("workload trust projection parent is not a directory")
					}
					break
				}
				if !os.IsNotExist(err) || candidate == filepath.Dir(candidate) {
					return err
				}
				candidate = filepath.Dir(candidate)
			}
			if err := sc.certWatcher.Add(candidate); err != nil {
				return err
			}
		}
	}
	return nil
}

func (sc *SecretManagerClient) denyDomainBundles() bool {
	b := sc.domainBundles
	b.mu.Lock()
	defer b.mu.Unlock()
	changed := !b.mapped || !b.watchFailed || len(b.roots) != 0
	b.mapped, b.watchFailed, b.roots = true, true, map[string][]byte{}
	return changed
}

func (sc *SecretManagerClient) refreshWorkloadCRLLocked() bool {
	b := sc.domainBundles
	if b.crlPath == "" {
		return false
	}
	data, err := os.ReadFile(b.crlPath)
	if os.IsNotExist(err) && b.crl == nil {
		return false
	}
	if err != nil {
		// A provided CRL is never silently withdrawn. SDS translates explicit
		// empty input into a valid denying store, not a NACK retaining old roots.
		data = []byte{}
	}
	changed := (b.crl == nil) != (data == nil) || !bytes.Equal(b.crl, data)
	b.crl = bytes.Clone(data)
	return changed
}

func (sc *SecretManagerClient) domainBundleFileEvent(event fsnotify.Event) bool {
	b := sc.domainBundles
	if b == nil {
		return false
	}
	affects := func(directory string) bool {
		return event.Name == directory || filepath.Dir(event.Name) == directory ||
			strings.HasPrefix(directory, event.Name+string(filepath.Separator))
	}
	if !affects(b.directory) && (b.crlPath == "" || !affects(filepath.Dir(b.crlPath))) {
		return false
	}
	// Recover only through a working watch of the same projection directory.
	if err := sc.watchDomainBundleDirectories(); err != nil {
		return sc.denyDomainBundles()
	}
	b.mu.Lock()
	b.watchFailed = false
	b.mu.Unlock()
	return sc.refreshDomainBundles()
}

func (sc *SecretManagerClient) domainBundleSecret() *security.SecretItem {
	// Read now as well as on events. A caller cannot receive old roots merely
	// because the native watcher has not dispatched an already-visible update.
	sc.refreshDomainBundles()
	b := sc.domainBundles
	b.mu.Lock()
	mapped, roots, crl := b.mapped, cloneDomainRoots(b.roots), bytes.Clone(b.crl)
	b.mu.Unlock()
	if !mapped {
		// Generate/read only our own workload SVID. Endpoint CA/xDS roots and
		// ProxyConfig/PCDS flat roots are never fallback authority.
		own, err := sc.GenerateSecret(security.WorkloadKeyCertResourceName)
		if err == nil {
			var anchors []byte
			if cached := sc.cache.GetWorkload(); cached != nil {
				anchors = cached.RootCert
			} else if sc.configOptions.FileMountedCerts {
				anchors, err = os.ReadFile(sc.existingCertificateFile.CaCertificatePath)
			}
			if err == nil {
				qualified, qualifyErr := qualifyLocalWorkloadRoots(own.CertificateChain, anchors, sc.configOptions)
				if qualifyErr == nil && len(qualified) > 0 {
					roots[sc.configOptions.TrustDomain] = qualified
				}
			}
		}
		// Signing/read may have waited while the authoritative map arrived.
		// Recheck under the same lock; fallback can never override mapped removal.
		sc.refreshDomainBundles()
		b.mu.Lock()
		if b.mapped {
			roots = cloneDomainRoots(b.roots)
		}
		crl = bytes.Clone(b.crl)
		b.mu.Unlock()
	}
	return &security.SecretItem{ResourceName: security.RootCertReqResourceName,
		TrustDomainBundles: roots, LocalTrustDomain: sc.configOptions.TrustDomain, WorkloadCRL: crl}
}

func parseWorkloadCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for rest := bytes.TrimSpace(data); len(rest) > 0; {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, fmt.Errorf("invalid workload certificate material")
		}
		end := bytes.Index(rest, []byte("-----END CERTIFICATE-----"))
		if end < 0 {
			return nil, fmt.Errorf("unterminated workload certificate")
		}
		end += len("-----END CERTIFICATE-----")
		if bytes.Count(rest[:end], []byte("-----BEGIN")) != 1 {
			return nil, fmt.Errorf("skipped workload certificate block")
		}
		block, tail := pem.Decode(rest[:end])
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(tail)) != 0 {
			return nil, fmt.Errorf("invalid workload certificate PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		rest = bytes.TrimSpace(rest[end:])
	}
	return certs, nil
}

func qualifyLocalWorkloadRoots(chain, anchors []byte, options *security.Options) ([]byte, error) {
	certs, err := parseWorkloadCertificates(chain)
	if err != nil || len(certs) == 0 {
		return nil, fmt.Errorf("missing valid own workload chain")
	}
	leaf := certs[0]
	if leaf.IsCA || leaf.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 || len(leaf.URIs) != 1 {
		return nil, fmt.Errorf("own workload SVID requires exactly one URI")
	}
	id, err := spiffeid.FromURI(leaf.URIs[0])
	if err != nil || id.String() != leaf.URIs[0].String() || id.Path() == "" || id.Path() == "/" || id.TrustDomain().Name() != options.TrustDomain {
		return nil, fmt.Errorf("own SVID is not in the configured local domain")
	}
	identity, err := spiffe.ParseIdentity(id.String())
	if err != nil || identity.Namespace == "" || identity.ServiceAccount == "" ||
		identity.Namespace != options.WorkloadNamespace || identity.ServiceAccount != options.ServiceAccount {
		return nil, fmt.Errorf("own SVID does not match the native workload identity")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	candidates, err := parseWorkloadCertificates(anchors)
	if err != nil {
		return nil, err
	}
	qualified := map[string]*x509.Certificate{}
	for _, anchor := range candidates {
		if !anchor.BasicConstraintsValid || !anchor.IsCA || (anchor.KeyUsage != 0 && anchor.KeyUsage&x509.KeyUsageCertSign == 0) {
			continue
		}
		roots := x509.NewCertPool()
		roots.AddCert(anchor)
		valid := true
		for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth} {
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
				valid = false
				break
			}
		}
		if valid {
			qualified[string(anchor.Raw)] = anchor
		}
	}
	keys := make([]string, 0, len(qualified))
	for key := range qualified {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var result []byte
	for _, key := range keys {
		result = append(result, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: qualified[key].Raw})...)
	}
	return result, nil
}
