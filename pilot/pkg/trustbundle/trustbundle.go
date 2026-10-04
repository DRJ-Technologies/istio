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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sort"
	"sync"
	"time"

	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pkg/config/mesh"
	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/spiffe"
	"istio.io/istio/pkg/util/sets"
)

// Source is all possible sources of MeshConfig
type Source int

const (
	SourceIstioCA Source = iota
	SourceMeshConfig
	SourceIstioRA
	sourceSpiffeEndpoints

	RemoteDefaultPollPeriod = 30 * time.Minute
)

func (s Source) String() string {
	switch s {
	case SourceIstioCA:
		return "IstioCA"
	case SourceMeshConfig:
		return "MeshConfig"
	case SourceIstioRA:
		return "IstioRA"
	case sourceSpiffeEndpoints:
		return "SpiffeEndpoints"
	default:
		return "Unknown"
	}
}

type TrustAnchorConfig struct {
	Certs []string
}

type TrustAnchorUpdate struct {
	TrustAnchorConfig
	Source Source
}

type TrustBundle struct {
	sourceConfig       map[Source]TrustAnchorConfig
	mutex              sync.RWMutex
	mergedCerts        []string
	updatecb           func()
	endpointMutex      sync.RWMutex
	endpoints          []string
	endpointUpdateChan chan struct{}
	remoteCaCertPool   *x509.CertPool
	meshConfig         mesh.Watcher
	domains            domainBundleState
}

var (
	trustBundleLog = log.RegisterScope("trustBundle", "Workload mTLS trust bundle logs")
	remoteTimeout  = 10 * time.Second
)

// NewTrustBundle returns a new trustbundle
func NewTrustBundle(remoteCaCertPool *x509.CertPool, meshConfig mesh.Watcher) *TrustBundle {
	var err error
	tb := &TrustBundle{
		sourceConfig: map[Source]TrustAnchorConfig{
			SourceIstioCA:         {Certs: []string{}},
			SourceMeshConfig:      {Certs: []string{}},
			SourceIstioRA:         {Certs: []string{}},
			sourceSpiffeEndpoints: {Certs: []string{}},
		},
		mergedCerts:        []string{},
		updatecb:           nil,
		endpointUpdateChan: make(chan struct{}, 1),
		endpoints:          []string{},
		meshConfig:         meshConfig,
		domains:            newDomainBundleState(),
	}
	if remoteCaCertPool == nil {
		tb.remoteCaCertPool, err = x509.SystemCertPool()
		if err != nil {
			trustBundleLog.Errorf("failed to initialize remote Cert pool: %v", err)
		}
	} else {
		tb.remoteCaCertPool = remoteCaCertPool
	}
	return tb
}

func (tb *TrustBundle) UpdateCb(updatecb func()) {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()
	tb.updatecb = updatecb
}

// GetTrustBundle : Retrieves all the trustAnchors for current Spiffee Trust Domain
func (tb *TrustBundle) GetTrustBundle() []string {
	tb.mutex.RLock()
	defer tb.mutex.RUnlock()
	trustedCerts := make([]string, len(tb.mergedCerts))
	copy(trustedCerts, tb.mergedCerts)
	return trustedCerts
}

func verifyTrustAnchor(trustAnchor string) error {
	_, err := parseDomainTrustAnchors([]string{trustAnchor})
	return err
}

func (tb *TrustBundle) mergeInternalLocked() {
	var mergeCerts []string
	certMap := sets.New[string]()

	for _, configSource := range tb.sourceConfig {
		for _, cert := range configSource.Certs {
			if !certMap.InsertContains(cert) {
				mergeCerts = append(mergeCerts, cert)
			}
		}
	}
	tb.mergedCerts = mergeCerts
	sort.Strings(tb.mergedCerts)
}

// UpdateTrustAnchor : External Function to merge a TrustAnchor config with the existing TrustBundle
func (tb *TrustBundle) UpdateTrustAnchor(anchorConfig *TrustAnchorUpdate) error {
	if anchorConfig == nil {
		return fmt.Errorf("nil trust anchor update")
	}
	certs, err := parseDomainTrustAnchors(anchorConfig.Certs)
	tb.mutex.Lock()
	cachedConfig, ok := tb.sourceConfig[anchorConfig.Source]
	if !ok {
		tb.mutex.Unlock()
		return fmt.Errorf("invalid source of TrustBundle configuration %v", anchorConfig.Source)
	}
	// Only native workload CA/RA roots bind implicitly to the local domain. A
	// legacy flat source (including fetched endpoint roots) never grants a domain.
	native := anchorConfig.Source == SourceIstioCA || anchorConfig.Source == SourceIstioRA
	if err != nil {
		if native {
			tb.domains.invalidSources.Insert(anchorConfig.Source)
		}
		handlers := tb.refreshDomainBundleLocked()
		tb.mutex.Unlock()
		notifyDomainBundleHandlers(handlers)
		return err
	}
	changed := !slices.Equal(anchorConfig.Certs, cachedConfig.Certs)
	if changed {
		tb.sourceConfig[anchorConfig.Source] = TrustAnchorConfig{Certs: slices.Clone(anchorConfig.Certs)}
		tb.mergeInternalLocked()
	}
	if native {
		tb.domains.nativeRoots[anchorConfig.Source] = certs
		tb.domains.invalidSources.Delete(anchorConfig.Source)
	}
	handlers := tb.refreshDomainBundleLocked()
	updatecb := tb.updatecb
	tb.mutex.Unlock()
	notifyDomainBundleHandlers(handlers)
	if changed && updatecb != nil {
		updatecb()
	}
	return nil
}

func (tb *TrustBundle) updateRemoteEndpoint(spiffeEndpoints []string) {
	tb.endpointMutex.RLock()
	remoteEndpoints := tb.endpoints
	tb.endpointMutex.RUnlock()

	if slices.Equal(spiffeEndpoints, remoteEndpoints) {
		return
	}
	trustBundleLog.Infof("updated remote endpoints  :%v", spiffeEndpoints)
	tb.endpointMutex.Lock()
	tb.endpoints = spiffeEndpoints
	tb.endpointMutex.Unlock()
	tb.endpointUpdateChan <- struct{}{}
}

// AddMeshConfigUpdate : Update trustAnchor configurations from meshConfig
func (tb *TrustBundle) AddMeshConfigUpdate(cfg *meshconfig.MeshConfig) error {
	local, bindings, err := meshDomainTrustAnchors(cfg)
	tb.mutex.Lock()
	tb.domains.localDomain = local
	tb.domains.meshRoots = bindings
	tb.domains.meshValid = err == nil
	// The legacy flat API is retained for existing consumers, but explicitly
	// foreign roots must not be pooled into the local workload root response.
	changed := false
	if err == nil {
		localPEM := make([]string, 0, len(bindings[local]))
		for _, cert := range bindings[local] {
			localPEM = append(localPEM, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
		}
		changed = !slices.Equal(localPEM, tb.sourceConfig[SourceMeshConfig].Certs)
		tb.sourceConfig[SourceMeshConfig] = TrustAnchorConfig{Certs: localPEM}
		tb.mergeInternalLocked()
	}
	handlers := tb.refreshDomainBundleLocked()
	updatecb := tb.updatecb
	tb.mutex.Unlock()
	notifyDomainBundleHandlers(handlers)
	if changed && updatecb != nil {
		updatecb()
	}
	return err
}

func (tb *TrustBundle) fetchRemoteTrustAnchors() {
	var err error

	tb.endpointMutex.RLock()
	remoteEndpoints := tb.endpoints
	tb.endpointMutex.RUnlock()
	remoteCerts := []string{}

	currentTrustDomain := tb.meshConfig.Mesh().GetTrustDomain()
	for _, endpoint := range remoteEndpoints {
		trustDomainAnchorMap, err := spiffe.RetrieveSpiffeBundleRootCerts(
			map[string]string{currentTrustDomain: endpoint}, tb.remoteCaCertPool, remoteTimeout)
		if err != nil {
			trustBundleLog.Errorf("unable to fetch trust Anchors from endpoint %s: %s", endpoint, err)
			continue
		}
		certs := trustDomainAnchorMap[currentTrustDomain]
		for _, cert := range certs {
			certStr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
			trustBundleLog.Debugf("from endpoint %v, fetched trust anchor cert: %v", endpoint, certStr)
			remoteCerts = append(remoteCerts, certStr)
		}
	}
	err = tb.UpdateTrustAnchor(&TrustAnchorUpdate{
		TrustAnchorConfig: TrustAnchorConfig{Certs: remoteCerts},
		Source:            sourceSpiffeEndpoints,
	})
	if err != nil {
		trustBundleLog.Errorf("failed to update meshConfig Spiffe trustAnchors: %v", err)
	}
}

func (tb *TrustBundle) ProcessRemoteTrustAnchors(stop <-chan struct{}, pollInterval time.Duration) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			trustBundleLog.Infof("waking up to perform periodic checks")
			tb.fetchRemoteTrustAnchors()
		case <-stop:
			trustBundleLog.Infof("stop processing endpoint trustAnchor updates")
			return
		case <-tb.endpointUpdateChan:
			tb.fetchRemoteTrustAnchors()
			trustBundleLog.Infof("processing endpoint trustAnchor Updates for config change")
		}
	}
}
