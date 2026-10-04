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

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/server"
	"istio.io/istio/pilot/pkg/trustbundle"
	"istio.io/istio/pkg/cluster"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/mesh/meshwatcher"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/inject"
	"istio.io/istio/pkg/kube/kclient"
	filter "istio.io/istio/pkg/kube/namespace"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/env"
	"istio.io/istio/pkg/test/util/assert"
	"istio.io/istio/pkg/test/util/retry"
)

func trustDomainsCM(tds string) map[string]string {
	return map[string]string{constants.TrustDomainsNamespaceConfigMapDataName: tds}
}

func TestTrustDomainsController(t *testing.T) {
	client := kube.NewFakeClient()
	t.Cleanup(client.Shutdown)
	meshWatcher := meshwatcher.NewTestWatcher(&meshconfig.MeshConfig{
		TrustDomain:        "cluster.local",
		TrustDomainAliases: []string{"old.local"},
	})
	stop := test.NewStop(t)
	kube.SetObjectFilter(client, filter.NewDiscoveryNamespacesFilter(kclient.New[*v1.Namespace](client), meshWatcher, stop))
	c := NewTrustDomainsController(client, meshWatcher, nil)
	client.RunAndWait(stop)
	go c.Run(stop)
	retry.UntilOrFail(t, c.queue.HasSynced)

	createNamespace(t, client.Kube(), "foo", nil)
	expectConfigMap(t, c.configmaps, TrustDomainsNamespaceConfigMap, "foo", trustDomainsCM("cluster.local\nold.local\n"))

	// Mesh config changes are written without a restart, including trust domains attached to a CA certificate.
	meshWatcher.Set(&meshconfig.MeshConfig{
		TrustDomain: "cluster.local",
		CaCertificates: []*meshconfig.MeshConfig_CertificateData{
			{TrustDomains: []string{"other.local", "cluster.local"}},
		},
	})
	expectConfigMap(t, c.configmaps, TrustDomainsNamespaceConfigMap, "foo", trustDomainsCM("cluster.local\nother.local\n"))

	// Tampering with the ConfigMap is reverted.
	_, err := client.Kube().CoreV1().ConfigMaps("foo").Update(context.TODO(), &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: TrustDomainsNamespaceConfigMap, Namespace: "foo"},
		Data:       trustDomainsCM("evil.local\n"),
	}, metav1.UpdateOptions{})
	assert.NoError(t, err)
	expectConfigMap(t, c.configmaps, TrustDomainsNamespaceConfigMap, "foo", trustDomainsCM("cluster.local\nother.local\n"))

	// Deletion is reverted.
	assert.NoError(t, client.Kube().CoreV1().ConfigMaps("foo").Delete(context.TODO(), TrustDomainsNamespaceConfigMap, metav1.DeleteOptions{}))
	expectConfigMap(t, c.configmaps, TrustDomainsNamespaceConfigMap, "foo", trustDomainsCM("cluster.local\nother.local\n"))

	for _, ns := range inject.IgnoredNamespaces.Copy().Delete(constants.KubeSystemNamespace).UnsortedList() {
		createNamespace(t, client.Kube(), ns, nil)
		err := retry.Until(func() bool {
			return c.configmaps.Get(TrustDomainsNamespaceConfigMap, ns) != nil
		}, retry.Timeout(time.Millisecond*25))
		if err == nil {
			t.Fatalf("%s namespace should not have %s configmap", ns, TrustDomainsNamespaceConfigMap)
		}
	}
}

func TestTrustDomainsControllerWatchNamespace(t *testing.T) {
	test.SetForTest(t, &features.InformerWatchNamespace, "owned")
	test.SetForTest(t, &features.SkipValidateTrustDomain, false)
	outside := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: TrustDomainsNamespaceConfigMap, Namespace: "outside-existing"},
		Data:       trustDomainsCM("external-owner.example\n"),
	}
	client := kube.NewFakeClient(
		&v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "owned"}},
		&v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "outside-absent"}},
		&v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "outside-existing"}},
		outside,
	)
	t.Cleanup(client.Shutdown)
	watcher := meshwatcher.NewTestWatcher(&meshconfig.MeshConfig{TrustDomain: "local.example"})
	stop := make(chan struct{})
	c := NewTrustDomainsController(client, watcher, nil)
	client.RunAndWait(stop)
	done := make(chan struct{})
	go func() {
		c.Run(stop)
		close(done)
	}()
	shutdown := func() {
		select {
		case <-stop:
		default:
			close(stop)
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("trust domain controller did not stop")
		}
		// Drain queued writes before making negative assertions, without a timing sleep.
		select {
		case <-c.queue.Closed():
		case <-time.After(5 * time.Second):
			t.Fatal("trust domain queue did not drain")
		}
	}
	t.Cleanup(shutdown)
	expectTrustDomainsConfigMap(t, client, "owned", "local.example\n")

	watcher.Set(&meshconfig.MeshConfig{
		TrustDomain: "local.example",
		CaCertificates: []*meshconfig.MeshConfig_CertificateData{
			{TrustDomains: []string{"peer.example"}},
		},
	})
	expectTrustDomainsConfigMap(t, client, "owned", "local.example\npeer.example\n")
	watcher.Set(&meshconfig.MeshConfig{TrustDomain: "local.example"})
	expectTrustDomainsConfigMap(t, client, "owned", "local.example\n")

	// Stale or independently queued Namespace and ConfigMap keys cannot bypass scope.
	assert.NoError(t, c.reconcile(types.NamespacedName{Name: "outside-absent"}))
	assert.NoError(t, c.reconcile(types.NamespacedName{Namespace: "outside-existing", Name: TrustDomainsNamespaceConfigMap}))
	shutdown()
	for _, action := range client.Kube().(*fake.Clientset).Actions() {
		if action.GetResource().Resource != "configmaps" || action.GetNamespace() == "owned" {
			continue
		}
		switch action.GetVerb() {
		case "create", "update", "patch", "delete":
			t.Errorf("attempted %s of ConfigMap outside watched namespace: %s", action.GetVerb(), action.GetNamespace())
		}
	}
	_, err := client.Kube().CoreV1().ConfigMaps("outside-absent").Get(context.TODO(), TrustDomainsNamespaceConfigMap, metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("outside namespace ConfigMap must remain absent: %v", err)
	}
	got, err := client.Kube().CoreV1().ConfigMaps("outside-existing").Get(context.TODO(), TrustDomainsNamespaceConfigMap, metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, got.Data, trustDomainsCM("external-owner.example\n"))
}

// Certificate-associated domains are sufficient without aliases or skipped validation.
// Removing the explicit domain narrows the published set back to the local domain.
func TestTrustDomainsDataExplicitCertificateDomains(t *testing.T) {
	test.SetForTest(t, &features.SkipValidateTrustDomain, false)
	m := &meshconfig.MeshConfig{
		TrustDomain: "local.example",
		CaCertificates: []*meshconfig.MeshConfig_CertificateData{
			{TrustDomains: []string{"peer.example", "local.example", "peer.example"}},
		},
	}
	assert.Equal(t, string(trustDomainsData(m)), "local.example\npeer.example\n")
	m.CaCertificates = nil
	assert.Equal(t, string(trustDomainsData(m)), "local.example\n")
}

func TestTrustDomainsDataSkipValidation(t *testing.T) {
	mesh := &meshconfig.MeshConfig{TrustDomain: "cluster.local", TrustDomainAliases: []string{"old.local"}}
	assert.Equal(t, string(trustDomainsData(mesh)), "cluster.local\nold.local\n")

	// Sidecars and waypoints accept any trust domain when validation is skipped; an empty list would instead
	// mean only the proxy's own trust domain.
	test.SetForTest(t, &features.SkipValidateTrustDomain, true)
	assert.Equal(t, string(trustDomainsData(mesh)), "*\n")
}

// The trust domains are needed whichever CA issues certificates, so they are written even when istiod does
// not distribute the CA certificate (external CA, cert-manager, SPIRE, ...).
func TestTrustDomainsWrittenWithoutCADistribution(t *testing.T) {
	clientset := kube.NewFakeClient()
	stop := test.NewStop(t)
	s := server.New()
	mcc := initController(clientset, stop)
	mockserviceController := newMockserviceController()
	_ = NewMulticluster("pilot-abc-123", Options{
		ClusterID:             cluster.ID("cluster-1"),
		DomainSuffix:          DomainSuffix,
		MeshWatcher:           meshwatcher.NewTestWatcher(&meshconfig.MeshConfig{TrustDomain: "td.local"}),
		MeshNetworksWatcher:   meshwatcher.NewFixedNetworksWatcher(nil),
		MeshServiceController: mockserviceController,
	}, nil, nil, "default", false /* distributeCACert */, nil, s, mcc)
	assert.NoError(t, mcc.Run(stop))
	go mockserviceController.Run(stop)
	clientset.RunAndWait(stop)
	kube.WaitForCacheSync("test", stop, mcc.HasSynced)
	_ = s.Start(stop)

	createNamespace(t, clientset.Kube(), "foo", nil)
	expectTrustDomainsConfigMap(t, clientset, "foo", "td.local\n")
}

// waitForTrustDomainsController waits until the trust domains controller started by a Multicluster is writing.
func waitForTrustDomainsController(t *testing.T, client kube.Client) {
	t.Helper()
	createNamespace(t, client.Kube(), "trust-domains-probe", nil)
	expectTrustDomainsConfigMap(t, client, "trust-domains-probe", "")
}

// expectTrustDomainsConfigMap waits for the ConfigMap in ns; an empty want only waits for it to exist.
func expectTrustDomainsConfigMap(t *testing.T, client kube.Client, ns, want string) {
	t.Helper()
	retry.UntilSuccessOrFail(t, func() error {
		cm, err := client.Kube().CoreV1().ConfigMaps(ns).Get(context.TODO(), TrustDomainsNamespaceConfigMap, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if got := cm.Data[constants.TrustDomainsNamespaceConfigMapDataName]; want != "" && got != want {
			return fmt.Errorf("unexpected trust domains %q, want %q", got, want)
		}
		return nil
	}, retry.Timeout(10*time.Second))
}

func TestDomainBundleControllerAtomicProjectionAndScope(t *testing.T) {
	test.SetForTest(t, &features.InformerWatchNamespace, "owned")
	// The new projection cannot widen authority even if the legacy name flag is set.
	test.SetForTest(t, &features.SkipValidateTrustDomain, true)
	outside := &v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: TrustDomainsNamespaceConfigMap, Namespace: "outside"}, Data: trustDomainsCM("other-owner.example\n")}
	client := kube.NewFakeClient(&v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "owned"}}, &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "outside"}}, outside)
	t.Cleanup(client.Shutdown)
	root, err := os.ReadFile(filepath.Join(env.IstioSrc, "samples/certs/root-cert.pem"))
	assert.NoError(t, err)
	cfg := &meshconfig.MeshConfig{TrustDomain: "local.example", CaCertificates: []*meshconfig.MeshConfig_CertificateData{{
		CertificateData: &meshconfig.MeshConfig_CertificateData_Pem{Pem: string(root)}, TrustDomains: []string{"foreign.example"},
	}}}
	watcher := meshwatcher.NewTestWatcher(cfg)
	tb := trustbundle.NewTrustBundle(nil, watcher)
	assert.NoError(t, tb.AddMeshConfigUpdate(cfg))
	assert.NoError(t, tb.UpdateTrustAnchor(&trustbundle.TrustAnchorUpdate{Source: trustbundle.SourceIstioCA, TrustAnchorConfig: trustbundle.TrustAnchorConfig{Certs: []string{string(root)}}}))
	reg := watcher.AddMeshHandler(func() { _ = tb.AddMeshConfigUpdate(watcher.Mesh()) })
	t.Cleanup(func() { watcher.DeleteMeshHandler(reg) })
	fakeClient := client.Kube().(*fake.Clientset)
	// Every emitted API mutation must carry a self-consistent pair. The API
	// reactor observes writes, not merely the eventual informer cache contents.
	verifyWrite := func(cm *v1.ConfigMap) {
		if cm.Namespace != "owned" {
			t.Errorf("attempted out-of-scope write to %s", cm.Namespace)
		}
		var doc struct {
			TrustDomains map[string]json.RawMessage `json:"trust_domains"`
		}
		if err := json.Unmarshal([]byte(cm.Data[constants.SPIFFEBundleMapConfigMapDataName]), &doc); err != nil {
			t.Errorf("invalid emitted bundle: %v", err)
			return
		}
		if doc.TrustDomains == nil {
			t.Error("missing authoritative map")
		}
		var names []string
		for name := range doc.TrustDomains {
			names = append(names, name)
		}
		want := ""
		if len(names) > 0 {
			sort.Strings(names)
			want = strings.Join(names, "\n") + "\n"
		}
		if cm.Data[constants.TrustDomainsNamespaceConfigMapDataName] != want {
			t.Errorf("torn bundle/names update: %+v", cm.Data)
		}
	}
	fakeClient.PrependReactor("create", "configmaps", func(a ktesting.Action) (bool, runtime.Object, error) {
		verifyWrite(a.(ktesting.CreateAction).GetObject().(*v1.ConfigMap))
		return false, nil, nil
	})
	fakeClient.PrependReactor("update", "configmaps", func(a ktesting.Action) (bool, runtime.Object, error) {
		verifyWrite(a.(ktesting.UpdateAction).GetObject().(*v1.ConfigMap))
		return false, nil, nil
	})
	stop := make(chan struct{})
	c := NewTrustDomainsController(client, watcher, tb)
	client.RunAndWait(stop)
	done := make(chan struct{})
	go func() { c.Run(stop); close(done) }()
	shutdown := func() {
		select {
		case <-stop:
		default:
			close(stop)
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("controller did not stop")
		}
		<-c.queue.Closed()
	}
	t.Cleanup(shutdown)
	expected := func() map[string]string {
		snapshot := tb.GetDomainBundle()
		names := ""
		if len(snapshot.TrustDomains()) > 0 {
			names = strings.Join(snapshot.TrustDomains(), "\n") + "\n"
		}
		return map[string]string{constants.SPIFFEBundleMapConfigMapDataName: string(snapshot.BundleMap()), constants.TrustDomainsNamespaceConfigMapDataName: names}
	}
	expectConfigMap(t, c.configmaps, TrustDomainsNamespaceConfigMap, "owned", expected())
	// Native CA rotation/removal notifies without a MeshConfig change.
	assert.NoError(t, tb.UpdateTrustAnchor(&trustbundle.TrustAnchorUpdate{Source: trustbundle.SourceIstioCA}))
	expectConfigMap(t, c.configmaps, TrustDomainsNamespaceConfigMap, "owned", expected())
	// Explicit foreign removal and malformed update revoke without a restart.
	watcher.Set(&meshconfig.MeshConfig{TrustDomain: "local.example"})
	expectConfigMap(t, c.configmaps, TrustDomainsNamespaceConfigMap, "owned", expected())
	watcher.Set(cfg)
	expectConfigMap(t, c.configmaps, TrustDomainsNamespaceConfigMap, "owned", expected())
	watcher.Set(&meshconfig.MeshConfig{TrustDomain: "local.example", CaCertificates: []*meshconfig.MeshConfig_CertificateData{{CertificateData: &meshconfig.MeshConfig_CertificateData_Pem{Pem: string(root) + "bad trailing block"}, TrustDomains: []string{"foreign.example"}}}})
	expectConfigMap(t, c.configmaps, TrustDomainsNamespaceConfigMap, "owned", expected())
	// The central reconcile guard must also reject direct scheduling.
	assert.NoError(t, c.reconcile(types.NamespacedName{Namespace: "outside"}))
	shutdown()
	got, err := client.Kube().CoreV1().ConfigMaps("outside").Get(context.Background(), TrustDomainsNamespaceConfigMap, metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, got.Data, outside.Data)
	// No listener survives the controller lifetime.
	before := len(fakeClient.Actions())
	assert.NoError(t, tb.AddMeshConfigUpdate(cfg))
	assert.Equal(t, len(fakeClient.Actions()), before)
}
