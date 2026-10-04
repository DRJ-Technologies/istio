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
	"strings"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/networking/plugin/authn"
	"istio.io/istio/pilot/pkg/trustbundle"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/mesh"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/inject"
	"istio.io/istio/pkg/kube/kclient"
	"istio.io/istio/pkg/util/sets"
	"istio.io/istio/security/pkg/k8s"
)

// TrustDomainsNamespaceConfigMap is the name of the ConfigMap in each namespace storing the trust domains
// peers are accepted from.
var TrustDomainsNamespaceConfigMap = features.TrustDomainsConfigMapName

// anyTrustDomain is written instead of a list when trust domain validation is skipped.
const anyTrustDomain = "*"

// TrustDomainsController projects one authoritative per-domain bundle snapshot
// and its compatibility names into a ConfigMap in each watched namespace. It
// runs independently of the root-cert controller and PCDS. Production authority
// is owned by the local config cluster's native workload TrustBundle.
type TrustDomainsController struct {
	meshWatcher mesh.Watcher
	trustBundle *trustbundle.TrustBundle

	queue controllers.Queue

	namespaces kclient.Client[*v1.Namespace]
	configmaps kclient.Client[*v1.ConfigMap]

	ignoredNamespaces sets.Set[string]
}

// NewTrustDomainsController returns a controller writing the trust domains accepted according to meshWatcher.
func NewTrustDomainsController(kubeClient kube.Client, meshWatcher mesh.Watcher, trustBundle *trustbundle.TrustBundle) *TrustDomainsController {
	c := &TrustDomainsController{
		meshWatcher: meshWatcher,
		trustBundle: trustBundle,
		// kube-system is not skipped to enable deploying ztunnel in that namespace
		ignoredNamespaces: inject.IgnoredNamespaces.Copy().Delete(constants.KubeSystemNamespace),
	}
	c.queue = controllers.NewQueue("trust domains controller",
		controllers.WithReconciler(c.reconcile),
		controllers.WithMaxAttempts(maxRetries))

	c.configmaps = kclient.NewFiltered[*v1.ConfigMap](kubeClient, kclient.Filter{
		FieldSelector: "metadata.name=" + TrustDomainsNamespaceConfigMap,
		ObjectFilter:  kubeClient.ObjectFilter(),
	})
	c.namespaces = kclient.NewFiltered[*v1.Namespace](kubeClient, kclient.Filter{
		ObjectFilter: kubeClient.ObjectFilter(),
	})

	c.configmaps.AddEventHandler(controllers.FilteredObjectSpecHandler(c.queue.AddObject, func(o controllers.Object) bool {
		return c.shouldProcessNamespace(o.GetNamespace())
	}))
	c.namespaces.AddEventHandler(controllers.FilteredObjectSpecHandler(c.queue.AddObject, func(o controllers.Object) bool {
		return c.shouldProcessNamespace(o.GetName())
	}))
	return c
}

// Run starts the controller until stop is closed.
func (c *TrustDomainsController) Run(stop <-chan struct{}) {
	if !kube.WaitForCacheSync("trust domains controller", stop, c.namespaces.HasSynced, c.configmaps.HasSynced) {
		c.queue.ShutDownEarly()
		return
	}
	if c.trustBundle != nil {
		// MeshConfig and native workload CA/RA changes publish one complete snapshot.
		unregister := c.trustBundle.AddDomainBundleHandler(c.syncAll)
		defer unregister()
	} else {
		// Legacy names-only callers do not supply workload root authority.
		reg := c.meshWatcher.AddMeshHandler(c.syncAll)
		defer c.meshWatcher.DeleteMeshHandler(reg)
	}
	c.syncAll()
	c.queue.Run(stop)
	controllers.ShutdownAll(c.configmaps, c.namespaces)
}

func (c *TrustDomainsController) shouldProcessNamespace(ns string) bool {
	return !c.ignoredNamespaces.Contains(ns) &&
		(features.InformerWatchNamespace == "" || features.InformerWatchNamespace == ns)
}

func (c *TrustDomainsController) syncAll() {
	for _, ns := range c.namespaces.List("", labels.Everything()) {
		if ns.Status.Phase != v1.NamespaceTerminating && c.shouldProcessNamespace(ns.Name) {
			c.queue.Add(types.NamespacedName{Name: ns.Name})
		}
	}
}

func (c *TrustDomainsController) reconcile(o types.NamespacedName) error {
	ns := o.Namespace
	if ns == "" {
		// For Namespace object, it will not have o.Namespace field set
		ns = o.Name
	}
	if !c.shouldProcessNamespace(ns) {
		return nil
	}
	if c.trustBundle != nil {
		snapshot := c.trustBundle.GetDomainBundle()
		names := ""
		if domains := snapshot.TrustDomains(); len(domains) != 0 {
			names = strings.Join(domains, "\n") + "\n"
		}
		return k8s.InsertMapToConfigMap(c.configmaps, metav1.ObjectMeta{
			Name: TrustDomainsNamespaceConfigMap, Namespace: ns, Labels: configMapLabel,
		}, map[string]string{
			constants.SPIFFEBundleMapConfigMapDataName:       string(snapshot.BundleMap()),
			constants.TrustDomainsNamespaceConfigMapDataName: names,
		})
	}
	return k8s.InsertDataToConfigMap(
		c.configmaps,
		metav1.ObjectMeta{
			Name:      TrustDomainsNamespaceConfigMap,
			Namespace: ns,
			Labels:    configMapLabel,
		},
		constants.TrustDomainsNamespaceConfigMapDataName,
		trustDomainsData(c.meshWatcher.Mesh()),
	)
}

// trustDomainsData returns the trust domains peers are accepted from, one per line: the set sidecars and
// waypoints validate peers against. When that validation is skipped it is anyTrustDomain instead, since
// an empty set would mean accepting only the proxy's own trust domain.
func trustDomainsData(m *meshconfig.MeshConfig) []byte {
	if features.SkipValidateTrustDomain {
		return []byte(anyTrustDomain + "\n")
	}
	tds := authn.TrustDomainsForValidation(m)
	if len(tds) == 0 {
		return nil
	}
	return []byte(strings.Join(tds, "\n") + "\n")
}
