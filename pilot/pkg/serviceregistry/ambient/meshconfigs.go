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

package ambient

import (
	"fmt"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"

	"istio.io/istio/pkg/cluster"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/mesh/kubemesh"
	"istio.io/istio/pkg/config/mesh/meshwatcher"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/kclient"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/kube/multicluster"
	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/ptr"
)

const (
	// defaultMeshConfigMapName is the default name of the ConfigMap with the mesh config
	// The actual name can be different - use getMeshConfigMapName
	defaultMeshConfigMapName = "istio"
)

// ClusterMeshConfig is the subset of a cluster's own mesh config that the local cluster needs in order
// to send traffic to it. Only the fields listed here are read from remote clusters; the rest of a remote
// cluster's mesh config must not influence local configuration.
type ClusterMeshConfig struct {
	ClusterID cluster.ID
	// TrustDomain is the trust domain workloads in the cluster are issued identities in.
	TrustDomain string
}

func (c ClusterMeshConfig) ResourceName() string {
	return c.ClusterID.String()
}

type MeshConfigCollections struct {
	ClusterMeshConfigs krt.Collection[ClusterMeshConfig]

	localClusterID cluster.ID
}

// FetchTrustDomain returns the trust domain workloads in the given cluster are issued identities in.
// Clusters we cannot read the mesh config from fall back to the local trust domain, which is correct
// for a mesh using a single trust domain throughout.
func (c MeshConfigCollections) FetchTrustDomain(ctx krt.HandlerContext, id cluster.ID) string {
	if cfg := krt.FetchOne(ctx, c.ClusterMeshConfigs, krt.FilterKey(id.String())); cfg != nil {
		return cfg.TrustDomain
	}
	if id != c.localClusterID {
		log.Debugf("no mesh config for cluster %s, using the local trust domain", id)
	}
	if local := krt.FetchOne(ctx, c.ClusterMeshConfigs, krt.FilterKey(c.localClusterID.String())); local != nil {
		return local.TrustDomain
	}
	return constants.DefaultClusterLocalDomain
}

func buildGlobalMeshConfigCollections(
	ctrl *multicluster.Controller,
	localMeshConfig meshwatcher.WatcherCollection,
	options Options,
	opts krt.OptionsBuilder,
) MeshConfigCollections {
	GlobalClusterMeshConfigs := multicluster.NestedCollectionFromLocalAndRemote(
		ctrl,
		localClusterMeshConfig(localMeshConfig, options, opts).AsCollection(),
		func(ctx krt.HandlerContext, c *multicluster.Cluster) *krt.Collection[ClusterMeshConfig] {
			// N.B the cluster stop is used here, never the top-level stop, so the informer goes away with
			// the cluster.
			clusterOpts := krt.NewOptionsBuilder(c.GetStop(), fmt.Sprintf("ambient/mesh[%s]/", c.ID), opts.Debugger())
			source := remoteMeshConfigSource(
				c.Client,
				options.SystemNamespace,
				getMeshConfigMapName(options.Revision),
				clusterOpts,
			)
			mesh := meshwatcher.NewCollection(clusterOpts, source)
			return ptr.Of(krt.NewSingleton(func(ctx krt.HandlerContext) *ClusterMeshConfig {
				if krt.FetchOne(ctx, source.AsCollection()) == nil {
					// The cluster has no readable mesh config; leave it out so we fall back to ours rather
					// than to the defaults, which would claim the mesh-wide default trust domain.
					return nil
				}
				return &ClusterMeshConfig{
					ClusterID:   c.ID,
					TrustDomain: krt.FetchOne(ctx, mesh.AsCollection()).GetTrustDomain(),
				}
			}, clusterOpts.WithName("ClusterMeshConfig")...).AsCollection())
		},
		"ClusterMeshConfigs",
		opts,
	)

	ClusterMeshConfigs := krt.NestedJoinWithMergeCollection(
		GlobalClusterMeshConfigs,
		func(configs []ClusterMeshConfig) *ClusterMeshConfig {
			if len(configs) == 0 {
				return nil
			}
			// Keys are cluster IDs, so there is never more than one.
			return &configs[0]
		},
		opts.WithName("MergedClusterMeshConfigs")...,
	)

	return MeshConfigCollections{
		ClusterMeshConfigs: ClusterMeshConfigs,
		localClusterID:     options.ClusterID,
	}
}

// Remote mesh data is optional. The cache may remain unsynced when remote reads
// are denied, so register changes through a native trigger and read only cached
// data. Mandatory local and KRT collection synchronization stays unchanged.
func remoteMeshConfigSource(client kube.Client, namespace, name string, opts krt.OptionsBuilder) meshwatcher.MeshConfigSource {
	clt := kclient.NewFiltered[*v1.ConfigMap](client, kclient.Filter{
		Namespace:     namespace,
		FieldSelector: fields.OneTermEqualSelector(metav1.ObjectNameField, name).String(),
	})
	changed := krt.NewRecomputeTrigger(true, opts.WithName("RemoteMeshConfigChanged")...)
	clt.AddEventHandler(controllers.ObjectHandler(func(controllers.Object) {
		changed.TriggerRecomputation()
	}))
	clt.Start(opts.Stop())
	go func() {
		<-opts.Stop()
		clt.ShutdownHandlers()
	}()
	return krt.NewSingleton(func(ctx krt.HandlerContext) *string {
		// Subscribe before reading the cache so a concurrent event cannot be lost.
		changed.MarkDependant(ctx)
		cm := clt.Get(name, namespace)
		if cm == nil {
			return nil
		}
		data, found := cm.Data[kubemesh.MeshConfigKey]
		if !found {
			return nil
		}
		return &data
	}, opts.WithName("RemoteMeshConfig_"+name)...)
}

func localClusterMeshConfig(
	localMeshConfig meshwatcher.WatcherCollection,
	options Options,
	opts krt.OptionsBuilder,
) krt.Singleton[ClusterMeshConfig] {
	return krt.NewSingleton(func(ctx krt.HandlerContext) *ClusterMeshConfig {
		mesh := krt.FetchOne(ctx, localMeshConfig.AsCollection())
		if mesh == nil {
			return nil
		}
		return &ClusterMeshConfig{
			ClusterID:   options.ClusterID,
			TrustDomain: mesh.GetTrustDomain(),
		}
	}, opts.WithName("LocalClusterMeshConfig")...)
}

// getMeshConfigMapName returns the mesh ConfigMap name based on the revision. Remote clusters are
// assumed to run the same revision as we do.
func getMeshConfigMapName(revision string) string {
	name := defaultMeshConfigMapName
	if revision == "" || revision == "default" {
		return name
	}
	return name + "-" + revision
}
