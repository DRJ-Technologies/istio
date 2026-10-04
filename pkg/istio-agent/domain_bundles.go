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

package istioagent

import (
	mesh "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pkg/security"
	"istio.io/istio/pkg/util/protomarshal"
)

// Advertise the actual agent input through existing native ProxyMetadata. This
// does not declare roots or introduce another enable flag. A copied mesh setting
// must not claim typed ROOTCA support when the process did not select the map.
func proxyConfigWithBundleMap(config *mesh.ProxyConfig, options *security.Options) *mesh.ProxyConfig {
	if config == nil {
		return config
	}
	path := ""
	if options != nil {
		path = options.SPIFFEBundleMapPath
	}
	_, declared := config.ProxyMetadata[security.SPIFFEBundleMapPathEnv]
	if path == "" && !declared {
		return config
	}
	derived := protomarshal.Clone(config)
	if derived.ProxyMetadata == nil {
		derived.ProxyMetadata = map[string]string{}
	}
	if path == "" {
		delete(derived.ProxyMetadata, security.SPIFFEBundleMapPathEnv)
	} else {
		derived.ProxyMetadata[security.SPIFFEBundleMapPathEnv] = path
	}
	return derived
}
