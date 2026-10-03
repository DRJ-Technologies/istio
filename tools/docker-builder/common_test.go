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

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	testenv "istio.io/istio/pkg/test/env"
	"istio.io/istio/tools/docker-builder/dockerfile"
)

func TestBaseReferences(t *testing.T) {
	images := map[string]string{
		"pilot":       "pilot/docker/Dockerfile.pilot",
		"proxyv2":     "pilot/docker/Dockerfile.proxyv2",
		"ztunnel":     "pilot/docker/Dockerfile.ztunnel",
		"install-cni": "cni/deployments/kubernetes/Dockerfile.install-cni",
	}
	for _, pinned := range []bool{false, true} {
		for _, variant := range []string{DistrolessVariant, DebugVariant} {
			for _, arch := range []string{"linux/amd64", "linux/arm64"} {
				for target, file := range images {
					t.Run(target+"/"+variant+"/"+arch+"/"+map[bool]string{false: "tag", true: "digest"}[pinned], func(t *testing.T) {
						a := Args{BaseVersion: "fixture", BaseImageRegistry: "example.test/native"}
						if pinned {
							a.IptablesBaseImage = "example.test/iptables@sha256:" + strings.Repeat("a", 64)
							a.DistrolessBaseImage = "example.test/distroless@sha256:" + strings.Repeat("b", 64)
						}
						baseName := "iptables"
						if target == "pilot" {
							baseName = "distroless"
						}
						want := a.BaseImageRegistry + "/" + baseName + ":" + a.BaseVersion
						if pinned {
							want = a.IptablesBaseImage
							if target == "pilot" {
								want = a.DistrolessBaseImage
							}
						}
						if variant == DebugVariant {
							want = a.BaseImageRegistry + "/base:" + a.BaseVersion
						}
						parsed, err := dockerfile.Parse(filepath.Join(testenv.IstioSrc, file), dockerfile.WithArgs(createArgs(a, target, variant, arch)))
						if err != nil {
							t.Fatal(err)
						}
						if parsed.Base != want {
							t.Fatalf("base = %q, want %q", parsed.Base, want)
						}
						for _, source := range parsed.Files {
							if strings.HasPrefix(source, "amd64/") && arch == "linux/arm64" {
								t.Fatalf("wrong architecture copied: %s", source)
							}
						}
					})
				}
			}
		}
	}
}

func TestBakeBaseReferences(t *testing.T) {
	previous := testenv.LocalOut
	testenv.LocalOut = t.TempDir()
	t.Cleanup(func() { testenv.LocalOut = previous })
	a := Args{
		Targets:  []string{"pilot", "proxyv2", "install-cni", "ztunnel"},
		Variants: []string{DistrolessVariant}, Architectures: []string{"linux/amd64", "linux/arm64"},
		Hubs: []string{"example.test/fork"}, Tags: []string{"fixture"}, Save: true,
		BaseVersion: "fixture", BaseImageRegistry: "example.test/native",
		IptablesBaseImage:   "example.test/iptables@sha256:" + strings.Repeat("a", 64),
		DistrolessBaseImage: "example.test/distroless@sha256:" + strings.Repeat("b", 64),
		Plan: map[string]BuildPlan{"linux/amd64": {Images: []ImagePlan{
			{Name: "pilot", Dockerfile: "pilot/docker/Dockerfile.pilot"},
			{Name: "proxyv2", Dockerfile: "pilot/docker/Dockerfile.proxyv2"},
			{Name: "install-cni", Dockerfile: "cni/deployments/kubernetes/Dockerfile.install-cni"},
			{Name: "ztunnel", Dockerfile: "pilot/docker/Dockerfile.ztunnel"},
		}}},
	}
	if _, err := ConstructBakeFile(a); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(testenv.LocalOut, "dockerx_build", "docker-bake.json"))
	if err != nil {
		t.Fatal(err)
	}
	var bake BakeFile
	if err := json.Unmarshal(b, &bake); err != nil {
		t.Fatal(err)
	}
	for _, target := range a.Targets {
		got, present := bake.Target[target+"-distroless"]
		if !present || got.Args["ISTIO_IPTABLES_BASE_IMAGE"] != a.IptablesBaseImage ||
			got.Args["ISTIO_DISTROLESS_BASE_IMAGE"] != a.DistrolessBaseImage || len(got.Platforms) != 2 {
			t.Fatalf("native bake target lost base/platform inputs: %+v", got)
		}
	}
}

func TestBaseImageDefaults(t *testing.T) {
	for _, name := range []string{"ISTIO_IPTABLES_BASE_IMAGE", "ISTIO_DISTROLESS_BASE_IMAGE"} {
		t.Run(name, func(t *testing.T) {
			value, present := os.LookupEnv(name)
			if err := os.Unsetenv(name); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if present {
					_ = os.Setenv(name, value)
				} else {
					_ = os.Unsetenv(name)
				}
			})
			if got := fetchBaseImage(name); !strings.Contains(got, "@sha256:") {
				t.Fatalf("default is not a full digest reference: %q", got)
			}
			t.Setenv(name, "fixture.test/explicit:base")
			if got := fetchBaseImage(name); got != "fixture.test/explicit:base" {
				t.Fatalf("explicit input lost: %q", got)
			}
			t.Setenv(name, "")
			if got := fetchBaseImage(name); got != "" {
				t.Fatalf("explicit registry/tag fallback lost: %q", got)
			}
		})
	}
}
