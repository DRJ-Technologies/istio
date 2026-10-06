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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	testenv "istio.io/istio/pkg/test/env"
)

func proxyCacheFixture(t *testing.T) (string, string, []string) {
	t.Helper()
	root := t.TempDir()
	env := []string{"PATH=/usr/bin:/bin", "HOME=" + root, "RUNNER_TEMP=" + root,
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"PROXY_CACHE_DIR=" + filepath.Join(root, "cache"), "GITHUB_OUTPUT=" + filepath.Join(root, "output")}
	git := func(repo string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	for _, name := range []string{"istio", "proxy"} {
		repo := filepath.Join(root, name)
		proxyFixtureWrite(t, filepath.Join(repo, "source"), []byte("native source\n"), 0o600)
		git(repo, "init", "--quiet")
		git(repo, "config", "user.name", "Dan")
		git(repo, "config", "user.email", "dan@drj.tools")
		git(repo, "add", ".")
		git(repo, "commit", "--quiet", "-m", "native source")
	}
	proxy := filepath.Join(root, "proxy")
	deps, err := json.Marshal([]map[string]string{{"name": "PROXY_REPO_SHA", "lastStableSHA": git(proxy, "rev-parse", "HEAD")}})
	if err != nil {
		t.Fatal(err)
	}
	istio := filepath.Join(root, "istio")
	proxyFixtureWrite(t, filepath.Join(istio, "istio.deps"), deps, 0o600)
	git(istio, "add", ".")
	git(istio, "commit", "--quiet", "-m", "native dependency")
	env = append(env, "GITHUB_SHA="+git(istio, "rev-parse", "HEAD"))
	return root, proxy, env
}

func TestNativeProxyCacheSelection(t *testing.T) {
	for _, runner := range []string{"ubuntu-22.04", "ubuntu-24.04-arm"} {
		for _, wrongHead := range []bool{false, true} {
			t.Run(runner+map[bool]string{false: "/matching", true: "/wrong-head"}[wrongHead], func(t *testing.T) {
				root, proxy, env := proxyCacheFixture(t)
				env = append(env, "PROXY_RUNNER="+runner)
				if wrongHead {
					proxyFixtureWrite(t, filepath.Join(root, "istio", "istio.deps"), []byte(`[{"name":"PROXY_REPO_SHA","lastStableSHA":"other-source"}]`), 0o600)
				}
				cmd := exec.Command("bash", "-c", proxyWorkflowStep(t, "proxy", "Select native proxy cache"))
				cmd.Dir, cmd.Env = proxy, env
				log, err := cmd.CombinedOutput()
				if (err == nil) == wrongHead {
					t.Fatalf("native selection result: %v\n%s", err, log)
				}
				if wrongHead {
					if _, err := os.Stat(filepath.Join(root, "output")); !os.IsNotExist(err) {
						t.Fatal("mismatched source selected a cache namespace")
					}
					return
				}
				output, err := os.ReadFile(filepath.Join(root, "output"))
				if err != nil || !strings.HasPrefix(string(output), "cache_prefix=native-proxy-"+runner+"-") {
					t.Fatalf("runner/source namespace not derived: %s %v", output, err)
				}
				for _, directory := range []string{"disk", "repository"} {
					if info, err := os.Stat(filepath.Join(root, "cache", directory)); err != nil || !info.IsDir() {
						t.Fatalf("native cache directory missing: %v", err)
					}
				}
			})
		}
	}
}

func TestNativeProxyCacheBudget(t *testing.T) {
	for _, mode := range []string{"fits", "oversized", "absent", "incomplete-directory", "dirty-proxy", "dirty-istio", "wrong-istio-head", "wrong-proxy-head"} {
		t.Run(mode, func(t *testing.T) {
			testNativeProxyCacheFinalization(t, mode)
		})
	}
}

func TestNativeProxyCacheTransport(t *testing.T) {
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct {
				Uses string
				With map[string]string
			}
		}
	}
	data, err := os.ReadFile(filepath.Join(testenv.IstioSrc, ".github/workflows/native-oci-build.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	cache := map[string]map[string]string{}
	for _, step := range workflow.Jobs["proxy"].Steps {
		for _, action := range []string{"restore", "save"} {
			if strings.HasPrefix(step.Uses, "actions/cache/"+action+"@") {
				cache[action] = step.With
			}
		}
		if strings.HasPrefix(step.Uses, "actions/upload-artifact@") && step.With["name"] == "native-proxy-log-${{ matrix.arch }}" &&
			!strings.Contains(step.With["path"], "native-proxy-profile.json.gz") {
			t.Fatal("native profile must be retained with existing logs")
		}
	}
	if len(cache) != 2 || cache["restore"]["key"] != cache["save"]["key"] ||
		cache["save"]["path"] != "${{ env.PROXY_CACHE_DIR }}" || cache["restore"]["path"] != cache["save"]["path"] ||
		!strings.Contains(cache["save"]["key"], "github.run_id") || !strings.Contains(cache["save"]["key"], "github.run_attempt") ||
		cache["restore"]["restore-keys"] != "${{ steps.proxy-inputs.outputs.cache_prefix }}-" {
		t.Fatal("native cache transport must use isolated derived source namespace and immutable run key")
	}
}
