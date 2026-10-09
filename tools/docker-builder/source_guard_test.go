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

// Exercise the actual workflow shell against real Git repositories. The build
// itself is synthetic; no compiler, image builder or artifact upload is run.
func TestNativeOCISourceGuard(t *testing.T) {
	var workflow struct {
		Jobs map[string]struct {
			Defaults struct {
				Run struct {
					WorkingDirectory string `json:"working-directory"`
				}
			}
			Steps []struct {
				Name, Uses, If, Run string
				With                map[string]any
				Env                 map[string]string
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
	job := workflow.Jobs["build"]
	var checkoutPaths []string
	var script, goVersionFile string
	var upload bool
	buildStep := -1
	for i, step := range job.Steps {
		switch {
		case strings.HasPrefix(step.Uses, "actions/checkout@"):
			path, _ := step.With["path"].(string)
			checkoutPaths = append(checkoutPaths, path)
		case strings.HasPrefix(step.Uses, "actions/setup-go@"):
			goVersionFile, _ = step.With["go-version-file"].(string)
		case step.Name == "Build native multiarch OCI layouts":
			script, buildStep = step.Run, i
			// Every component, or pilot alone for a referenced pilot-only build.
			if step.Env["BUILD_TARGETS"] != "${{ inputs.proxy_run_id == '' && 'pilot,proxyv2,install-cni,ztunnel' || 'pilot' }}" {
				t.Fatal("component selection must follow the pilot-only input")
			}
		case strings.HasPrefix(step.Uses, "actions/upload-artifact@"):
			upload = true
			// A failed build must retain GitHub's default success condition.
			if buildStep < 0 || i <= buildStep || (step.If != "" && step.If != "success()") {
				t.Fatal("artifact upload must follow the successful guarded build")
			}
		}
	}
	if len(checkoutPaths) != 2 || script == "" || buildStep < 0 || !upload {
		t.Fatal("missing native source checkouts or guarded build")
	}
	if filepath.Dir(checkoutPaths[0]) != "." || filepath.Dir(checkoutPaths[1]) != "." || checkoutPaths[0] == checkoutPaths[1] {
		t.Fatal("source checkouts must be distinct sibling directories")
	}
	if job.Defaults.Run.WorkingDirectory != checkoutPaths[0] || goVersionFile != filepath.Join(checkoutPaths[0], "go.mod") {
		t.Fatal("native shell and Go setup must use the Istio checkout")
	}

	for _, mode := range []string{
		"clean", "ignored-output", "failed-build",
		"istio-tracked", "istio-staged", "istio-untracked", "istio-head",
		"companion-tracked", "companion-staged", "companion-untracked", "companion-head",
		"post-istio-tracked", "post-istio-untracked", "post-istio-head",
		"post-companion-tracked", "post-companion-untracked", "post-companion-head",
	} {
		t.Run(mode, func(t *testing.T) {
			workspace := t.TempDir()
			istio := filepath.Join(workspace, checkoutPaths[0])
			companion := filepath.Join(workspace, checkoutPaths[1])
			marker := filepath.Join(workspace, "operation-log")
			env := append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
				"GITHUB_WORKSPACE="+workspace, "BUILD_ZTUNNEL_REPO="+companion,
				"RUNNER_TEMP="+workspace, "OCI_BUILDER=synthetic-builder",
				"DEBUG_IMAGE=external", "ISTIO_ENVOY_LINUX_RELEASE_PATH=/external/amd64",
				"ISTIO_ENVOY_LINUX_DEBUG_PATH=/external/debug",
				"FIXTURE_MODE="+mode, "FIXTURE_LOG="+marker, "BUILD_TARGETS=pilot,proxyv2,install-cni,ztunnel")
			write := func(path, data string, mode os.FileMode) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(data), mode); err != nil {
					t.Fatal(err)
				}
			}
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
			for _, repo := range []string{istio, companion} {
				write(filepath.Join(repo, "build-input.txt"), "initial source\n", 0o600)
				write(filepath.Join(repo, ".gitignore"), "out/\n", 0o600)
				git(repo, "init", "--quiet")
				git(repo, "config", "user.name", "Dan")
				git(repo, "config", "user.email", "dan@drj.tools")
			}
			git(companion, "add", ".")
			git(companion, "commit", "--quiet", "-m", "fixture source")
			deps, err := json.Marshal([]map[string]string{{"name": "ZTUNNEL_REPO_SHA", "lastStableSHA": git(companion, "rev-parse", "HEAD")}})
			if err != nil {
				t.Fatal(err)
			}
			write(filepath.Join(istio, "istio.deps"), string(deps), 0o600)
			write(filepath.Join(istio, "tools/docker"), `#!/bin/bash
set -euo pipefail
test ! -v DEBUG_IMAGE
test ! -v ISTIO_ENVOY_LINUX_RELEASE_PATH
test ! -v ISTIO_ENVOY_LINUX_DEBUG_PATH
test "$2" = "$BUILD_TARGETS"
printf 'build\n' >> "$FIXTURE_LOG"
case "$FIXTURE_MODE" in
  failed-build) exit 7 ;;
  post-istio-tracked) printf 'NONSECRET_MUTATED_CONTENT\n' > build-input.txt ;;
  post-companion-tracked) printf 'NONSECRET_MUTATED_CONTENT\n' > "$BUILD_ZTUNNEL_REPO/build-input.txt" ;;
  post-istio-untracked) printf 'extra source\n' > extra.go ;;
  post-companion-untracked) printf 'extra source\n' > "$BUILD_ZTUNNEL_REPO/extra.rs" ;;
  post-istio-head) git commit --quiet --allow-empty -m 'changed build source head' ;;
  post-companion-head) git -C "$BUILD_ZTUNNEL_REPO" commit --quiet --allow-empty -m 'changed build source head' ;;
esac
mkdir -p out "$BUILD_ZTUNNEL_REPO/out/rust"
printf 'synthetic output\n' > out/output
printf 'synthetic output\n' > "$BUILD_ZTUNNEL_REPO/out/rust/output"
`, 0o700)
			git(istio, "add", ".")
			git(istio, "commit", "--quiet", "-m", "fixture source")
			env = append(env, "GITHUB_SHA="+git(istio, "rev-parse", "HEAD"))
			if mode == "ignored-output" {
				for _, repo := range []string{istio, companion} {
					write(filepath.Join(repo, "out/cache"), "native ignored output\n", 0o600)
				}
			}
			if !strings.HasPrefix(mode, "post-") {
				var repo string
				if strings.HasPrefix(mode, "istio-") {
					repo = istio
				} else if strings.HasPrefix(mode, "companion-") {
					repo = companion
				}
				if repo != "" {
					switch {
					case strings.HasSuffix(mode, "-tracked"), strings.HasSuffix(mode, "-staged"):
						write(filepath.Join(repo, "build-input.txt"), "NONSECRET_MUTATED_CONTENT\n", 0o600)
						if strings.HasSuffix(mode, "-staged") {
							git(repo, "add", "build-input.txt")
						}
					case strings.HasSuffix(mode, "-untracked"):
						write(filepath.Join(repo, "extra-source"), "extra source\n", 0o600)
					case strings.HasSuffix(mode, "-head"):
						git(repo, "commit", "--quiet", "--allow-empty", "-m", "other source head")
					}
				}
			}
			// The final marker models the following upload step's native default
			// success condition, verified above; it never uploads an artifact.
			cmd := exec.Command("bash", "-e", "-c", script+"\nprintf 'upload\\n' >> \"$FIXTURE_LOG\"\n")
			cmd.Dir, cmd.Env = istio, env
			out, buildErr := cmd.CombinedOutput()
			if strings.Contains(string(out), "NONSECRET_MUTATED_CONTENT") {
				t.Fatal("source guard printed file contents")
			}
			operations, readErr := os.ReadFile(marker)
			if readErr != nil && !os.IsNotExist(readErr) {
				t.Fatal(readErr)
			}
			success := mode == "clean" || mode == "ignored-output"
			if success && (buildErr != nil || string(operations) != "build\nupload\n") {
				t.Fatalf("clean sources did not reach upload: %v\n%s\n%s", buildErr, operations, out)
			}
			if !success {
				if buildErr == nil || strings.Contains(string(operations), "upload") {
					t.Fatalf("invalid source or failed build reached upload: %v\n%s\n%s", buildErr, operations, out)
				}
				wantBuild := mode == "failed-build" || strings.HasPrefix(mode, "post-")
				if strings.Contains(string(operations), "build") != wantBuild {
					t.Fatalf("wrong build boundary: operations=%q\n%s", operations, out)
				}
			}
		})
	}
}
