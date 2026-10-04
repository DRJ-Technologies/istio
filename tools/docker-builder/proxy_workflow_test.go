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
	"archive/tar"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	testenv "istio.io/istio/pkg/test/env"
)

func proxyWorkflowStep(t *testing.T, job, name string) string {
	t.Helper()
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct{ Name, Run string }
		}
	}
	data, err := os.ReadFile(filepath.Join(testenv.IstioSrc, ".github/workflows/native-oci-build.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	for _, step := range workflow.Jobs[job].Steps {
		if step.Name == name {
			return step.Run
		}
	}
	t.Fatalf("missing workflow step %s/%s", job, name)
	return ""
}

func proxyFixtureWrite(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func TestNativeProxyWorkflowTransport(t *testing.T) {
	var workflow struct {
		On          map[string]any
		Permissions map[string]string
		Jobs        map[string]struct {
			If, Needs string
			Strategy  struct {
				Matrix struct {
					Include []struct{ Arch, Machine, Runner string }
				}
			}
			Steps []struct {
				Name, Uses, If string
				With           map[string]string
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
	if len(workflow.On) != 1 || workflow.On["workflow_dispatch"] == nil || workflow.Permissions["contents"] != "read" {
		t.Fatal("proxy compilation must remain manual and use only read access")
	}
	if workflow.Jobs["build"].Needs != "proxy" {
		t.Fatal("components must wait for both native proxy jobs")
	}
	for _, job := range []string{"build", "proxy"} {
		if workflow.Jobs[job].If != "github.ref == 'refs/heads/main'" {
			t.Fatal("native build must use main")
		}
	}
	platforms := map[string]string{"amd64": "ubuntu-24.04/x86_64", "arm64": "ubuntu-24.04-arm/aarch64"}
	for _, row := range workflow.Jobs["proxy"].Strategy.Matrix.Include {
		if platforms[row.Arch] != row.Runner+"/"+row.Machine {
			t.Fatal("proxy job must use the matching native runner")
		}
		delete(platforms, row.Arch)
	}
	if len(platforms) != 0 {
		t.Fatal("missing native proxy architecture")
	}
	for _, step := range workflow.Jobs["proxy"].Steps {
		if strings.HasPrefix(step.Uses, "actions/upload-artifact@") && step.With["name"] == "native-proxy-${{ matrix.arch }}" {
			if step.If != "" && step.If != "success()" {
				t.Fatal("failed proxy build must never export a binary")
			}
		}
	}
	downloads := map[string]bool{}
	for _, step := range workflow.Jobs["build"].Steps {
		if strings.HasPrefix(step.Uses, "actions/download-artifact@") {
			name := step.With["name"]
			if step.With["path"] != "${{ runner.temp }}/"+name || step.With["github-token"] != "" || step.With["run-id"] != "" {
				t.Fatal("download must select its own run's matching artifact without credentials")
			}
			downloads[name] = true
		}
	}
	if len(downloads) != 2 || !downloads["native-proxy-amd64"] || !downloads["native-proxy-arm64"] {
		t.Fatal("both proxy outputs must be transported separately")
	}
}

// Execute the actual workflow against real Git and synthetic Bazel commands.
// No proxy compilation, Bazel download, registry or binary execution occurs.
func TestNativeProxyWorkflowBuild(t *testing.T) {
	script := proxyWorkflowStep(t, "proxy", "Build native release proxy")
	for _, machine := range []string{"x86_64", "aarch64"} {
		for _, mode := range []string{
			"clean", "wrong-machine", "wrong-os", "wrong-version", "failed-build", "missing-output",
			"istio-head", "proxy-head", "istio-tracked", "proxy-tracked", "proxy-untracked",
			"post-istio-tracked", "post-proxy-tracked", "post-proxy-head",
		} {
			t.Run(machine+"/"+mode, func(t *testing.T) {
				root := t.TempDir()
				istio, proxy := filepath.Join(root, "istio"), filepath.Join(root, "proxy")
				commands, outputs := filepath.Join(root, "commands"), filepath.Join(root, "outputs")
				env := []string{
					"PATH=" + commands + ":/usr/bin:/bin", "HOME=" + root, "RUNNER_TEMP=" + root,
					"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
					"PROXY_MACHINE=" + machine, "FIXTURE_MACHINE=" + machine, "FIXTURE_MODE=" + mode,
					"FIXTURE_OUTPUTS=" + outputs, "FIXTURE_ROOT=" + root,
					"BUILD_SCM_REVISION=external-revision", "BUILD_SCM_STATUS=external-status",
					"BUILD_CONFIG=debug", "USE_BAZEL_VERSION=external-version", "USE_BAZEL_FALLBACK_VERSION=external-fallback",
					"BAZELISK_BASE_URL=external-mirror", "BAZELISK_FORMAT_URL=external-format",
					"BAZEL_LLVM_PATH=external-compiler", "BAZEL_USE_HOST_SYSROOT=True", "BAZEL_USE_LIBSTDCPP=True",
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
				for _, repo := range []string{istio, proxy} {
					proxyFixtureWrite(t, filepath.Join(repo, "source"), []byte("native input\n"), 0o600)
					git(repo, "init", "--quiet")
					git(repo, "config", "user.name", "Dan")
					git(repo, "config", "user.email", "dan@drj.tools")
				}
				proxyFixtureWrite(t, filepath.Join(proxy, ".bazelversion"), []byte("fixture-version\n"), 0o600)
				git(proxy, "add", ".")
				git(proxy, "commit", "--quiet", "-m", "proxy input")
				deps, err := json.Marshal([]map[string]string{{"name": "PROXY_REPO_SHA", "lastStableSHA": git(proxy, "rev-parse", "HEAD")}})
				if err != nil {
					t.Fatal(err)
				}
				proxyFixtureWrite(t, filepath.Join(istio, "istio.deps"), deps, 0o600)
				git(istio, "add", ".")
				git(istio, "commit", "--quiet", "-m", "istio input")
				env = append(env, "GITHUB_SHA="+git(istio, "rev-parse", "HEAD"))
				if strings.HasSuffix(mode, "-head") && !strings.HasPrefix(mode, "post-") {
					repo := proxy
					if mode == "istio-head" {
						repo = istio
					}
					git(repo, "commit", "--quiet", "--allow-empty", "-m", "changed head")
				}
				if mode == "proxy-untracked" {
					proxyFixtureWrite(t, filepath.Join(proxy, "new-source"), []byte("new input"), 0o600)
				}
				if mode == "istio-tracked" || mode == "proxy-tracked" {
					repo := proxy
					if mode == "istio-tracked" {
						repo = istio
					}
					proxyFixtureWrite(t, filepath.Join(repo, "source"), []byte("PRIVATE_CONTENT_NOT_FOR_LOGS"), 0o600)
				}
				proxyFixtureWrite(t, filepath.Join(commands, "uname"), []byte(`#!/bin/bash
if [[ "$1" == -s ]]; then
  [[ "$FIXTURE_MODE" == wrong-os ]] && echo Darwin || echo Linux
else
  [[ "$FIXTURE_MODE" == wrong-machine ]] && echo unsupported || echo "$FIXTURE_MACHINE"
fi
`), 0o700)
				proxyFixtureWrite(t, filepath.Join(commands, "bazelisk"), []byte(`#!/bin/bash
set -euo pipefail
for name in BUILD_SCM_REVISION BUILD_SCM_STATUS USE_BAZEL_VERSION USE_BAZEL_FALLBACK_VERSION BAZELISK_BASE_URL BAZELISK_FORMAT_URL BAZEL_LLVM_PATH BAZEL_USE_HOST_SYSROOT BAZEL_USE_LIBSTDCPP; do
  test ! -v "$name"
done
test "$BUILD_CONFIG" = release
if [[ "$*" == --version ]]; then
  [[ "$FIXTURE_MODE" == wrong-version ]] && echo 'bazel other-version' || echo 'bazel fixture-version'
elif [[ " $* " == *' build '* ]]; then
  printf 'build\n' >> "$FIXTURE_ROOT/operations"
  test "$*" = "--nosystem_rc --nohome_rc --output_user_root=$RUNNER_TEMP/proxy-bazel build --config=release --stamp --jobs=1 //:envoy_tar"
  [[ "$FIXTURE_MODE" == failed-build ]] && exit 8
  mkdir -p "$FIXTURE_OUTPUTS"
  printf 'native-proxy-fixture' > "$FIXTURE_OUTPUTS/envoy"
  chmod +x "$FIXTURE_OUTPUTS/envoy"
  if [[ "$FIXTURE_MODE" != missing-output ]]; then
    printf 'native-archive-fixture' > "$FIXTURE_OUTPUTS/envoy_tar.tar.gz"
  fi
  case "$FIXTURE_MODE" in
    post-istio-tracked) printf 'PRIVATE_CONTENT_NOT_FOR_LOGS' > ../istio/source ;;
    post-proxy-tracked) printf 'PRIVATE_CONTENT_NOT_FOR_LOGS' > source ;;
    post-proxy-head) git commit --quiet --allow-empty -m 'changed source' ;;
  esac
else
  echo "$FIXTURE_OUTPUTS"
fi
`), 0o700)
				if err := os.Mkdir(filepath.Join(root, "proxy-export"), 0o700); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command("bash", "-c", script)
				cmd.Dir, cmd.Env = proxy, env
				log, err := cmd.CombinedOutput()
				if (err == nil) != (mode == "clean") {
					t.Fatalf("unexpected result: %v\n%s", err, log)
				}
				if strings.Contains(string(log), "PRIVATE_CONTENT_NOT_FOR_LOGS") {
					t.Fatal("guard printed file contents")
				}
				_, built := os.Stat(filepath.Join(root, "operations"))
				wantBuild := mode == "clean" || mode == "failed-build" || mode == "missing-output" || strings.HasPrefix(mode, "post-")
				if (built == nil) != wantBuild {
					t.Fatalf("wrong native build boundary: %v\n%s", built, log)
				}
				_, exported := os.Stat(filepath.Join(root, "proxy-export", "envoy"))
				if (exported == nil) != (mode == "clean") {
					t.Fatal("failed source/build reached artifact export")
				}
			})
		}
	}
}

// Minimal static ELF fixtures are parsed by native readelf, never executed.
func proxyFixtureELF(machine uint16) []byte {
	data := make([]byte, 64)
	copy(data, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(data[16:], 2)
	binary.LittleEndian.PutUint16(data[18:], machine)
	binary.LittleEndian.PutUint32(data[20:], 1)
	binary.LittleEndian.PutUint16(data[52:], 64)
	return data
}

func TestNativeProxyWorkflowInputs(t *testing.T) {
	script := proxyWorkflowStep(t, "build", "Prepare matching native proxy inputs")
	for _, mode := range []string{"clean", "wrong-amd64", "wrong-arm64", "mismatched-binary", "missing-archive", "nonexecutable", "invalid-elf"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			istio := filepath.Join(root, "istio")
			if err := os.Mkdir(istio, 0o700); err != nil {
				t.Fatal(err)
			}
			if log, err := exec.Command("git", "init", "--quiet", istio).CombinedOutput(); err != nil {
				t.Fatalf("fixture Git setup: %v\n%s", err, log)
			}
			// Use the real outer Makefile, setup_env, and init recipe. These
			// read-only links are fixture inputs, not a source writer or build.
			for _, path := range []string{"Makefile", "Makefile.core.mk", "VERSION", "bin", "common", "tools", "tests"} {
				if err := os.Symlink(filepath.Join(testenv.IstioSrc, path), filepath.Join(istio, path)); err != nil {
					t.Fatal(err)
				}
			}
			deps, err := os.ReadFile(filepath.Join(testenv.IstioSrc, "istio.deps"))
			if err != nil {
				t.Fatal(err)
			}
			proxyFixtureWrite(t, filepath.Join(istio, "istio.deps"), deps, 0o600)
			for arch, machine := range map[string]uint16{"amd64": 62, "arm64": 183} {
				if mode == "wrong-"+arch {
					machine = 0
				}
				data := proxyFixtureELF(machine)
				if mode == "invalid-elf" && arch == "arm64" {
					data = []byte("not an ELF binary")
				}
				artifact := filepath.Join(root, "native-proxy-"+arch)
				proxyFixtureWrite(t, filepath.Join(artifact, "envoy"), data, 0o600)
				if mode == "mismatched-binary" && arch == "arm64" {
					proxyFixtureWrite(t, filepath.Join(artifact, "envoy"), []byte("other native bytes"), 0o600)
				}
				if mode == "missing-archive" && arch == "arm64" {
					continue
				}
				file, err := os.Create(filepath.Join(artifact, "envoy_tar.tar.gz"))
				if err != nil {
					t.Fatal(err)
				}
				gz := gzip.NewWriter(file)
				tarball := tar.NewWriter(gz)
				permissions := int64(0o755)
				if mode == "nonexecutable" && arch == "arm64" {
					permissions = 0o644
				}
				if err := tarball.WriteHeader(&tar.Header{Name: "usr/local/bin/envoy", Mode: permissions, Size: int64(len(data))}); err != nil {
					t.Fatal(err)
				}
				if _, err := tarball.Write(data); err != nil {
					t.Fatal(err)
				}
				for _, close := range []func() error{tarball.Close, gz.Close, file.Close} {
					if err := close(); err != nil {
						t.Fatal(err)
					}
				}
			}
			cmd := exec.Command("bash", "-c", script)
			cmd.Dir = istio
			cmd.Env = []string{
				"PATH=/usr/bin:/bin", "HOME=" + root, "TMPDIR=" + root,
				"GITHUB_WORKSPACE=" + root, "RUNNER_TEMP=" + root, "GOPATH=" + root,
				"DEBUG_IMAGE=external", "ISTIO_ENVOY_LINUX_RELEASE_PATH=/missing-external",
				"ISTIO_ENVOY_LINUX_DEBUG_PATH=/missing-external", "VERSION=fixture", "TAG=fixture",
			}
			log, err := cmd.CombinedOutput()
			if (err == nil) != (mode == "clean") {
				t.Fatalf("unexpected result: %v\n%s", err, log)
			}
			for arch, machine := range map[string]uint16{"amd64": 62, "arm64": 183} {
				out := filepath.Join(istio, "out", "linux_"+arch)
				_, err := os.Stat(filepath.Join(out, "istio_is_init"))
				if mode != "clean" {
					if !os.IsNotExist(err) {
						t.Fatalf("invalid artifact initialized %s: %v", arch, err)
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				for _, path := range []string{"envoy", "release/envoy"} {
					got, err := os.ReadFile(filepath.Join(out, path))
					if err != nil || string(got) != string(proxyFixtureELF(machine)) {
						t.Fatalf("wrong native %s %s input: %v", arch, path, err)
					}
				}
			}
		})
	}
}
