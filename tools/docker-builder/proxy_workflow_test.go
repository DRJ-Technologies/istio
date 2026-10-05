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
	"strconv"
	"strings"
	"testing"
	"time"

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

func TestNativeProxyJobBudgetStart(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "env")
	cmd := exec.Command("bash", "-c", proxyWorkflowStep(t, "proxy", "Start native proxy job budget"))
	cmd.Env = []string{"PATH=/usr/bin:/bin", "GITHUB_ENV=" + output}
	before := time.Now().Unix()
	if log, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native job clock: %v\n%s", err, log)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := strconv.ParseInt(strings.TrimPrefix(strings.TrimSpace(string(data)), "PROXY_JOB_START_EPOCH="), 10, 64)
	if err != nil || epoch < before || epoch > time.Now().Unix() {
		t.Fatalf("job budget must use the actual runner start: %s %v", data, err)
	}
}

// Exercise the real host-setup script with isolated APT commands. The fixture
// never installs packages or invokes the compiler on the local host.
func TestNativeProxyHostDependencies(t *testing.T) {
	for _, mode := range []string{"complete", "update-failed", "install-failed"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			commands := filepath.Join(root, "commands")
			proxyFixtureWrite(t, filepath.Join(commands, "sudo"), []byte("#!/bin/bash\nexec \"$@\"\n"), 0o700)
			proxyFixtureWrite(t, filepath.Join(commands, "apt-get"), []byte(`#!/bin/bash
set -euo pipefail
printf '%s\n' "$*" >> "$APT_LOG"
case "$1" in
  update)
    [[ "$MODE" != update-failed ]] || exit 37
    touch "$FIXTURE/index"
    ;;
  install)
    test -f "$FIXTURE/index"
    [[ "$MODE" != install-failed ]] || exit 41
    shift
    for package in "$@"; do
      case "$package" in
        -y|--no-install-recommends) ;;
        libtinfo5) touch "$FIXTURE/soname5" ;;
        autoconf-archive) printf 'AC_DEFUN([AX_PTHREAD], [])\n' > "$FIXTURE/ax_pthread.m4" ;;
        *) echo "Unexpected or unsafe APT argument: $package" >&2; exit 43 ;;
      esac
    done
    ;;
  *) exit 45 ;;
esac
`), 0o700)
			cmd := exec.Command("bash", "-c", proxyWorkflowStep(t, "proxy", "Install native proxy host dependencies"))
			cmd.Env = []string{"PATH=" + commands + ":/usr/bin:/bin", "HOME=" + root,
				"FIXTURE=" + root, "APT_LOG=" + filepath.Join(root, "apt.log"), "MODE=" + mode}
			output, err := cmd.CombinedOutput()
			if (err == nil) != (mode == "complete") {
				t.Fatalf("host setup result: %v\n%s", err, output)
			}
			calls, err := os.ReadFile(filepath.Join(root, "apt.log"))
			if err != nil || !strings.HasPrefix(string(calls), "update\n") {
				t.Fatalf("native package index must be refreshed first: %s %v", calls, err)
			}
			if mode == "update-failed" && strings.Contains(string(calls), "install") {
				t.Fatal("index failure must stop before package installation")
			}
			for _, prerequisite := range []string{"soname5", "ax_pthread.m4"} {
				_, err := os.Stat(filepath.Join(root, prerequisite))
				if (err == nil) != (mode == "complete") {
					t.Fatalf("missing host prerequisite or failed setup continued: %s %v", prerequisite, err)
				}
			}
		})
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
				Name, Uses, If  string
				TimeoutMinutes  int `json:"timeout-minutes"`
				With            map[string]string
				ContinueOnError bool `json:"continue-on-error"`
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
	platforms := map[string]string{"amd64": "ubuntu-22.04/x86_64", "arm64": "ubuntu-24.04-arm/aarch64"}
	for _, row := range workflow.Jobs["proxy"].Strategy.Matrix.Include {
		if platforms[row.Arch] != row.Runner+"/"+row.Machine {
			t.Fatal("proxy job must use the matching native runner")
		}
		delete(platforms, row.Arch)
	}
	if len(platforms) != 0 {
		t.Fatal("missing native proxy architecture")
	}
	hostDependencies := false
	if workflow.Jobs["proxy"].Steps[0].Name != "Start native proxy job budget" {
		t.Fatal("checkout and preparation must consume the job budget")
	}
	finalizationMinutes := 0
	for _, step := range workflow.Jobs["proxy"].Steps {
		if step.Name == "Check native proxy cache size" || strings.HasPrefix(step.Uses, "actions/cache/save@") ||
			strings.HasPrefix(step.Uses, "actions/upload-artifact@") {
			if step.TimeoutMinutes <= 0 {
				t.Fatal("each finalization step must have a bounded duration")
			}
			finalizationMinutes += step.TimeoutMinutes
		}
		if step.Name == "Install native proxy host dependencies" {
			if step.If != "matrix.arch == 'amd64'" {
				t.Fatal("x86-only QAT and LLVM host packages must remain scoped to Jammy AMD64")
			}
			hostDependencies = true
		}
		if step.Name == "Build native release proxy" && !hostDependencies {
			t.Fatal("native host dependencies must be installed before compilation")
		}
		if strings.HasPrefix(step.Uses, "actions/upload-artifact@") && step.With["name"] == "native-proxy-${{ matrix.arch }}" {
			if step.If != "" && step.If != "success()" {
				t.Fatal("failed proxy build must never export a binary")
			}
		}
		if strings.HasPrefix(step.Uses, "actions/cache/save@") {
			if step.If != "always() && steps.proxy-cache-size.outputs.save == 'true'" || !step.ContinueOnError {
				t.Fatal("cache save must be bounded, allow incomplete builds, and never authorize release")
			}
		}
	}
	if finalizationMinutes > 25 {
		t.Fatal("cache and artifacts must fit after the native stop and shutdown grace")
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
			"clean", "wrong-machine", "wrong-os", "wrong-version", "failed-build", "deadline", "missing-output",
			"istio-head", "proxy-head", "istio-tracked", "proxy-tracked", "proxy-untracked",
			"post-istio-tracked", "post-proxy-tracked", "post-proxy-head", "late-start", "budget-expired", "future-clock",
		} {
			t.Run(machine+"/"+mode, func(t *testing.T) {
				root := t.TempDir()
				istio, proxy := filepath.Join(root, "istio"), filepath.Join(root, "proxy")
				commands, outputs := filepath.Join(root, "commands"), filepath.Join(root, "outputs")
				env := []string{
					"PATH=" + commands + ":/usr/bin:/bin", "HOME=" + root, "RUNNER_TEMP=" + root,
					"GITHUB_WORKSPACE=" + root, "PROXY_CACHE_DIR=" + filepath.Join(root, "cache"),
					"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
					"PROXY_MACHINE=" + machine, "FIXTURE_MACHINE=" + machine, "FIXTURE_MODE=" + mode,
					"FIXTURE_OUTPUTS=" + outputs, "FIXTURE_ROOT=" + root,
					"PROXY_JOB_START_EPOCH=1700000000",
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
				proxyFixtureWrite(t, filepath.Join(commands, "date"), []byte(`#!/bin/bash
case "$FIXTURE_MODE" in
  late-start) echo 1700000600 ;;
  budget-expired) echo 1700019800 ;;
  future-clock) echo 1699999999 ;;
  *) echo 1700000000 ;;
esac
`), 0o700)
				proxyFixtureWrite(t, filepath.Join(commands, "timeout"), []byte(`#!/bin/bash
set -euo pipefail
if [[ "$3" == 60s ]]; then exec /usr/bin/timeout "$@"; fi
expected=19800s
[[ "$FIXTURE_MODE" != late-start ]] || expected=19200s
[[ "$1" == --signal=INT && "$2" == --kill-after=120s && "$3" == "$expected" ]]
printf '%s\n' "$3" > "$FIXTURE_ROOT/deadline"
if [[ "$FIXTURE_MODE" == deadline ]]; then
  shift 3
  exec /usr/bin/timeout --signal=INT --kill-after=1s 0.2s "$@"
fi
exec /usr/bin/timeout "$@"
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
  test "$*" = "--nosystem_rc --nohome_rc --output_user_root=$RUNNER_TEMP/proxy-bazel build --config=release --stamp --jobs=HOST_CPUS --disk_cache=$PROXY_CACHE_DIR/disk --repository_cache=$PROXY_CACHE_DIR/repository --profile=$RUNNER_TEMP/native-proxy-profile.json.gz //:envoy_tar"
  mkdir -p "$PROXY_CACHE_DIR/disk" "$PROXY_CACHE_DIR/repository"
  printf 'completed action' > "$PROXY_CACHE_DIR/disk/completed"
  printf 'qualified repository' > "$PROXY_CACHE_DIR/repository/completed"
  if [[ "$FIXTURE_MODE" == deadline ]]; then
    trap 'printf "SIGINT\n" >> "$FIXTURE_ROOT/operations"; exit 130' INT
    while :; do sleep 10; done
  fi
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
				if (err == nil) != (mode == "clean" || mode == "late-start") {
					t.Fatalf("unexpected result: %v\n%s", err, log)
				}
				if strings.Contains(string(log), "PRIVATE_CONTENT_NOT_FOR_LOGS") {
					t.Fatal("guard printed file contents")
				}
				if mode == "deadline" {
					status, ok := err.(*exec.ExitError)
					operations, readErr := os.ReadFile(filepath.Join(root, "operations"))
					if !ok || status.ExitCode() != 124 || readErr != nil || !strings.Contains(string(operations), "SIGINT") {
						t.Fatalf("native deadline must send SIGINT and preserve incomplete exit: %v\n%s", err, log)
					}
					cacheOutput := filepath.Join(root, "cache-output")
					budget := exec.Command("bash", "-c", proxyWorkflowStep(t, "proxy", "Check native proxy cache size"))
					budget.Dir, budget.Env = proxy, append(env, "GITHUB_OUTPUT="+cacheOutput)
					if output, err := budget.CombinedOutput(); err != nil {
						t.Fatalf("incomplete build must retain bounded native cache: %v\n%s", err, output)
					}
					output, readErr := os.ReadFile(cacheOutput)
					if readErr != nil || !strings.Contains(string(output), "save=true") {
						t.Fatal("failed build lost eligibility for completed-action cache persistence")
					}
					for _, directory := range []string{"disk", "repository"} {
						if data, err := os.ReadFile(filepath.Join(root, "cache", directory, "completed")); err != nil || len(data) == 0 {
							t.Fatal("deadline removed completed native cache entries")
						}
					}
				}
				_, built := os.Stat(filepath.Join(root, "operations"))
				wantBuild := mode == "clean" || mode == "late-start" || mode == "failed-build" || mode == "deadline" || mode == "missing-output" || strings.HasPrefix(mode, "post-")
				if (built == nil) != wantBuild {
					t.Fatalf("wrong native build boundary: %v\n%s", built, log)
				}
				_, exported := os.Stat(filepath.Join(root, "proxy-export", "envoy"))
				if (exported == nil) != (mode == "clean" || mode == "late-start") {
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
