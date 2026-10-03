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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	testenv "istio.io/istio/pkg/test/env"
)

func TestCompanionBuild(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    string
		profile string
		target  string
		cached  bool
		fails   bool
	}{
		{name: "source-release", profile: "release"},
		{name: "source-arm64", profile: "release", target: "aarch64-unknown-linux-gnu"},
		{name: "source-default-profile"},
		{name: "source-with-stock-cache", profile: "release", cached: true},
		{name: "failed-compile", mode: "fail", fails: true},
		{name: "missing-compile-output", mode: "missing-output", fails: true},
		{name: "missing-explicit-repo", mode: "missing-repo", fails: true},
		{name: "missing-inferred-repo", mode: "infer", fails: true},
		{name: "stock-download", mode: "stock"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			repo, out, commands := filepath.Join(root, "companion"), filepath.Join(root, "linux"), filepath.Join(root, "commands")
			for _, dir := range []string{repo, out, commands} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			write := func(path, text string, mode os.FileMode) {
				t.Helper()
				if err := os.WriteFile(path, []byte(text), mode); err != nil {
					t.Fatal(err)
				}
			}
			write(filepath.Join(root, "istio.deps"), "", 0o600)
			write(filepath.Join(commands, "cargo"), `#!/bin/bash
set -eu
[[ "${FIXTURE_MODE}" != fail ]] || exit 9
[[ "${FIXTURE_MODE}" != missing-output ]] || exit 0
profile="${BUILD_ZTUNNEL_PROFILE:-dev}"
[[ "$profile" != dev ]] || profile=debug
path="out/rust/${BUILD_ZTUNNEL_TARGET:+${BUILD_ZTUNNEL_TARGET}/}${profile}"
mkdir -p "$path"
printf 'paired-companion' > "$path/ztunnel"
`, 0o700)
			write(filepath.Join(commands, "curl"), `#!/bin/bash
set -eu
if [[ "${1:-}" == --version ]]; then
  printf 'Protocols: https\n'
else
  printf 'download-called' > "$FIXTURE_DOWNLOAD_MARKER"
  printf 'stock-companion'
fi
`, 0o700)
			if tc.cached {
				if err := os.MkdirAll(filepath.Join(out, "release"), 0o700); err != nil {
					t.Fatal(err)
				}
				write(filepath.Join(out, "release", "ztunnel-fixture"), "cached-stock", 0o600)
			}
			cmd := exec.Command("bash", filepath.Join(testenv.IstioSrc, "bin", "build_ztunnel.sh"))
			cmd.Dir = root
			cmd.Env = []string{"PATH=" + commands + ":/usr/bin:/bin", "TARGET_OUT_LINUX=" + out, "TARGET_ARCH=amd64",
				"ZTUNNEL_REPO_SHA=fixture", "FIXTURE_MODE=" + tc.mode, "FIXTURE_DOWNLOAD_MARKER=" + filepath.Join(root, "download")}
			if tc.mode == "infer" {
				cmd.Env = append(cmd.Env, "BUILD_ZTUNNEL=1")
			} else if tc.mode != "stock" {
				if tc.mode == "missing-repo" {
					repo = filepath.Join(root, "absent")
				}
				cmd.Env = append(cmd.Env, "BUILD_ZTUNNEL_REPO="+repo, "BUILD_ZTUNNEL_PROFILE="+tc.profile, "BUILD_ZTUNNEL_TARGET="+tc.target)
			}
			log, err := cmd.CombinedOutput()
			if (err != nil) != tc.fails {
				t.Fatalf("unexpected result: %v\n%s", err, log)
			}
			binary, readErr := os.ReadFile(filepath.Join(out, "ztunnel"))
			if tc.fails {
				if !os.IsNotExist(readErr) {
					t.Fatalf("failed source build produced a fallback: %q (%v)", binary, readErr)
				}
			} else {
				want := "paired-companion"
				if tc.mode == "stock" {
					want = "stock-companion"
				}
				if readErr != nil || string(binary) != want {
					t.Fatalf("binary = %q (%v), want %q\n%s", binary, readErr, want, log)
				}
			}
			_, downloadErr := os.Stat(filepath.Join(root, "download"))
			if tc.mode != "stock" && !os.IsNotExist(downloadErr) {
				t.Fatal("explicit source build reached downloader")
			}
			if strings.Contains(string(log), "Downloading ztunnel:") && tc.mode != "stock" {
				t.Fatal("source build attempted stock download")
			}
		})
	}
}
