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
	"time"

	testenv "istio.io/istio/pkg/test/env"
)

// These tests execute the maintained init script and Make rule with synthetic
// files. No supplied artifact is executed and no downloader can reach a network.
func TestExplicitEnvoyInputs(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		for _, tc := range []struct {
			name, release, debug string
			debugImage           bool
			emptyDebugImage      bool
			failureText          string
			fails                bool
		}{
			{name: "release", release: "valid"},
			{name: "native-image-path", release: "native-output"},
			{name: "native-target-path", release: "target-output"},
			{name: "empty-release", release: "empty", fails: true},
			{name: "missing-release", release: "missing", fails: true},
			{name: "directory-release", release: "directory", fails: true},
			{name: "unreadable-release", release: "unreadable", fails: true},
			{name: "nonexecutable-release", release: "nonexecutable", fails: true},
			{name: "debug-and-release", release: "valid", debug: "valid", debugImage: true},
			{name: "empty-debug-flag", release: "valid", debug: "valid", debugImage: true, emptyDebugImage: true},
			{name: "empty-debug-flag-missing-input", release: "valid", debug: "missing", debugImage: true, emptyDebugImage: true, fails: true},
			{name: "release-aliases-debug-output", release: "debug-native-output", debug: "valid", debugImage: true, fails: true, failureText: "aliases the selected native debug destination"},
			{name: "release-at-unselected-debug-output", release: "debug-native-output"},
			{name: "empty-debug", release: "valid", debug: "empty", debugImage: true, fails: true},
			{name: "missing-debug", release: "valid", debug: "missing", debugImage: true, fails: true},
			{name: "directory-debug", release: "valid", debug: "directory", debugImage: true, fails: true},
			{name: "unreadable-debug", release: "valid", debug: "unreadable", debugImage: true, fails: true},
			{name: "nonexecutable-debug", release: "valid", debug: "nonexecutable", debugImage: true, fails: true},
			{name: "unselected-debug", release: "valid", debug: "missing"},
		} {
			t.Run(arch+"/"+tc.name, func(t *testing.T) {
				root := t.TempDir()
				commands := filepath.Join(root, "commands")
				if err := os.Mkdir(commands, 0o700); err != nil {
					t.Fatal(err)
				}
				out := filepath.Join(root, "out")
				// A stale destination must survive a refused input, rather than
				// silently becoming a fallback or a partially copied publication.
				if err := os.Mkdir(out, 0o700); err != nil {
					t.Fatal(err)
				}
				envoy := filepath.Join(out, "envoy")
				if err := os.WriteFile(envoy, []byte("previous-artifact"), 0o600); err != nil {
					t.Fatal(err)
				}
				for _, mode := range []string{"release", "debug"} {
					dir := filepath.Join(out, mode)
					if err := os.Mkdir(dir, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dir, "envoy"), []byte("previous-image-artifact"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				marker := filepath.Join(root, "external-command")
				for _, name := range []string{"curl", "wget", "aws"} {
					if err := os.WriteFile(filepath.Join(commands, name), []byte("#!/bin/bash\nprintf '%s\\n' external > \"$FIXTURE_EXTERNAL_MARKER\"\nexit 91\n"), 0o700); err != nil {
						t.Fatal(err)
					}
				}
				input := func(name, kind string) string {
					t.Helper()
					path := filepath.Join(root, name)
					if kind == "native-output" {
						path = filepath.Join(out, name, "envoy")
					}
					if kind == "debug-native-output" {
						path = filepath.Join(out, "debug", "envoy")
					}
					if kind == "target-output" {
						path = envoy
					}
					switch kind {
					case "empty":
						return ""
					case "missing":
						return path
					case "directory":
						if err := os.Mkdir(path, 0o700); err != nil {
							t.Fatal(err)
						}
					default:
						mode := os.FileMode(0o700)
						if kind == "nonexecutable" {
							mode = 0o600
						}
						if kind == "unreadable" {
							if os.Geteuid() == 0 {
								t.Skip("root can read files without permission bits")
							}
							mode = 0o100
						}
						if err := os.WriteFile(path, []byte("selected-"+arch+"-"+name), mode); err != nil {
							t.Fatal(err)
						}
						if err := os.Chmod(path, mode); err != nil {
							t.Fatal(err)
						}
					}
					return path
				}
				cmd := exec.Command("bash", filepath.Join(testenv.IstioSrc, "bin", "init.sh"))
				cmd.Dir = root
				cmd.Env = []string{
					"PATH=" + commands + ":/usr/bin:/bin", "TARGET_ARCH=" + arch,
					"TARGET_OUT=" + out, "TARGET_OUT_LINUX=" + out, "GOOS_LOCAL=linux",
					"PROXY_REPO_SHA=fixture", "FIXTURE_EXTERNAL_MARKER=" + marker,
					"ISTIO_ENVOY_LINUX_RELEASE_URL=s3://fixture.invalid/release",
					"ISTIO_ENVOY_LINUX_DEBUG_URL=s3://fixture.invalid/debug",
					"ISTIO_ENVOY_LINUX_RELEASE_PATH=" + input("release", tc.release),
				}
				if tc.debug != "" {
					cmd.Env = append(cmd.Env, "ISTIO_ENVOY_LINUX_DEBUG_PATH="+input("debug", tc.debug))
				}
				if tc.debugImage {
					flag := "1"
					if tc.emptyDebugImage {
						flag = ""
					}
					cmd.Env = append(cmd.Env, "DEBUG_IMAGE="+flag)
				}
				previous := make(map[string]string)
				for _, mode := range []string{"release", "debug"} {
					bytes, err := os.ReadFile(filepath.Join(out, mode, "envoy"))
					if err != nil {
						t.Fatal(err)
					}
					previous[mode] = string(bytes)
				}
				log, err := cmd.CombinedOutput()
				if (err != nil) != tc.fails {
					t.Fatalf("unexpected result: %v\n%s", err, log)
				}
				if _, err := os.Stat(marker); !os.IsNotExist(err) {
					t.Fatalf("explicit inputs reached downloader/credential command: %v\n%s", err, log)
				}
				got, err := os.ReadFile(envoy)
				want := "selected-" + arch + "-release"
				if tc.fails {
					want = "previous-artifact"
					failureText := tc.failureText
					if failureText == "" {
						failureText = "must be a readable executable regular file"
					}
					if !strings.Contains(string(log), failureText) {
						t.Fatalf("did not refuse the explicit input: %s", log)
					}
				}
				if err != nil || string(got) != want {
					t.Fatalf("destination %q (%v), want %q\n%s", got, err, want, log)
				}
				for _, mode := range []string{"release", "debug"} {
					got, err := os.ReadFile(filepath.Join(out, mode, "envoy"))
					want := previous[mode]
					if !tc.fails && (mode == "release" || tc.debugImage) {
						want = "selected-" + arch + "-" + mode
					}
					if err != nil || string(got) != want {
						t.Fatalf("native %s image input = %q (%v), want %q\n%s", mode, got, err, want, log)
					}
					if !tc.fails && (mode == "release" || tc.debugImage) {
						info, err := os.Stat(filepath.Join(out, mode, "envoy"))
						if err != nil || info.Mode().Perm()&0o111 == 0 {
							t.Fatalf("selected native image input is not executable: %v", err)
						}
					}
				}
			})
		}
	}
}

func TestExplicitEnvoyReconsumesInit(t *testing.T) {
	for _, kind := range []string{"release", "empty-release", "debug", "empty-debug-flag", "unselected-debug", "default-cache"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			out := filepath.Join(root, "out")
			if err := os.Mkdir(out, 0o700); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(out, "istio_is_init")
			if err := os.WriteFile(marker, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			future := time.Now().Add(time.Hour)
			if err := os.Chtimes(marker, future, future); err != nil {
				t.Fatal(err)
			}
			// Use the actual complete Makefile in dry-run mode: inspect native
			// prerequisite selection without invoking init, Cargo or a compiler.
			cmd := exec.Command("make", "--no-print-directory", "--dry-run", "-f", "Makefile.core.mk", marker)
			cmd.Dir = testenv.IstioSrc
			cmd.Env = []string{"PATH=/usr/bin:/bin", "TARGET_ARCH=amd64", "TARGET_OS=linux", "TARGET_OUT=" + out,
				"TARGET_OUT_LINUX=" + out, "VERSION=fixture", "GOPATH=" + root, "GOBIN=" + root}
			switch kind {
			case "release":
				cmd.Env = append(cmd.Env, "ISTIO_ENVOY_LINUX_RELEASE_PATH="+filepath.Join(root, "selected"))
			case "empty-release":
				cmd.Env = append(cmd.Env, "ISTIO_ENVOY_LINUX_RELEASE_PATH=")
			case "debug":
				cmd.Env = append(cmd.Env, "DEBUG_IMAGE=1", "ISTIO_ENVOY_LINUX_DEBUG_PATH="+filepath.Join(root, "selected"))
			case "empty-debug-flag":
				cmd.Env = append(cmd.Env, "DEBUG_IMAGE=", "ISTIO_ENVOY_LINUX_DEBUG_PATH="+filepath.Join(root, "selected"))
			case "unselected-debug":
				cmd.Env = append(cmd.Env, "ISTIO_ENVOY_LINUX_DEBUG_PATH="+filepath.Join(root, "selected"))
			}
			log, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("native Make prerequisite check failed: %v\n%s", err, log)
			}
			selected := kind == "release" || kind == "empty-release" || kind == "debug" || kind == "empty-debug-flag"
			if strings.Contains(string(log), "bin/retry.sh") != selected {
				t.Fatalf("stale marker selection incorrect for %s\n%s", kind, log)
			}
		})
	}
}
