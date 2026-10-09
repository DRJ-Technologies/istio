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
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	testenv "istio.io/istio/pkg/test/env"
)

// inspectGoBinary builds a minimal Go program in its own Git repository, so it
// carries real build info: vcs.revision, vcs.modified and CGO_ENABLED=0. Each
// variant is a distinct commit, so its revision differs from the others'.
func inspectGoBinary(t *testing.T, variant string, modified bool) ([]byte, string) {
	t.Helper()
	repo, out := t.TempDir(), filepath.Join(t.TempDir(), "binary")
	env := append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=-buildvcs=true", "GOWORK=off",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	run := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir, cmd.Env = dir, env
		b, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, b)
		}
		return strings.TrimSpace(string(b))
	}
	proxyFixtureWrite(t, filepath.Join(repo, "go.mod"), []byte("module fixture\n\ngo 1.21\n"), 0o600)
	proxyFixtureWrite(t, filepath.Join(repo, "main.go"), []byte("package main\n\n// "+variant+"\nfunc main() {}\n"), 0o600)
	run(repo, "git", "init", "--quiet")
	run(repo, "git", "add", ".")
	run(repo, "git", "-c", "user.name=Dan", "-c", "user.email=dan@drj.tools", "commit", "--quiet", "-m", "fixture")
	if modified {
		proxyFixtureWrite(t, filepath.Join(repo, "main.go"), []byte("package main\n\nfunc main() { println() }\n"), 0o600)
	}
	run(repo, "go", "build", "-o", out, ".")
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return data, run(repo, "git", "rev-parse", "HEAD")
}

type inspectImage struct {
	platform, configPlatform string
	files                    map[string][]byte
}

// inspectLayout writes the OCI layout BuildKit exports for one repository:
// an image index with each platform's image and an attestation for it.
func inspectLayout(t *testing.T, dir, ref string, images []inspectImage) {
	t.Helper()
	put := func(v any) (string, int) {
		t.Helper()
		data, ok := v.([]byte)
		if !ok {
			var err error
			if data, err = json.Marshal(v); err != nil {
				t.Fatal(err)
			}
		}
		sum := sha256.Sum256(data)
		proxyFixtureWrite(t, filepath.Join(dir, "blobs", "sha256", hex.EncodeToString(sum[:])), data, 0o600)
		return "sha256:" + hex.EncodeToString(sum[:]), len(data)
	}
	var entries []map[string]any
	for _, image := range images {
		var layer bytes.Buffer
		gz := gzip.NewWriter(&layer)
		tw := tar.NewWriter(gz)
		for name, data := range image.files {
			if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write(data); err != nil {
				t.Fatal(err)
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		layerDigest, layerSize := put(layer.Bytes())
		os, arch, _ := strings.Cut(image.configPlatform, "/")
		configDigest, configSize := put(map[string]any{"os": os, "architecture": arch, "config": map[string]any{"Entrypoint": []string{"/entry"}}})
		manifest, manifestSize := put(map[string]any{
			"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
			"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": configDigest, "size": configSize},
			"layers": []map[string]any{{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": layerDigest, "size": layerSize}},
		})
		os, arch, _ = strings.Cut(image.platform, "/")
		entries = append(entries, map[string]any{
			"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": manifest, "size": manifestSize,
			"platform": map[string]string{"os": os, "architecture": arch},
		})
		attestation, attestationSize := put(map[string]any{"schemaVersion": 2, "layers": []any{}})
		entries = append(entries, map[string]any{
			"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": attestation, "size": attestationSize,
			"platform":    map[string]string{"os": "unknown", "architecture": "unknown"},
			"annotations": map[string]string{"vnd.docker.reference.digest": manifest, "vnd.docker.reference.type": "attestation-manifest"},
		})
	}
	index, indexSize := put(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": entries})
	envelope, err := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []map[string]any{{
		"mediaType": "application/vnd.oci.image.index.v1+json", "digest": index, "size": indexSize,
		"annotations": map[string]string{"org.opencontainers.image.ref.name": ref},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	proxyFixtureWrite(t, filepath.Join(dir, "index.json"), envelope, 0o600)
}

// Run the reviewed inspector on synthetic native artifacts, with and without
// Python's -O (which strips assert statements): every result must be the same.
func TestInspectOCI(t *testing.T) {
	script := filepath.Join(testenv.IstioSrc, "tools/docker-builder/inspect_oci.py")
	source, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`(?m)^\s*assert\b`).Match(source) {
		t.Fatal("qualification checks must not use assert, which python -O removes")
	}
	goBinary, revision := inspectGoBinary(t, "source", false)
	modifiedBinary, _ := inspectGoBinary(t, "source", true)
	other, otherRevision := inspectGoBinary(t, "other", false)
	if otherRevision == revision {
		t.Fatal("fixture revisions must differ")
	}
	const tag = "1.31.1-drj.4-pilot.1-distroless"
	native := func(name, platform string) []byte { return []byte("native " + name + " " + platform) }
	files := func(repo, platform string, bin []byte) map[string][]byte {
		return map[string]map[string][]byte{
			"pilot":       {"usr/local/bin/pilot-discovery": bin},
			"proxyv2":     {"usr/local/bin/envoy": native("envoy", platform), "usr/local/bin/pilot-agent": bin},
			"install-cni": {"usr/local/bin/install-cni": bin, "opt/cni/bin/istio-cni": bin},
			"ztunnel":     {"usr/local/bin/ztunnel": native("ztunnel", platform)},
		}[repo]
	}
	imagesOf := func(repo string, bin []byte) []inspectImage {
		return []inspectImage{
			{platform: "linux/amd64", configPlatform: "linux/amd64", files: files(repo, "linux/amd64", bin)},
			{platform: "linux/arm64", configPlatform: "linux/arm64", files: files(repo, "linux/arm64", bin)},
		}
	}
	images := func(repo string) []inspectImage { return imagesOf(repo, goBinary) }
	inputs := func(change func(map[string]string)) []byte {
		v := map[string]string{
			"mode": "pilot-only", "source": revision, "tag": tag, "beside": "1.31.1-drj.4-distroless", "proxy_run": "4242",
			"proxy_run_head": "referenced-head", "PROXY_REPO_SHA": "native-proxy-source",
			"native-proxy-amd64": "100 sha256:" + strings.Repeat("a", 64), "native-proxy-arm64": "101 sha256:" + strings.Repeat("b", 64),
		}
		if change != nil {
			change(v)
		}
		var b strings.Builder
		for _, k := range []string{"mode", "source", "tag", "beside", "proxy_run", "proxy_run_head", "PROXY_REPO_SHA", "native-proxy-amd64", "native-proxy-arm64"} {
			if value, ok := v[k]; ok {
				b.WriteString(k + "=" + value + "\n")
			}
		}
		return []byte(b.String())
	}
	full := func(t *testing.T, root string, change func(repo string, images []inspectImage) []inspectImage) {
		for _, repo := range []string{"pilot", "proxyv2", "install-cni", "ztunnel"} {
			im := images(repo)
			if change != nil {
				im = change(repo, im)
			}
			if im != nil {
				inspectLayout(t, filepath.Join(root, repo), "1.31.1-drj.4-distroless", im)
			}
		}
	}
	pilotOnly := func(t *testing.T, root string, in []byte, im []inspectImage) {
		if im == nil {
			im = images("pilot")
		}
		inspectLayout(t, filepath.Join(root, "pilot"), tag, im)
		proxyFixtureWrite(t, filepath.Join(root, "pilot-inputs.txt"), in, 0o600)
	}
	only := func(keep string) func(string, []inspectImage) []inspectImage {
		return func(repo string, im []inspectImage) []inspectImage {
			if repo != keep {
				return im
			}
			return im[:1]
		}
	}

	for _, tc := range []struct {
		name     string
		build    func(t *testing.T, root, baseline string)
		baseline bool
		finding  string // empty: the artifact qualifies
		compare  map[string]string
	}{
		{name: "full", build: func(t *testing.T, root, _ string) { full(t, root, nil) }},
		{name: "pilot-only", build: func(t *testing.T, root, _ string) { pilotOnly(t, root, inputs(nil), nil) }},
		{
			name: "pilot-only-beside-same-baseline", baseline: true,
			build: func(t *testing.T, root, baseline string) {
				pilotOnly(t, root, inputs(nil), nil)
				full(t, baseline, nil)
			},
			compare: map[string]string{
				"pilot linux/amd64 usr/local/bin/pilot-discovery": "identical",
				"pilot linux/arm64 usr/local/bin/pilot-discovery": "identical",
			},
		},
		{
			name: "pilot-only-beside-other-baseline", baseline: true,
			build: func(t *testing.T, root, baseline string) {
				pilotOnly(t, root, inputs(nil), nil)
				full(t, baseline, func(repo string, _ []inspectImage) []inspectImage { return imagesOf(repo, other) })
			},
			compare: map[string]string{
				"pilot linux/amd64 usr/local/bin/pilot-discovery": "differs",
				"pilot linux/arm64 usr/local/bin/pilot-discovery": "differs",
			},
		},
		{name: "baseline-findings-count", baseline: true, finding: "baseline: proxyv2: unreadable index.json",
			build: func(t *testing.T, root, baseline string) {
				pilotOnly(t, root, inputs(nil), nil)
				full(t, baseline, nil)
				proxyFixtureWrite(t, filepath.Join(baseline, "proxyv2", "index.json"), []byte("{"), 0o600)
			}},
		{name: "corrupt-blob", finding: "does not match its digest", build: func(t *testing.T, root, _ string) {
			full(t, root, nil)
			blobs, _ := filepath.Glob(filepath.Join(root, "ztunnel", "blobs", "sha256", "*"))
			for _, b := range blobs {
				data, _ := os.ReadFile(b)
				if len(data) > 100 { // the layer
					data[len(data)/2] ^= 0xff
					proxyFixtureWrite(t, b, data, 0o600)
				}
			}
		}},
		{name: "two-selected-indexes", finding: "must select exactly one image index", build: func(t *testing.T, root, _ string) {
			full(t, root, nil)
			path := filepath.Join(root, "pilot", "index.json")
			var envelope map[string][]any
			data, _ := os.ReadFile(path)
			_ = json.Unmarshal(data, &envelope)
			envelope["manifests"] = append(envelope["manifests"], envelope["manifests"][0])
			data, _ = json.Marshal(envelope)
			proxyFixtureWrite(t, path, data, 0o600)
		}},
		{name: "unreadable-index", finding: "unreadable index.json", build: func(t *testing.T, root, _ string) {
			full(t, root, nil)
			proxyFixtureWrite(t, filepath.Join(root, "proxyv2", "index.json"), []byte("not json"), 0o600)
		}},
		{name: "missing-arm64", finding: "images for ['linux/amd64']", build: func(t *testing.T, root, _ string) {
			full(t, root, only("install-cni"))
		}},
		{name: "config-platform-mismatch", finding: "linux/arm64 image config is linux/amd64", build: func(t *testing.T, root, _ string) {
			full(t, root, func(repo string, im []inspectImage) []inspectImage {
				if repo == "ztunnel" {
					im[1].configPlatform = "linux/amd64"
				}
				return im
			})
		}},
		{name: "missing-binary", finding: "lacks ['usr/local/bin/pilot-agent']", build: func(t *testing.T, root, _ string) {
			full(t, root, func(repo string, im []inspectImage) []inspectImage {
				if repo == "proxyv2" {
					delete(im[0].files, "usr/local/bin/pilot-agent")
				}
				return im
			})
		}},
		{name: "full-missing-repository", finding: "a full artifact holds", build: func(t *testing.T, root, _ string) {
			full(t, root, func(repo string, im []inspectImage) []inspectImage {
				if repo == "ztunnel" {
					return nil
				}
				return im
			})
		}},
		{name: "pilot-only-extra-repository", finding: "a pilot-only artifact holds ['pilot']", build: func(t *testing.T, root, _ string) {
			pilotOnly(t, root, inputs(nil), nil)
			inspectLayout(t, filepath.Join(root, "proxyv2"), tag, images("proxyv2"))
		}},
		{name: "inputs-missing-key", finding: "pilot-inputs.txt keys", build: func(t *testing.T, root, _ string) {
			pilotOnly(t, root, inputs(func(v map[string]string) { delete(v, "beside") }), nil)
		}},
		{name: "inputs-malformed-artifact", finding: "native-proxy-arm64 is not", build: func(t *testing.T, root, _ string) {
			pilotOnly(t, root, inputs(func(v map[string]string) { v["native-proxy-arm64"] = "101 md5:00" }), nil)
		}},
		{name: "source-mismatch", finding: "is not the recorded source", build: func(t *testing.T, root, _ string) {
			pilotOnly(t, root, inputs(func(v map[string]string) { v["source"] = "another-revision" }), nil)
		}},
		{name: "tag-mismatch", finding: "is not the recorded tag", build: func(t *testing.T, root, _ string) {
			pilotOnly(t, root, inputs(func(v map[string]string) { v["tag"] = "1.31.1-drj.4-pilot.2-distroless" }), nil)
		}},
		{name: "modified-sources", finding: "built from modified sources", build: func(t *testing.T, root, _ string) {
			im := images("pilot")
			im[0].files = map[string][]byte{"usr/local/bin/pilot-discovery": modifiedBinary}
			pilotOnly(t, root, inputs(nil), im)
		}},
		{name: "not-a-go-binary", finding: "has no Go build info", build: func(t *testing.T, root, _ string) {
			im := images("pilot")
			im[1].files = map[string][]byte{"usr/local/bin/pilot-discovery": native("pilot", "arm64")}
			pilotOnly(t, root, inputs(nil), im)
		}},
		{name: "several-revisions", finding: "Go binaries from several revisions", build: func(t *testing.T, root, _ string) {
			full(t, root, func(repo string, im []inspectImage) []inspectImage {
				if repo == "install-cni" {
					im[0].files["opt/cni/bin/istio-cni"] = other
				}
				return im
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, baseline := t.TempDir(), t.TempDir()
			tc.build(t, root, baseline)
			args := []string{root}
			if tc.baseline {
				args = append(args, baseline)
			}
			var results []string
			for _, python := range [][]string{{"python3"}, {"python3", "-O"}} {
				cmd := exec.Command(python[0], append(append(python[1:], script), args...)...)
				out, err := cmd.Output()
				code := 0
				if exitErr, ok := err.(*exec.ExitError); ok {
					code = exitErr.ExitCode()
				} else if err != nil {
					t.Fatal(err)
				}
				var report struct {
					Findings []string
					Compare  map[string]string `json:"binary_comparison_vs_baseline"`
					Inputs   map[string]string `json:"pilot_only_inputs"`
				}
				if err := json.Unmarshal(out, &report); err != nil {
					t.Fatalf("%v: no JSON report: %v\n%s", python, err, out)
				}
				if tc.finding == "" {
					if code != 0 || len(report.Findings) != 0 {
						t.Fatalf("%v: qualifying artifact refused (%d): %v", python, code, report.Findings)
					}
				} else if code != 1 || !strings.Contains(strings.Join(report.Findings, "\n"), tc.finding) {
					t.Fatalf("%v: want exit 1 with %q, got %d: %v", python, tc.finding, code, report.Findings)
				}
				for k, v := range tc.compare {
					if report.Compare[k] != v {
						t.Fatalf("%v: comparison %s = %q, want %q", python, k, report.Compare[k], v)
					}
				}
				if strings.HasPrefix(tc.name, "pilot-only") && report.Inputs["source"] != revision {
					t.Fatalf("%v: pilot-only inputs not reported: %v", python, report.Inputs)
				}
				results = append(results, string(out)+"\n"+string(rune('0'+code)))
			}
			if results[0] != results[1] {
				t.Fatalf("python -O changed the result:\n%s\n---\n%s", results[0], results[1])
			}
		})
	}
	if out, err := exec.Command("python3", script).CombinedOutput(); err == nil || !strings.Contains(string(out), "usage:") {
		t.Fatalf("missing arguments must fail with usage: %v\n%s", err, out)
	}
}
