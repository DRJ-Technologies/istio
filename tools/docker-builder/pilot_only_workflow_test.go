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
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// Execute the pilot-only step against a synthetic GitHub API: it must take
// the native proxy only from a successful main run of this workflow with the
// same PROXY_REPO_SHA, with every artifact matching its recorded digest.
func TestNativePilotOnlyProxyArtifacts(t *testing.T) {
	script := proxyWorkflowStep(t, "build", "Download referenced native proxy artifacts")
	const repo, runID, head, tag = "DRJ-Technologies/istio", "4242", "referenced-head", "1.31.1-drj.5-distroless"
	sanitize := regexp.MustCompile(`[^A-Za-z0-9]`)
	for _, mode := range []string{
		"clean", "bad-run-id", "other-workflow", "other-branch", "failed-run", "other-proxy-sha",
		"digest-mismatch", "missing-artifact", "expired-artifact", "reused-tag",
	} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			istio, fixtures, commands := filepath.Join(root, "istio"), filepath.Join(root, "api"), filepath.Join(root, "commands")
			serve := func(path string, data []byte) {
				t.Helper()
				proxyFixtureWrite(t, filepath.Join(fixtures, sanitize.ReplaceAllString("repos/"+repo+"/"+path, "_")), data, 0o600)
			}
			deps := func(sha string) []byte {
				b, err := json.Marshal([]map[string]string{{"name": "PROXY_REPO_SHA", "lastStableSHA": sha}})
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			proxyFixtureWrite(t, filepath.Join(istio, "istio.deps"), deps("native-proxy-source"), 0o600)

			run := map[string]any{
				"path": ".github/workflows/native-oci-build.yml", "head_branch": "main", "event": "workflow_dispatch",
				"status": "completed", "conclusion": "success", "head_sha": head,
				"repository": map[string]string{"full_name": repo},
			}
			switch mode {
			case "other-workflow":
				run["path"] = ".github/workflows/other.yml"
			case "other-branch":
				run["head_branch"] = "feature"
			case "failed-run":
				run["conclusion"] = "failure"
			}
			b, _ := json.Marshal(run)
			serve("actions/runs/"+runID, b)
			referencedSHA := "native-proxy-source"
			if mode == "other-proxy-sha" {
				referencedSHA = "other-proxy-source"
			}
			b, _ = json.Marshal(map[string]string{"content": base64.StdEncoding.EncodeToString(deps(referencedSHA))})
			serve("contents/istio.deps?ref="+head, b)

			binaries := map[string][]byte{}
			artifacts := []map[string]any{{
				"name": "istio-oci-1.31.1-drj.4-distroless", "id": 1, "expired": false,
				"digest": "sha256:" + hex.EncodeToString(make([]byte, 32)),
			}}
			if mode == "reused-tag" {
				artifacts[0]["name"] = "istio-oci-" + tag
			}
			for i, arch := range []string{"amd64", "arm64"} {
				binaries[arch] = proxyFixtureELF(uint16(62 + i*121))
				var archive bytes.Buffer
				w := zip.NewWriter(&archive)
				for name, data := range map[string][]byte{"envoy": binaries[arch], "envoy_tar.tar.gz": []byte("native " + arch + " archive")} {
					f, err := w.Create(name)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := f.Write(data); err != nil {
						t.Fatal(err)
					}
				}
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
				id := 100 + i
				sum := sha256.Sum256(archive.Bytes())
				digest := "sha256:" + hex.EncodeToString(sum[:])
				served := archive.Bytes()
				if mode == "digest-mismatch" && arch == "arm64" {
					served = append(append([]byte{}, served...), 0)
				}
				serve("actions/artifacts/"+strconv.Itoa(id)+"/zip", served)
				if mode == "missing-artifact" && arch == "arm64" {
					continue
				}
				artifacts = append(artifacts, map[string]any{
					"name": "native-proxy-" + arch, "id": id, "expired": mode == "expired-artifact" && arch == "amd64", "digest": digest,
				})
			}
			b, _ = json.Marshal(map[string]any{"artifacts": artifacts})
			serve("actions/runs/"+runID+"/artifacts?per_page=100", b)

			// gh api [-H header] PATH: serve the fixture for PATH, or fail.
			proxyFixtureWrite(t, filepath.Join(commands, "gh"), []byte(`#!/bin/bash
set -euo pipefail
test "$1" = api && test -n "$GH_TOKEN"
path="${!#}"
cat "$FIXTURE_API/$(printf '%s' "$path" | sed 's/[^A-Za-z0-9]/_/g')"
`), 0o700)

			id := runID
			if mode == "bad-run-id" {
				id = "4242; touch injected"
			}
			cmd := exec.Command("bash", "-c", script)
			cmd.Dir = istio
			cmd.Env = []string{
				"PATH=" + commands + ":/usr/bin:/bin", "HOME=" + root, "RUNNER_TEMP=" + root, "FIXTURE_API=" + fixtures,
				"GH_TOKEN=fixture-token", "GITHUB_REPOSITORY=" + repo, "GITHUB_SHA=pilot-source",
				"PROXY_RUN_ID=" + id, "INPUT_ARTIFACT_TAG=" + tag,
			}
			log, err := cmd.CombinedOutput()
			if (err == nil) != (mode == "clean") {
				t.Fatalf("unexpected result: %v\n%s", err, log)
			}
			if _, err := os.Stat(filepath.Join(istio, "injected")); !os.IsNotExist(err) {
				t.Fatal("run ID reached a shell")
			}
			reasons := map[string]string{
				"bad-run-id":       "proxy_run_id must be a workflow run ID",
				"other-workflow":   "is not a successful main run of this workflow",
				"other-branch":     "is not a successful main run of this workflow",
				"failed-run":       "is not a successful main run of this workflow",
				"other-proxy-sha":  "Referenced run built PROXY_REPO_SHA other-proxy-source",
				"digest-mismatch":  "native-proxy-arm64 does not match its recorded digest",
				"missing-artifact": "expected one unexpired native-proxy-arm64 artifact",
				"expired-artifact": "expected one unexpired native-proxy-amd64 artifact",
				"reused-tag":       "artifact_tag must be new",
			}
			if mode != "clean" {
				if !bytes.Contains(log, []byte(reasons[mode])) {
					t.Fatalf("refused for another reason:\n%s", log)
				}
				return
			}
			for arch, want := range binaries {
				got, err := os.ReadFile(filepath.Join(root, "native-proxy-"+arch, "envoy"))
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("referenced %s proxy not delivered: %v", arch, err)
				}
				if _, err := os.Stat(filepath.Join(root, "native-proxy-"+arch, "envoy_tar.tar.gz")); err != nil {
					t.Fatal(err)
				}
			}
			inputs, err := os.ReadFile(filepath.Join(root, "pilot-inputs.txt"))
			if err != nil {
				t.Fatal(err)
			}
			want := regexp.MustCompile(`^mode=pilot-only\nsource=pilot-source\ntag=` + regexp.QuoteMeta(tag) + `\nproxy_run=4242\n` +
				`proxy_run_head=referenced-head\nPROXY_REPO_SHA=native-proxy-source\n` +
				`native-proxy-amd64=100 sha256:[0-9a-f]{64}\nnative-proxy-arm64=101 sha256:[0-9a-f]{64}\n$`)
			if !want.Match(inputs) {
				t.Fatalf("pilot-only provenance:\n%s", inputs)
			}
		})
	}
}
