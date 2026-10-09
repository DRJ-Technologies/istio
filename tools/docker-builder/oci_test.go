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
	"encoding/csv"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	testenv "istio.io/istio/pkg/test/env"
)

func ociFixture(t *testing.T) Args {
	t.Helper()
	return Args{
		Builder: DockerBuilder, OCIOutputDir: filepath.Join(t.TempDir(), "OCI, layouts"), OCIBuilder: "owned-fixture",
		Targets: []string{"pilot", "ztunnel"}, Variants: []string{DistrolessVariant},
		Hubs: []string{"localhost/istio"}, Tags: []string{"fixture-drj.1"},
		Architectures: []string{"linux/amd64", "linux/arm64"},
		Plan: map[string]BuildPlan{
			"linux/amd64": {Images: []ImagePlan{{Name: "pilot", Dockerfile: "Dockerfile.pilot"}, {Name: "ztunnel", Dockerfile: "Dockerfile.ztunnel"}}},
			"linux/arm64": {Images: []ImagePlan{{Name: "pilot", Dockerfile: "Dockerfile.pilot"}, {Name: "ztunnel", Dockerfile: "Dockerfile.ztunnel"}}},
		},
	}
}

func TestOCIValidation(t *testing.T) {
	for name, edit := range map[string]func(*Args){
		"push": func(a *Args) { a.Push = true }, "save": func(a *Args) { a.Save = true },
		"crane": func(a *Args) { a.Builder = CraneBuilder }, "remote-no-clobber": func(a *Args) { a.NoClobber = true },
		"relative-output": func(a *Args) { a.OCIOutputDir = "relative" }, "implicit-builder": func(a *Args) { a.OCIBuilder = "" },
		"multiple-tags":          func(a *Args) { a.Tags = append(a.Tags, "alias") },
		"multiple-hubs":          func(a *Args) { a.Hubs = append(a.Hubs, "example.test/alias") },
		"multiple-variants":      func(a *Args) { a.Variants = append(a.Variants, DefaultVariant) },
		"no-platform":            func(a *Args) { a.Architectures = nil },
		"builder-without-output": func(a *Args) { a.OCIOutputDir = "" },
	} {
		t.Run(name, func(t *testing.T) {
			a := ociFixture(t)
			edit(&a)
			if ValidateArgs(a) == nil {
				t.Fatal("incompatible OCI arguments accepted")
			}
		})
	}
	if err := ValidateArgs(ociFixture(t)); err != nil {
		t.Fatal(err)
	}
}

func readBake(t *testing.T) BakeFile {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(testenv.LocalOut, "dockerx_build", "docker-bake.json"))
	if err != nil {
		t.Fatal(err)
	}
	var bake BakeFile
	if err := json.Unmarshal(b, &bake); err != nil {
		t.Fatal(err)
	}
	return bake
}

func TestOCINativeCommands(t *testing.T) {
	for _, localOCI := range []bool{true, false} {
		t.Run(map[bool]string{true: "multiarch-oci", false: "legacy-load"}[localOCI], func(t *testing.T) {
			a := ociFixture(t)
			if !localOCI {
				a.OCIOutputDir, a.OCIBuilder = "", ""
			}
			previousOut, previousSrc, previousSkip := testenv.LocalOut, testenv.IstioSrc, SkipMake
			root := t.TempDir()
			testenv.LocalOut, testenv.IstioSrc, SkipMake = filepath.Join(root, "out"), root, ""
			t.Cleanup(func() { testenv.LocalOut, testenv.IstioSrc, SkipMake = previousOut, previousSrc, previousSkip })
			bin := filepath.Join(root, "bin")
			if err := os.MkdirAll(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(root, "tools"), 0o700); err != nil {
				t.Fatal(err)
			}
			for file, body := range map[string]string{
				filepath.Join(bin, "make"):                     "#!/bin/sh\nprintf 'make %s\\n' \"$TARGET_ARCH\" >> \"$RECORD\"\n",
				filepath.Join(bin, "docker"):                   "#!/bin/sh\nprintf 'docker %s\\n' \"$*\" >> \"$RECORD\"\n",
				filepath.Join(root, "tools", "docker-copy.sh"): "#!/bin/sh\nexit 0\n",
			} {
				if err := os.WriteFile(file, []byte(body), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			record := filepath.Join(root, "commands")
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("RECORD", record)
			t.Setenv("CI", "true") // OCI must not enter legacy automatic builder creation.
			if err := RunDocker(a); err != nil {
				t.Fatal(err)
			}
			calls, err := os.ReadFile(record)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(calls), "make amd64\n") != 1 || strings.Count(string(calls), "make arm64\n") != 1 {
				t.Fatalf("architecture build propagation lost: %s", calls)
			}
			wantBakes := 2
			if localOCI {
				wantBakes = 1
			}
			if strings.Count(string(calls), "docker buildx bake ") != wantBakes || strings.Contains(string(calls), "inspect") ||
				strings.Contains(string(calls), " create ") || strings.Contains(string(calls), " use ") {
				t.Fatalf("unexpected builder operations: %s", calls)
			}
			bake := readBake(t)
			for _, target := range a.Targets {
				got := bake.Target[target+"-distroless"]
				if localOCI {
					if !reflect.DeepEqual(got.Platforms, a.Architectures) || len(got.Tags) != 1 || strings.HasSuffix(got.Tags[0], "-arm64") ||
						!reflect.DeepEqual(got.Attest, []string{"type=provenance,mode=min"}) || !strings.Contains(string(calls), "--builder="+a.OCIBuilder) ||
						!strings.Contains(string(calls), "--allow=fs.write="+a.OCIOutputDir) {
						t.Fatalf("native OCI platform/tag/attestation/builder lost: %+v\n%s", got, calls)
					}
					fields, err := csv.NewReader(strings.NewReader(got.Outputs[0])).Read()
					want := []string{"type=oci", "tar=false", "oci-artifact=false", "dest=" + filepath.Join(a.OCIOutputDir, target)}
					if err != nil || !reflect.DeepEqual(fields, want) {
						t.Fatalf("OCI output/path encoding: %v %v; want %v", fields, err, want)
					}
				} else if len(got.Platforms) != 1 || got.Platforms[0] != "linux/arm64" || !strings.HasSuffix(got.Tags[0], "-arm64") ||
					!reflect.DeepEqual(got.Outputs, []string{"type=docker"}) || len(got.Attest) != 0 {
					t.Fatalf("legacy load changed: %+v", got)
				}
			}
		})
	}
}

func TestOCIBakePrint(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("native Docker CLI unavailable; synthetic command tests still run")
	}
	previous := testenv.LocalOut
	testenv.LocalOut = t.TempDir()
	t.Cleanup(func() { testenv.LocalOut = previous })
	a := ociFixture(t)
	if _, err := ConstructBakeFile(a); err != nil {
		t.Fatal(err)
	}
	// --print parses the generated native Bake file without a build, daemon,
	// registry access, credentials or the user's selected builder/configuration.
	private := t.TempDir()
	t.Setenv("DOCKER_CONFIG", private)
	t.Setenv("BUILDX_CONFIG", private)
	t.Setenv("DOCKER_HOST", "unix://"+filepath.Join(private, "no-daemon.sock"))
	t.Setenv("DOCKER_CONTEXT", "")
	t.Setenv("BUILDX_BUILDER", "")
	cmd := exec.Command("docker", "buildx", "bake", "--print", "--allow=fs.write="+a.OCIOutputDir,
		"-f", filepath.Join(testenv.LocalOut, "dockerx_build", "docker-bake.json"), "all")
	b, err := cmd.Output()
	if err != nil {
		t.Fatalf("native Bake parsing: %v", err)
	}
	var printed struct {
		Target map[string]struct {
			Platforms []string
			Tags      []string
			Output    []map[string]string
			Attest    []map[string]string
		}
	}
	if err := json.Unmarshal(b, &printed); err != nil {
		t.Fatal(err)
	}
	for _, target := range a.Targets {
		got := printed.Target[target+"-distroless"]
		if !reflect.DeepEqual(got.Platforms, a.Architectures) || len(got.Tags) != 1 || len(got.Output) != 1 || len(got.Attest) != 1 {
			t.Fatalf("native Bake lost multiarch singleton/provenance: %s", b)
		}
		if got.Output[0]["type"] != "oci" || got.Output[0]["tar"] != "false" || got.Output[0]["oci-artifact"] != "false" ||
			got.Output[0]["dest"] != filepath.Join(a.OCIOutputDir, target) || got.Attest[0]["mode"] != "min" {
			t.Fatalf("native Bake output path/format/provenance: %s", b)
		}
	}
}

func TestOCIWorkflowTag(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(testenv.IstioSrc, ".github", "workflows", "native-oci-build.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Env   map[string]string
			Steps []struct{ Name, Run string }
		}
	}
	if err := yaml.Unmarshal(b, &workflow); err != nil {
		t.Fatal(err)
	}
	job := workflow.Jobs["build"]
	var script string
	for _, step := range job.Steps {
		if step.Run != "" {
			if out, err := exec.Command("bash", "-n", "-c", step.Run).CombinedOutput(); err != nil {
				t.Fatalf("%s syntax: %v %s", step.Name, err, out)
			}
		}
		if step.Name == "Select artifact tag" {
			script = step.Run
		}
	}
	if script == "" {
		t.Fatal("no native tag input handling")
	}
	version := job.Env["VERSION"]
	// A full build takes drj.N; a pilot-only build (proxy run set) drj.N-pilot.M.
	full := map[string]bool{"-drj.1-distroless": true, "-drj.123-distroless": true}
	pilot := map[string]bool{"-drj.4-pilot.1-distroless": true, "-drj.4-pilot.12-distroless": true}
	for _, suffix := range []string{
		"-drj.1-distroless", "-drj.123-distroless", "-distroless", "-drj.0-distroless", "-drj.1-debug",
		"-drj.1-distroless; touch injected", "-drj.4-pilot.1-distroless", "-drj.4-pilot.12-distroless",
		"-drj.4-pilot.0-distroless", "-drj.4-pilot-distroless", "-drj.4-pilot.1-debug", "-drj.0-pilot.1-distroless",
	} {
		for _, run := range []string{"", "4242"} {
			t.Run(suffix+"/run="+run, func(t *testing.T) {
				dest := filepath.Join(t.TempDir(), "env")
				cmd := exec.Command("bash", "-c", script)
				cmd.Env = append(os.Environ(), "VERSION="+version, "INPUT_ARTIFACT_TAG="+version+suffix, "GITHUB_ENV="+dest, "PROXY_RUN_ID="+run)
				out, err := cmd.CombinedOutput()
				valid := (run == "" && full[suffix]) || (run != "" && pilot[suffix])
				if valid {
					got, readErr := os.ReadFile(dest)
					if err != nil || readErr != nil || string(got) != "TAG="+version+strings.TrimSuffix(suffix, "-distroless")+"\n" {
						t.Fatalf("tag input lost: %s %v %v %s", got, err, readErr, out)
					}
				} else if err == nil {
					t.Fatalf("invalid fork tag accepted: %s", out)
				} else if _, err := os.Stat(dest); !os.IsNotExist(err) {
					t.Fatal("invalid tag wrote workflow environment")
				}
			})
		}
	}
}
