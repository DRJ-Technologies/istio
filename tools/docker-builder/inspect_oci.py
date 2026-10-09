#!/usr/bin/env python3
# Copyright Istio Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Read-only qualification of a native OCI artifact from native-oci-build.yml.

usage: inspect_oci.py <extracted-artifact-dir> [<baseline-extracted-dir>]

The artifact holds one OCI layout per repository: all of pilot, proxyv2,
install-cni and ztunnel for a full build, or pilot alone beside the
pilot-inputs.txt record of a pilot-only build. For each repository it checks
that index.json selects exactly one image index whose bytes match its digest,
that every blob matches its name, that the index holds exactly linux/amd64
and linux/arm64 images whose configs agree, and that each image carries its
binaries. Go binaries must embed clean VCS build info with one revision across
the artifact, CGO disabled; a pilot-only build's revision must be the source it
recorded. It prints a JSON report, with each failed check under "findings",
and exits 1 if there are any. Checks are explicit, so python -O changes
nothing. A baseline is inspected the same way and its binaries compared.
Never contacts a registry.
"""
import gzip
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

REPOS = ["pilot", "proxyv2", "install-cni", "ztunnel"]
BINARIES = {
    "pilot": ["usr/local/bin/pilot-discovery"],
    "proxyv2": ["usr/local/bin/envoy", "usr/local/bin/pilot-agent"],
    "install-cni": ["usr/local/bin/install-cni", "opt/cni/bin/istio-cni"],
    "ztunnel": ["usr/local/bin/ztunnel"],
}
NATIVE = {"usr/local/bin/envoy", "usr/local/bin/ztunnel"}
PLATFORMS = {"linux/amd64", "linux/arm64"}
# What native-oci-build.yml writes for a pilot-only build.
PILOT_INPUTS = ["mode", "source", "tag", "beside", "proxy_run", "proxy_run_head", "PROXY_REPO_SHA",
                "native-proxy-amd64", "native-proxy-arm64"]
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class Inspection:
    def __init__(self, label):
        self.label = label
        self.findings = []

    def check(self, ok, message):
        if not ok:
            self.findings.append(f"{self.label}: {message}")
        return ok

    def blob(self, layout, digest):
        """The verified bytes of a referenced blob, or None (a finding)."""
        if not self.check(isinstance(digest, str) and DIGEST.match(digest), f"{layout.name}: invalid digest {digest!r}"):
            return None
        path = layout / "blobs" / "sha256" / digest.split(":", 1)[1]
        if not self.check(path.is_file(), f"{layout.name}: missing blob {digest}"):
            return None
        data = path.read_bytes()
        if not self.check("sha256:" + hashlib.sha256(data).hexdigest() == digest, f"{layout.name}: blob {digest} does not match its digest"):
            return None
        return data

    def json_blob(self, layout, digest):
        data = self.blob(layout, digest)
        if data is None:
            return None
        try:
            return json.loads(data)
        except ValueError:
            self.check(False, f"{layout.name}: blob {digest} is not JSON")
            return None


def go_build_info(data):
    """The `go version -m` build settings of a Go binary, or None."""
    with tempfile.NamedTemporaryFile() as f:
        f.write(data)
        f.flush()
        result = subprocess.run(["go", "version", "-m", f.name], capture_output=True, text=True)
    if result.returncode != 0 or not result.stdout:
        return None
    lines = result.stdout.splitlines()
    settings = dict(line.split("\t")[2].split("=", 1) for line in lines
                    if line.startswith("\tbuild\t") and "=" in line.split("\t")[2])
    settings["go"] = lines[0].split(": ", 1)[-1]
    return settings


def layer_files(ins, layout, manifest, wanted):
    found = {}
    for layer in manifest.get("layers", []):
        data = ins.blob(layout, layer.get("digest"))
        if data is None:
            continue
        try:
            if data[:2] == b"\x1f\x8b":
                data = gzip.decompress(data)
            with tarfile.open(fileobj=io.BytesIO(data)) as tar:
                for member in tar.getmembers():
                    name = member.name.lstrip("./")
                    if name in wanted and member.isfile():
                        content = tar.extractfile(member).read()
                        entry = {"sha256": hashlib.sha256(content).hexdigest()}
                        if name not in NATIVE:
                            info = go_build_info(content)
                            if ins.check(info is not None, f"{layout.name}: {name} has no Go build info"):
                                entry.update({k: info.get(k) for k in ("go", "vcs.revision", "vcs.modified", "CGO_ENABLED")})
                        found[name] = entry
        except (OSError, EOFError, tarfile.TarError):
            ins.check(False, f"{layout.name}: layer {layer.get('digest')} is not a readable tar")
    return found


def inspect_layout(ins, layout, repo):
    try:
        envelope = json.loads((layout / "index.json").read_text())
    except (OSError, ValueError):
        ins.check(False, f"{repo}: unreadable index.json")
        return None
    selected = envelope.get("manifests") or []
    if not ins.check(len(selected) == 1, f"{repo}: index.json must select exactly one image index, not {len(selected)}"):
        return None
    selected = selected[0]
    index = ins.json_blob(layout, selected.get("digest"))
    if index is None:
        return None
    files = sorted((layout / "blobs" / "sha256").iterdir()) if (layout / "blobs" / "sha256").is_dir() else []
    bad = [f.name for f in files if hashlib.sha256(f.read_bytes()).hexdigest() != f.name]
    ins.check(not bad, f"{repo}: blobs not matching their names: {bad}")
    children, attestations = [], []
    for m in index.get("manifests", []):
        platform = m.get("platform", {})
        if platform.get("os") == "unknown":
            attestations.append({"manifest": m.get("digest"), "for": m.get("annotations", {}).get("vnd.docker.reference.digest")})
            continue
        name = f'{platform.get("os")}/{platform.get("architecture")}'
        manifest = ins.json_blob(layout, m.get("digest"))
        config = ins.json_blob(layout, (manifest or {}).get("config", {}).get("digest")) if manifest else None
        if manifest is None or config is None:
            continue
        config_platform = f'{config.get("os")}/{config.get("architecture")}'
        ins.check(config_platform == name, f"{repo}: {name} image config is {config_platform}")
        binaries = layer_files(ins, layout, manifest, set(BINARIES[repo]))
        missing = sorted(set(BINARIES[repo]) - set(binaries))
        ins.check(not missing, f"{repo}: {name} image lacks {missing}")
        children.append({"platform": name, "manifest": m.get("digest"), "config_os_arch": config_platform,
                         "entrypoint": config.get("config", {}).get("Entrypoint"), "binaries": binaries})
    platforms = sorted(c["platform"] for c in children)
    ins.check(platforms == sorted(PLATFORMS), f"{repo}: images for {platforms}, not {sorted(PLATFORMS)}")
    images = {c["manifest"] for c in children}
    ins.check(all(a["for"] in images for a in attestations), f"{repo}: an attestation names no image of this index")
    return {
        "selected_index_digest": selected.get("digest"),
        "ref_name": selected.get("annotations", {}).get("org.opencontainers.image.ref.name"),
        "blobs": len(files), "bad_blobs": bad, "children": children, "attestations": attestations,
    }


def pilot_inputs(ins, root):
    path = root / "pilot-inputs.txt"
    if not path.exists():
        return None
    lines = path.read_text().splitlines()
    pairs = [line.split("=", 1) for line in lines]
    ins.check(all(len(p) == 2 for p in pairs), "pilot-inputs.txt has a line without key=value")
    inputs = dict(p for p in pairs if len(p) == 2)
    ins.check([p[0] for p in pairs] == PILOT_INPUTS, f"pilot-inputs.txt keys {[p[0] for p in pairs]}, not {PILOT_INPUTS}")
    ins.check(inputs.get("mode") == "pilot-only", "pilot-inputs.txt mode is not pilot-only")
    for arch in ("amd64", "arm64"):
        artifact = inputs.get(f"native-proxy-{arch}", "").split(" ")
        ins.check(len(artifact) == 2 and artifact[0].isdigit() and DIGEST.match(artifact[1]),
                  f"pilot-inputs.txt native-proxy-{arch} is not '<artifact id> sha256:<digest>'")
    return inputs


def inspect(root, label):
    ins = Inspection(label)
    report = {}
    if not ins.check(root.is_dir(), f"{root} is not a directory"):
        return ins, report, None
    inputs = pilot_inputs(ins, root)
    repos = [r for r in REPOS if (root / r).exists()]
    expected = ["pilot"] if inputs is not None else REPOS
    ins.check(repos == expected, f"holds {repos}; a {'pilot-only' if inputs is not None else 'full'} artifact holds {expected}")
    for repo in repos:
        layout = inspect_layout(ins, root / repo, repo)
        if layout is not None:
            report[repo] = layout
    go = [(repo, c["platform"], name, b) for repo, r in report.items() for c in r["children"]
          for name, b in c["binaries"].items() if name not in NATIVE and "go" in b]
    revisions = sorted({b.get("vcs.revision") for *_, b in go})
    ins.check(all(b.get("vcs.revision") for *_, b in go), "a Go binary has no vcs.revision")
    ins.check(len(revisions) <= 1, f"Go binaries from several revisions: {revisions}")
    for repo, platform, name, b in go:
        ins.check(b.get("vcs.modified") == "false", f"{repo} {platform} {name} built from modified sources")
        ins.check(b.get("CGO_ENABLED") == "0", f"{repo} {platform} {name} built with CGO_ENABLED={b.get('CGO_ENABLED')}")
    if inputs is not None:
        ins.check(revisions == [inputs.get("source")], f"pilot revision {revisions} is not the recorded source {inputs.get('source')}")
        refs = {r["ref_name"] for r in report.values()}
        ins.check(all(ref in (inputs.get("tag"), None) or str(ref).endswith(":" + inputs.get("tag", "")) for ref in refs),
                  f"image reference {sorted(map(str, refs))} is not the recorded tag {inputs.get('tag')}")
    return ins, report, inputs


def main(argv):
    if len(argv) not in (2, 3):
        print(__doc__, file=sys.stderr)
        return 2
    try:
        ins, current, inputs = inspect(Path(argv[1]), "artifact")
        out = {"artifact": current}
        findings = ins.findings
        if inputs is not None:
            out["pilot_only_inputs"] = inputs
        if len(argv) == 3:
            base_ins, base, _ = inspect(Path(argv[2]), "baseline")
            findings += base_ins.findings
            compare = {}
            for repo, r in current.items():
                for child in r["children"]:
                    other = next((c for c in base.get(repo, {}).get("children", []) if c["platform"] == child["platform"]), None)
                    for name, b in child["binaries"].items():
                        same = other is not None and other["binaries"].get(name, {}).get("sha256") == b["sha256"]
                        compare[f'{repo} {child["platform"]} {name}'] = "identical" if same else "differs"
            out["binary_comparison_vs_baseline"] = compare
    except Exception as e:  # anything unexpected is a failed inspection, never a pass
        out, findings = {}, [f"inspection error: {e!r}"]
    out["findings"] = findings
    json.dump(out, sys.stdout, indent=2)
    print()
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
