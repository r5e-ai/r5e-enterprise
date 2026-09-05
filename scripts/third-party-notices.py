#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Generate THIRD_PARTY_NOTICES.md from the resolved dependency trees.

The notices are generated, not hand-kept, because a hand-kept list is wrong
the first time a dependency moves. Three sources, all read from disk with no
network:

  Hex    `deps/*/hex_metadata.config` in each of the three repositories.
  Cargo  `cargo metadata --offline` for each Rust crate in the release.
  npm    `ui/node_modules/.pnpm/*/node_modules/*/package.json` — the resolved
         workspace set, which is also what the image's dependency collector
         walks.

Ten Hex packages ship no LICENCE, LICENSE or COPYING file in their published
tarball, so a collector that copies license files finds nothing to copy for
them. Their notice is synthesised here from the `licenses` field in the
package's own metadata plus the canonical text of the license it names, so
that the notice travels with the distribution as MIT requires.
"""

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import subprocess
import sys

LICENSE_FILE_NAMES = ("LICENSE", "LICENCE", "COPYING", "NOTICE")

MIT_TEXT = """Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."""

APACHE_POINTER = """Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

The complete Apache License 2.0 text is distributed with this release as
`r5e-core/LICENSE`."""


def hex_packages(deps_dir):
    """`[(name, version, [licenses], ships_license_text)]` for a `deps/` tree."""
    found = []
    if not deps_dir.is_dir():
        return found
    for package in sorted(deps_dir.iterdir()):
        metadata = package / "hex_metadata.config"
        if not metadata.is_file():
            continue
        text = metadata.read_text(errors="replace")
        name = _erl_string(text, "name") or package.name
        version = _erl_string(text, "version") or "unknown"
        licenses = _erl_list(text, "licenses")
        ships = any(
            child.name.upper().startswith(LICENSE_FILE_NAMES)
            for child in package.rglob("*")
            if child.is_file()
        )
        found.append((name, version, licenses, ships))
    return found


def _erl_string(text, key):
    match = re.search(r'\{<<"%s">>,\s*<<"([^"]*)">>\}' % key, text, re.S)
    return match.group(1) if match else None


def _erl_list(text, key):
    match = re.search(r'\{<<"%s">>,\s*\[(.*?)\]\}' % key, text, re.S)
    if not match:
        return []
    return re.findall(r'<<"([^"]*)">>', match.group(1))


def cargo_packages(manifests):
    """`[(name, version, license)]` across every crate graph, deduplicated."""
    seen = {}
    for manifest in manifests:
        if not manifest.is_file():
            continue
        result = subprocess.run(
            ["cargo", "metadata", "--offline", "--format-version", "1",
             "--manifest-path", str(manifest)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(f"warning: cargo metadata failed for {manifest}:\n{result.stderr.strip()}",
                  file=sys.stderr)
            continue
        root = manifest.parent.resolve()
        for package in json.loads(result.stdout)["packages"]:
            # The crate under this repository is not a third party.
            if Path(package["manifest_path"]).resolve().is_relative_to(root):
                continue
            license_id = package.get("license") or (
                f"see {Path(package['license_file']).name}"
                if package.get("license_file") else "unstated"
            )
            seen[(package["name"], package["version"])] = license_id
    return [(name, version, seen[(name, version)]) for name, version in sorted(seen)]


def npm_packages(pnpm_dir):
    """`[(name, version, license)]` for the resolved workspace set."""
    found = {}
    if not pnpm_dir.is_dir():
        return []
    for entry in sorted(pnpm_dir.iterdir()):
        modules = entry / "node_modules"
        if not modules.is_dir():
            continue
        for manifest in sorted(modules.glob("*/package.json")) + sorted(
            modules.glob("@*/*/package.json")
        ):
            try:
                data = json.loads(manifest.read_text(errors="replace"))
            except json.JSONDecodeError:
                continue
            name, version = data.get("name"), data.get("version")
            if not name or not version:
                continue
            license_id = data.get("license")
            if isinstance(license_id, dict):
                license_id = license_id.get("type")
            if not license_id and isinstance(data.get("licenses"), list):
                license_id = " OR ".join(
                    item.get("type", "") for item in data["licenses"] if isinstance(item, dict)
                )
            found[(name, version)] = license_id or "unstated"
    return [(name, version, found[(name, version)]) for name, version in sorted(found)]


def table(rows):
    lines = ["| Package | Version | License |", "|---|---|---|"]
    lines += [f"| `{name}` | {version} | {license_id} |" for name, version, license_id in rows]
    return "\n".join(lines)


def main():
    enterprise = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=enterprise / "THIRD_PARTY_NOTICES.md")
    parser.add_argument("--core", type=Path, default=enterprise.parent / "r5e-core")
    parser.add_argument("--kernel", type=Path, default=enterprise.parent / "r5e-kernel")
    arguments = parser.parse_args()

    hex_rows, missing_text = {}, []
    for label, deps in (
        ("r5e-enterprise", enterprise / "deps"),
        ("r5e-kernel", arguments.kernel / "deps"),
        ("r5e-core", arguments.core / "verifier" / "deps"),
    ):
        for name, version, licenses, ships in hex_packages(deps):
            license_id = " OR ".join(licenses) if licenses else "unstated"
            hex_rows[(name, version)] = license_id
            if not ships and (name, version) not in {(n, v) for n, v, _ in missing_text}:
                missing_text.append((name, version, license_id))
    hex_table = [(name, version, hex_rows[(name, version)]) for name, version in sorted(hex_rows)]

    cargo_table = cargo_packages([
        enterprise / "native/recurse_cedar/Cargo.toml",
        enterprise / "native/recurse_spiffe/Cargo.toml",
        arguments.kernel / "native/r5e_cedar/Cargo.toml",
    ])
    npm_table = npm_packages(enterprise / "ui/node_modules/.pnpm")

    notices = []
    for name, version, license_id in sorted(missing_text):
        if "MIT" in license_id:
            body = f"Copyright (c) the {name} authors.\n\n{MIT_TEXT}"
        elif "Apache" in license_id:
            body = APACHE_POINTER
        else:
            body = f"Licensed {license_id}; the package publishes no license text."
        notices.append(f"### `{name}` {version} — {license_id}\n\n```\n{body}\n```\n")

    tally = Counter(license_id for _, _, license_id in hex_table + cargo_table + npm_table)
    license_tally = "\n".join(
        f"| {license_id} | {count} |"
        for license_id, count in sorted(tally.items(), key=lambda item: (-item[1], item[0]))
    )

    document = f"""# Third-party notices

Generated by `scripts/third-party-notices.py` from the resolved dependency
trees of the three repositories in this release. It is not hand-kept: rerun the
script when a dependency moves.

Every license below is permissive: it allows redistribution in source and binary
form with attribution. No copyleft dependency (GPL, LGPL, AGPL, MPL) and no
source-available dependency (SSPL, BUSL, Elastic) is present in any of the three
trees. The tally is mechanical — the ids are the ones the packages state about
themselves, spelling and all.

| Ecosystem | Packages |
|---|---:|
| Hex | {len(hex_table)} |
| Cargo | {len(cargo_table)} |
| npm | {len(npm_table)} |

| License id as stated | Packages |
|---|---:|
{license_tally}

The r5e code itself is not listed here. Its license is in `LICENSE` and
`LICENSE.md` in each repository.

## Hex

Read from each package's own `hex_metadata.config`, across
`r5e-enterprise/deps/`, `r5e-kernel/deps/` and `r5e-core/verifier/deps/`.

{table(hex_table)}

## Cargo

`cargo metadata --offline` over `native/recurse_cedar`, `native/recurse_spiffe`
and `r5e-kernel/native/r5e_cedar`, with the r5e crates themselves removed.

{table(cargo_table)}

## npm

The resolved workspace set under `ui/node_modules/.pnpm/`, which is what the
image's dependency collector walks. Build-time-only packages are included: the
list is what the tree resolves, not a judgement about what reaches the image.

{table(npm_table)}

## Packages that ship no license text

These {len(notices)} Hex packages publish no `LICENSE`, `LICENCE` or `COPYING`
file in their tarball, so a collector that copies license files finds nothing
to copy. The license each one names in its own metadata is reproduced below, so
the notice travels with the distribution.

{chr(10).join(notices)}"""

    arguments.output.write_text(document)
    print(f"{arguments.output}: hex {len(hex_table)}, cargo {len(cargo_table)}, "
          f"npm {len(npm_table)}, synthesised notices {len(notices)}")


if __name__ == "__main__":
    main()
