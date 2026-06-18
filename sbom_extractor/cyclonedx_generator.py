"""CycloneDX 1.5 JSON generator with streaming output support."""
import datetime
import hashlib
import json
import os
import re
import uuid
from typing import Any, Dict, List, Optional

from sbom_extractor import __version__
from sbom_extractor.cpe import generate_cpe
from sbom_extractor.purl import generate_purl

HTML_FILES_CAP = 5_000


class CycloneDXGenerator:
    """Generate CycloneDX 1.5 JSON SBOMs."""

    def __init__(
        self,
        project_name: str,
        project_version: str = "1.0.0",
        git_info: Optional[Dict[str, str]] = None,
        supplier: Optional[str] = None,
        reproducible: bool = False,
    ) -> None:
        self.project_name = project_name
        self.project_version = project_version
        self.supplier = supplier
        self.git_info = git_info or {}

        if reproducible:
            self.creation_time = "1970-01-01T00:00:00Z"
            self.serial_number = (
                "urn:uuid:"
                + str(uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"sbom-extractor/{project_name}/{project_version}",
                ))
            )
        else:
            self.creation_time = datetime.datetime.now(datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            self.serial_number = f"urn:uuid:{uuid.uuid4()}"

    # ── Internal helpers ──────────────────────────────────────────────

    def _file_ref(self, path: str) -> str:
        return f"file:{hashlib.md5(path.encode()).hexdigest()[:16]}"

    def _format_license(self, lic: str) -> List[Dict[str, Any]]:
        if not lic or lic == "NOASSERTION":
            return []
        if " OR " in lic or " AND " in lic or " WITH " in lic:
            return [{"expression": lic}]
        if re.match(r"^[a-zA-Z0-9\.\-\+\s\(\)]+$", lic) and len(lic) < 80:
            return [{"license": {"id": lic.strip()}}]
        return [{"license": {"name": lic.strip()}}]

    def _root_component(self) -> Dict[str, Any]:
        ext_refs: List[Dict[str, Any]] = []
        if self.git_info.get("remote_url"):
            comment_parts = []
            if self.git_info.get("commit"):
                comment_parts.append(f"Commit: {self.git_info['commit']}")
            if self.git_info.get("branch"):
                comment_parts.append(f"Branch: {self.git_info['branch']}")
            ext_refs.append({
                "type": "vcs",
                "url": self.git_info["remote_url"],
                **({"comment": "  ".join(comment_parts)} if comment_parts else {}),
            })

        comp: Dict[str, Any] = {
            "bom-ref": f"pkg:generic/{self.project_name}@{self.project_version}",
            "type": "application",
            "name": self.project_name,
            "version": self.project_version,
            "description": f"SBOM for {self.project_name}",
        }
        if self.supplier:
            comp["supplier"] = {"name": self.supplier}
        if ext_refs:
            comp["externalReferences"] = ext_refs
        return comp

    def _metadata(self) -> Dict[str, Any]:
        m: Dict[str, Any] = {
            "timestamp": self.creation_time,
            "tools": {
                "components": [
                    {"type": "application", "name": "sbom-extractor", "version": __version__}
                ]
            },
            "component": self._root_component(),
        }
        if self.supplier:
            m["supplier"] = {"name": self.supplier}
        return m

    def _file_component(self, f: Dict[str, Any]) -> Dict[str, Any]:
        comp: Dict[str, Any] = {
            "bom-ref": self._file_ref(f["path"]),
            "type": "file",
            "name": f["path"],
        }
        hashes = []
        if f.get("sha256"):
            hashes.append({"alg": "SHA-256", "content": f["sha256"]})
        if f.get("sha1"):
            hashes.append({"alg": "SHA-1", "content": f["sha1"]})
        if hashes:
            comp["hashes"] = hashes
        lic = self._format_license(f.get("license", "NOASSERTION"))
        if lic:
            comp["licenses"] = lic
        return comp

    def _dep_component(self, dep: Dict[str, Any]) -> Dict[str, Any]:
        purl = generate_purl(dep)
        cpe = generate_cpe(dep)
        comp: Dict[str, Any] = {
            "bom-ref": purl,
            "type": "library",
            "name": dep["name"],
            "version": dep.get("version", "unknown"),
            "purl": purl,
            "cpe": cpe,
        }
        if self.supplier:
            comp["supplier"] = {"name": self.supplier}
        lic = self._format_license(dep.get("license", "NOASSERTION"))
        if lic:
            comp["licenses"] = lic
        return comp

    # ── Public API ────────────────────────────────────────────────────

    def write_streaming(
        self,
        files: List[Dict[str, Any]],
        dependencies: List[Dict[str, Any]],
        output_path: str,
    ) -> None:
        """Stream-write a complete CycloneDX 1.5 JSON document to *output_path*."""
        main_ref = self._root_component()["bom-ref"]

        seen_purls: set = set()
        dep_comps: List[Dict[str, Any]] = []
        for dep in dependencies:
            purl = generate_purl(dep)
            if purl not in seen_purls:
                seen_purls.add(purl)
                dep_comps.append(self._dep_component(dep))

        tmp = output_path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as out:
                out.write("{\n")
                out.write(f'  "bomFormat": "CycloneDX",\n')
                out.write(f'  "specVersion": "1.5",\n')
                out.write(f'  "serialNumber": {json.dumps(self.serial_number)},\n')
                out.write(f'  "version": 1,\n')
                out.write(f'  "metadata": {json.dumps(self._metadata())},\n')

                # Components
                out.write('  "components": [\n')
                first = True
                for f in files:
                    sep = "" if first else ",\n"
                    out.write(f'{sep}    {json.dumps(self._file_component(f))}')
                    first = False
                for dc in dep_comps:
                    sep = "" if first else ",\n"
                    out.write(f'{sep}    {json.dumps(dc)}')
                    first = False
                out.write("\n  ],\n")

                # Dependencies (only meaningful edges; skip the O(n) empty file entries)
                main_depends_on = (
                    [self._file_ref(f["path"]) for f in files]
                    + [dc["bom-ref"] for dc in dep_comps]
                )
                out.write('  "dependencies": [\n')
                out.write(f'    {json.dumps({"ref": main_ref, "dependsOn": main_depends_on})}')
                out.write("\n  ]\n")
                out.write("}\n")

            os.replace(tmp, output_path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def generate(
        self,
        files: List[Dict[str, Any]],
        dependencies: List[Dict[str, Any]],
        max_files: int = HTML_FILES_CAP,
    ) -> Dict[str, Any]:
        """Return the CycloneDX 1.5 document as a dict."""
        main_ref = self._root_component()["bom-ref"]
        truncated = len(files) > max_files
        visible_files = files[:max_files] if truncated else files

        seen_purls: set = set()
        dep_comps: List[Dict[str, Any]] = []
        for dep in dependencies:
            purl = generate_purl(dep)
            if purl not in seen_purls:
                seen_purls.add(purl)
                dep_comps.append(self._dep_component(dep))

        bom: Dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": self.serial_number,
            "version": 1,
            "metadata": self._metadata(),
            "components": [],
            "dependencies": [],
        }
        if truncated:
            bom["metadata"]["properties"] = [
                {
                    "name": "sbom-extractor:truncated",
                    "value": f"File list capped at {max_files} of {len(files)} total",
                }
            ]

        main_depends_on: List[str] = []
        for f in visible_files:
            comp = self._file_component(f)
            bom["components"].append(comp)
            main_depends_on.append(comp["bom-ref"])

        for dc in dep_comps:
            bom["components"].append(dc)
            main_depends_on.append(dc["bom-ref"])

        bom["dependencies"].append({"ref": main_ref, "dependsOn": main_depends_on})

        return bom
