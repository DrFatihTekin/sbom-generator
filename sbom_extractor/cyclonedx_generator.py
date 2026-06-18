import datetime
import hashlib
import re
import uuid
from typing import Any, Dict, List, Optional

from sbom_extractor import __version__
from sbom_extractor.purl import generate_purl


class CycloneDXGenerator:
    """Generate a CycloneDX 1.5 JSON Software Bill of Materials."""

    def __init__(
        self,
        project_name: str,
        project_version: str = "1.0.0",
        git_info: Optional[Dict[str, str]] = None,
    ) -> None:
        self.project_name = project_name
        self.project_version = project_version
        self.serial_number = f"urn:uuid:{uuid.uuid4()}"
        self.creation_time = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        self.git_info = git_info or {}

    def _file_ref(self, path: str) -> str:
        return f"file:{hashlib.md5(path.encode()).hexdigest()[:16]}"

    def _format_license(self, lic: str) -> List[Dict[str, Any]]:
        if not lic or lic == "NOASSERTION":
            return []
        valid = re.compile(r"^[a-zA-Z0-9\.\-\+\s\(\)]+$")
        if " OR " in lic or " AND " in lic or " WITH " in lic:
            return [{"expression": lic}]
        if valid.match(lic) and len(lic) < 80:
            return [{"license": {"id": lic.strip()}}]
        return [{"license": {"name": lic.strip()}}]

    def generate(
        self, files: List[Dict[str, Any]], dependencies: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        main_ref = f"pkg:generic/{self.project_name}@{self.project_version}"

        # ── External references for the root component ────────────────
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

        root_component: Dict[str, Any] = {
            "bom-ref": main_ref,
            "type": "application",
            "name": self.project_name,
            "version": self.project_version,
            "description": f"SBOM for {self.project_name}",
        }
        if ext_refs:
            root_component["externalReferences"] = ext_refs

        bom: Dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": self.serial_number,
            "version": 1,
            "metadata": {
                "timestamp": self.creation_time,
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": "sbom-extractor",
                            "version": __version__,
                        }
                    ]
                },
                "component": root_component,
            },
            "components": [],
            "dependencies": [],
        }

        main_depends_on: List[str] = []

        # ── Scanned files ─────────────────────────────────────────────
        for f in files:
            ref = self._file_ref(f["path"])
            main_depends_on.append(ref)

            hashes = []
            if f.get("sha256"):
                hashes.append({"alg": "SHA-256", "content": f["sha256"]})
            if f.get("sha1"):
                hashes.append({"alg": "SHA-1", "content": f["sha1"]})

            comp: Dict[str, Any] = {
                "bom-ref": ref,
                "type": "file",
                "name": f["path"],
            }
            if hashes:
                comp["hashes"] = hashes
            lic = self._format_license(f.get("license", "NOASSERTION"))
            if lic:
                comp["licenses"] = lic

            bom["components"].append(comp)

        # ── Third-party packages ──────────────────────────────────────
        added_refs: set = set()
        for dep in dependencies:
            purl = generate_purl(dep)
            if purl in added_refs:
                continue
            added_refs.add(purl)
            main_depends_on.append(purl)

            comp = {
                "bom-ref": purl,
                "type": "library",
                "name": dep["name"],
                "version": dep.get("version", "unknown"),
                "purl": purl,
            }
            lic = self._format_license(dep.get("license", "NOASSERTION"))
            if lic:
                comp["licenses"] = lic
            bom["components"].append(comp)

        # ── Dependency graph ──────────────────────────────────────────
        bom["dependencies"].append({"ref": main_ref, "dependsOn": main_depends_on})
        for f in files:
            bom["dependencies"].append({"ref": self._file_ref(f["path"]), "dependsOn": []})
        for dep in dependencies:
            purl = generate_purl(dep)
            if not any(d["ref"] == purl for d in bom["dependencies"]):
                bom["dependencies"].append({"ref": purl, "dependsOn": []})

        return bom
