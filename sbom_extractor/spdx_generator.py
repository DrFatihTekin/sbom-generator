"""SPDX 2.3 JSON generator with streaming output support."""
import datetime
import hashlib
import json
import os
import uuid
from typing import Any, Dict, List, Optional

from sbom_extractor import __version__
from sbom_extractor.cpe import generate_cpe
from sbom_extractor.purl import generate_purl

# Maximum files embedded when generate() is called in dict mode (e.g. for HTML).
# write_streaming() always emits the complete file list.
HTML_FILES_CAP = 5_000


class SPDXGenerator:
    """Generate SPDX 2.3 JSON SBOMs."""

    def __init__(
        self,
        project_name: str,
        project_version: str = "1.0.0",
        namespace: Optional[str] = None,
        git_info: Optional[Dict[str, str]] = None,
        supplier: Optional[str] = None,
        reproducible: bool = False,
    ) -> None:
        self.project_name = project_name
        self.project_version = project_version
        self.supplier = supplier
        self.git_info = git_info or {}
        self.reproducible = reproducible

        if reproducible:
            self.creation_time = "1970-01-01T00:00:00Z"
            self.namespace = namespace or (
                "https://spdx.org/spdxdocs/"
                + str(uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"sbom-extractor/{project_name}/{project_version}",
                ))
            )
        else:
            self.creation_time = datetime.datetime.now(datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            self.namespace = namespace or (
                f"https://spdx.org/spdxdocs/{project_name}-{uuid.uuid4()}"
            )

    # ── Internal helpers ──────────────────────────────────────────────

    def _file_id(self, path: str) -> str:
        return f"SPDXRef-File-{hashlib.md5(path.encode()).hexdigest()[:16]}"

    def _dep_id(self, dep: Dict[str, Any]) -> str:
        key = f"{dep['name']}@{dep.get('version', '')}@{dep.get('type', '')}"
        return f"SPDXRef-Pkg-{hashlib.md5(key.encode()).hexdigest()[:16]}"

    def _creation_info(self) -> Dict[str, Any]:
        creators = [f"Tool: sbom-extractor-{__version__}"]
        if self.supplier:
            creators.append(f"Organization: {self.supplier}")
        return {
            "created": self.creation_time,
            "creators": creators,
            "licenseListVersion": "3.22",
        }

    def _download_location(self) -> str:
        if self.git_info.get("remote_url"):
            ref = self.git_info.get("tag") or self.git_info.get("commit", "")
            remote = self.git_info["remote_url"]
            return f"git+{remote}@{ref}" if ref else f"git+{remote}"
        return "NOASSERTION"

    def _main_package(self, main_id: str, file_licenses: List[str]) -> Dict[str, Any]:
        dl = self._download_location()
        pkg: Dict[str, Any] = {
            "SPDXID": main_id,
            "name": self.project_name,
            "versionInfo": self.project_version,
            "downloadLocation": dl,
            "filesAnalyzed": True,
            "licenseDeclared": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "licenseInfoFromFiles": sorted(file_licenses) if file_licenses else ["NOASSERTION"],
            "copyrightText": "NOASSERTION",
        }
        if self.supplier:
            pkg["supplier"] = f"Organization: {self.supplier}"

        ext_refs = []
        if dl != "NOASSERTION":
            ext_refs.append({
                "referenceCategory": "OTHER",
                "referenceType": "vcs",
                "referenceLocator": dl,
            })
        if ext_refs:
            pkg["externalRefs"] = ext_refs

        if self.git_info.get("commit"):
            pkg["comment"] = (
                f"Commit: {self.git_info['commit']}"
                + (f"  Branch: {self.git_info['branch']}" if self.git_info.get("branch") else "")
            )
        return pkg

    def _file_entry(self, f: Dict[str, Any]) -> Dict[str, Any]:
        path = f["path"]
        fid = self._file_id(path)
        if path.endswith((".md", ".txt", ".rst")):
            ftypes = ["DOCUMENTATION"]
        elif f.get("is_source"):
            ftypes = ["SOURCE"]
        else:
            ftypes = ["BINARY"]

        entry: Dict[str, Any] = {
            "SPDXID": fid,
            "fileName": f"./{path}",
            "fileTypes": ftypes,
            "checksums": [],
            "licenseConcluded": "NOASSERTION",
            "licenseInfoInFiles": [f.get("license", "NOASSERTION")],
            "copyrightText": "NOASSERTION",
        }
        if f.get("sha256"):
            entry["checksums"].append({"algorithm": "SHA256", "checksumValue": f["sha256"]})
        if f.get("sha1"):
            entry["checksums"].append({"algorithm": "SHA1", "checksumValue": f["sha1"]})
        return entry

    def _dep_package(self, dep_id: str, dep: Dict[str, Any]) -> Dict[str, Any]:
        purl = generate_purl(dep)
        cpe = generate_cpe(dep)
        pkg: Dict[str, Any] = {
            "SPDXID": dep_id,
            "name": dep["name"],
            "versionInfo": dep.get("version", "unknown"),
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseDeclared": dep.get("license", "NOASSERTION"),
            "licenseConcluded": dep.get("license", "NOASSERTION"),
            "copyrightText": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": purl,
                },
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": cpe,
                },
            ],
        }
        if self.supplier:
            pkg["supplier"] = f"Organization: {self.supplier}"
        return pkg

    # ── Public API ────────────────────────────────────────────────────

    def write_streaming(
        self,
        files: List[Dict[str, Any]],
        dependencies: List[Dict[str, Any]],
        output_path: str,
    ) -> None:
        """Write a complete SPDX 2.3 JSON document to *output_path* without
        building the full document in memory."""
        main_id = "SPDXRef-Package-Main"

        file_licenses = sorted({
            f["license"]
            for f in files
            if f.get("license") and f["license"] != "NOASSERTION"
        })

        # Deduplicate dependencies
        seen_dep_ids: set = set()
        dep_entries: List[tuple] = []
        for dep in dependencies:
            did = self._dep_id(dep)
            if did not in seen_dep_ids:
                seen_dep_ids.add(did)
                dep_entries.append((did, dep))

        tmp = output_path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as out:
                out.write("{\n")
                out.write(f'  "spdxVersion": "SPDX-2.3",\n')
                out.write(f'  "dataLicense": "CC0-1.0",\n')
                out.write(f'  "SPDXID": "SPDXRef-DOCUMENT",\n')
                out.write(f'  "name": {json.dumps(self.project_name)},\n')
                out.write(f'  "documentNamespace": {json.dumps(self.namespace)},\n')
                out.write(f'  "creationInfo": {json.dumps(self._creation_info())},\n')

                # Packages
                out.write('  "packages": [\n')
                out.write(f'    {json.dumps(self._main_package(main_id, file_licenses))}')
                for did, dep in dep_entries:
                    out.write(f',\n    {json.dumps(self._dep_package(did, dep))}')
                out.write("\n  ],\n")

                # Files
                out.write('  "files": [\n')
                first = True
                for f in files:
                    sep = "" if first else ",\n"
                    out.write(f'{sep}    {json.dumps(self._file_entry(f))}')
                    first = False
                out.write("\n  ],\n")

                # Relationships
                out.write('  "relationships": [\n')
                out.write(f'    {json.dumps({"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": main_id, "relationshipType": "DESCRIBES"})}')
                for f in files:
                    fid = self._file_id(f["path"])
                    out.write(f',\n    {json.dumps({"spdxElementId": main_id, "relatedSpdxElement": fid, "relationshipType": "CONTAINS"})}')
                for did, _ in dep_entries:
                    out.write(f',\n    {json.dumps({"spdxElementId": main_id, "relatedSpdxElement": did, "relationshipType": "DEPENDS_ON"})}')
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
        """Return the SPDX 2.3 document as a dict.

        *max_files* caps the embedded file list (use write_streaming for
        complete output on large projects).
        """
        main_id = "SPDXRef-Package-Main"
        truncated = len(files) > max_files
        visible_files = files[:max_files] if truncated else files

        file_licenses = sorted({
            f["license"]
            for f in files  # use full list for accurate license summary
            if f.get("license") and f["license"] != "NOASSERTION"
        })

        doc: Dict[str, Any] = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": self.project_name,
            "documentNamespace": self.namespace,
            "creationInfo": self._creation_info(),
            "packages": [],
            "files": [],
            "relationships": [],
        }
        if truncated:
            doc["comment"] = (
                f"File list truncated to {max_files} of {len(files)} total files. "
                "Use the SPDX JSON output for the complete list."
            )

        doc["packages"].append(self._main_package(main_id, file_licenses))
        doc["relationships"].append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relatedSpdxElement": main_id,
            "relationshipType": "DESCRIBES",
        })

        for f in visible_files:
            fid = self._file_id(f["path"])
            doc["files"].append(self._file_entry(f))
            doc["relationships"].append({
                "spdxElementId": main_id,
                "relatedSpdxElement": fid,
                "relationshipType": "CONTAINS",
            })

        seen_dep_ids: set = set()
        for dep in dependencies:
            did = self._dep_id(dep)
            if did in seen_dep_ids:
                continue
            seen_dep_ids.add(did)
            doc["packages"].append(self._dep_package(did, dep))
            doc["relationships"].append({
                "spdxElementId": main_id,
                "relatedSpdxElement": did,
                "relationshipType": "DEPENDS_ON",
            })

        return doc
