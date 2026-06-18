import datetime
import hashlib
import uuid
from typing import Any, Dict, List, Optional

from sbom_extractor import __version__
from sbom_extractor.purl import generate_purl


class SPDXGenerator:
    """Generate an SPDX 2.3 JSON Software Bill of Materials."""

    def __init__(
        self,
        project_name: str,
        project_version: str = "1.0.0",
        namespace: Optional[str] = None,
        git_info: Optional[Dict[str, str]] = None,
    ) -> None:
        self.project_name = project_name
        self.project_version = project_version
        self.namespace = namespace or f"https://spdx.org/spdxdocs/{project_name}-{uuid.uuid4()}"
        self.creation_time = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        self.git_info = git_info or {}

    def _spdx_id(self, name: str) -> str:
        clean = "".join(c if c.isalnum() or c == "-" else "-" for c in name)
        return "-".join(filter(None, clean.split("-")))

    def _file_id(self, path: str) -> str:
        return f"SPDXRef-File-{hashlib.md5(path.encode()).hexdigest()[:16]}"

    def generate(
        self, files: List[Dict[str, Any]], dependencies: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        main_id = "SPDXRef-Package-Main"

        doc: Dict[str, Any] = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": self.project_name,
            "documentNamespace": self.namespace,
            "creationInfo": {
                "created": self.creation_time,
                "creators": [
                    f"Tool: sbom-extractor-{__version__}",
                    "Organization: NOASSERTION",
                ],
                "licenseListVersion": "3.22",
            },
            "packages": [],
            "files": [],
            "relationships": [],
        }

        # ── Main package ─────────────────────────────────────────────
        file_licenses = {
            f["license"]
            for f in files
            if f.get("license") and f["license"] != "NOASSERTION"
        }

        # Determine downloadLocation from git info
        download_location = "NOASSERTION"
        if self.git_info.get("remote_url"):
            commit_ref = self.git_info.get("tag") or self.git_info.get("commit", "")
            remote = self.git_info["remote_url"]
            download_location = f"git+{remote}@{commit_ref}" if commit_ref else f"git+{remote}"

        main_pkg: Dict[str, Any] = {
            "SPDXID": main_id,
            "name": self.project_name,
            "versionInfo": self.project_version,
            "downloadLocation": download_location,
            "filesAnalyzed": True,
            "licenseDeclared": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "licenseInfoFromFiles": sorted(file_licenses) if file_licenses else ["NOASSERTION"],
            "copyrightText": "NOASSERTION",
            "hasFiles": [],
        }

        if self.git_info.get("remote_url"):
            main_pkg["externalRefs"] = [
                {
                    "referenceCategory": "OTHER",
                    "referenceType": "vcs",
                    "referenceLocator": download_location,
                }
            ]
            if self.git_info.get("commit"):
                main_pkg["comment"] = (
                    f"Commit: {self.git_info['commit']}"
                    + (f"  Branch: {self.git_info['branch']}" if self.git_info.get("branch") else "")
                )

        doc["packages"].append(main_pkg)
        doc["relationships"].append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relatedSpdxElement": main_id,
            "relationshipType": "DESCRIBES",
        })

        # ── Source / built files ──────────────────────────────────────
        for f in files:
            fid = self._file_id(f["path"])
            if f["path"].endswith((".md", ".txt", ".rst")):
                ftypes = ["DOCUMENTATION"]
            elif f.get("is_source"):
                ftypes = ["SOURCE"]
            else:
                ftypes = ["BINARY"]

            spdx_file: Dict[str, Any] = {
                "SPDXID": fid,
                "fileName": f"./{f['path']}",
                "fileTypes": ftypes,
                "checksums": [],
                "licenseConcluded": f.get("license", "NOASSERTION"),
                "licenseInfoInFiles": [f.get("license", "NOASSERTION")],
                "copyrightText": "NOASSERTION",
            }
            if f.get("sha256"):
                spdx_file["checksums"].append({"algorithm": "SHA256", "checksumValue": f["sha256"]})
            if f.get("sha1"):
                spdx_file["checksums"].append({"algorithm": "SHA1", "checksumValue": f["sha1"]})

            doc["files"].append(spdx_file)
            main_pkg["hasFiles"].append(fid)
            doc["relationships"].append({
                "spdxElementId": main_id,
                "relatedSpdxElement": fid,
                "relationshipType": "CONTAINS",
            })

        # ── Third-party dependencies ──────────────────────────────────
        added_ids: set = set()
        for dep in dependencies:
            dep_id = f"SPDXRef-Package-{self._spdx_id(dep['name'])}-{self._spdx_id(dep.get('version', 'unknown'))}"
            if dep_id in added_ids:
                continue
            added_ids.add(dep_id)

            purl = generate_purl(dep)
            spdx_pkg: Dict[str, Any] = {
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
                    }
                ],
            }
            doc["packages"].append(spdx_pkg)
            doc["relationships"].append({
                "spdxElementId": main_id,
                "relatedSpdxElement": dep_id,
                "relationshipType": "DEPENDS_ON",
            })

        return doc
