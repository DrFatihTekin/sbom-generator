import datetime
import hashlib
import json
import os
import uuid
from typing import Any, Dict, List, Optional

from sbom_extractor import __version__
from sbom_extractor.purl import generate_purl

HTML_FILES_CAP = 5_000


class SPDX3Generator:
    """Generate an SPDX 3.0.1 JSON-LD Software Bill of Materials."""

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

        if reproducible:
            self.creation_time = "1970-01-01T00:00:00Z"
            self.namespace = namespace or (
                "https://spdx.org/spdxdocs/"
                + str(uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"sbom-generator/{project_name}/{project_version}",
                ))
            )
        else:
            self.creation_time = datetime.datetime.now(datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            self.namespace = namespace or f"https://spdx.org/spdxdocs/{project_name}-{uuid.uuid4()}"

    def _hash_id(self, value: str) -> str:
        return hashlib.md5(value.encode()).hexdigest()[:12]

    def _created_by(self) -> List[str]:
        creators = [f"urn:spdx:tool:sbom-generator-{__version__}"]
        if self.supplier:
            creators.append(f"urn:spdx:organization:{self.supplier.replace(' ', '-')}")
        return creators

    def _main_pkg(self, creation_id: str, main_id: str) -> Dict[str, Any]:
        pkg: Dict[str, Any] = {
            "type": "software_Package",
            "spdxId": main_id,
            "creationInfo": creation_id,
            "name": self.project_name,
            "software_packageVersion": self.project_version,
            "software_primaryPurpose": "application",
            "software_copyrightText": "NOASSERTION",
        }
        if self.git_info.get("remote_url"):
            commit_ref = self.git_info.get("tag") or self.git_info.get("commit", "")
            remote = self.git_info["remote_url"]
            vcs_url = f"git+{remote}@{commit_ref}" if commit_ref else f"git+{remote}"
            pkg["externalIdentifiers"] = [
                {
                    "type": "ExternalIdentifier",
                    "externalIdentifierType": "other",
                    "identifier": vcs_url,
                    "comment": "VCS repository location",
                }
            ]
        return pkg

    # ── Public API ────────────────────────────────────────────────────

    def write_streaming(
        self,
        files: List[Dict[str, Any]],
        dependencies: List[Dict[str, Any]],
        output_path: str,
    ) -> None:
        """Write a complete SPDX 3.0.1 JSON-LD document without building it in memory."""
        creation_id = "_:creationinfo"
        main_id = "_:package-main"

        tmp = output_path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as out:
                out.write('{\n')
                out.write('  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",\n')
                out.write('  "@graph": [\n')

                # CreationInfo
                creation_info = {
                    "type": "CreationInfo",
                    "spdxId": creation_id,
                    "specVersion": "3.0.1",
                    "created": self.creation_time,
                    "createdBy": self._created_by(),
                }
                out.write(f'    {json.dumps(creation_info)}')

                # SpdxDocument
                spdx_doc = {
                    "type": "SpdxDocument",
                    "spdxId": self.namespace,
                    "creationInfo": creation_id,
                    "profileConformance": ["core", "software", "simpleLicensing"],
                    "rootElement": [main_id],
                    "name": self.project_name,
                }
                out.write(f',\n    {json.dumps(spdx_doc)}')

                # Main package + document-describes relationship
                out.write(f',\n    {json.dumps(self._main_pkg(creation_id, main_id))}')
                out.write(f',\n    {json.dumps({"type": "Relationship", "spdxId": f"_:rel-doc-{self._hash_id(self.project_name)}", "creationInfo": creation_id, "from": self.namespace, "relationshipType": "describes", "to": [main_id]})}')

                # License expression dedup: write each unique license node once
                seen_lics: Dict[str, str] = {}

                def _lic_id(lic_str: str) -> str:
                    if lic_str in seen_lics:
                        return seen_lics[lic_str]
                    lid = f"_:lic-{self._hash_id(lic_str)}"
                    out.write(f',\n    {json.dumps({"type": "simplelicensing_LicenseExpression", "spdxId": lid, "creationInfo": creation_id, "simplelicensing_licenseExpression": lic_str})}')
                    seen_lics[lic_str] = lid
                    return lid

                # Files
                for f in files:
                    ph = self._hash_id(f["path"])
                    fid = f"_:file-{ph}"
                    spdx_file: Dict[str, Any] = {
                        "type": "software_File",
                        "spdxId": fid,
                        "creationInfo": creation_id,
                        "name": f["path"],
                        "software_copyrightText": "NOASSERTION",
                    }
                    hashes = []
                    if f.get("sha256"):
                        hashes.append({"type": "Hash", "algorithm": "sha256", "hashValue": f["sha256"]})
                    if f.get("sha1"):
                        hashes.append({"type": "Hash", "algorithm": "sha1", "hashValue": f["sha1"]})
                    if hashes:
                        spdx_file["verifiedUsing"] = hashes
                    out.write(f',\n    {json.dumps(spdx_file)}')
                    out.write(f',\n    {json.dumps({"type": "Relationship", "spdxId": f"_:rel-contains-{ph}", "creationInfo": creation_id, "from": main_id, "relationshipType": "contains", "to": [fid]})}')
                    if f.get("license") and f["license"] != "NOASSERTION":
                        lid = _lic_id(f["license"])
                        out.write(f',\n    {json.dumps({"type": "Relationship", "spdxId": f"_:rel-lic-file-{ph}", "creationInfo": creation_id, "from": fid, "relationshipType": "hasDeclaredLicense", "to": [lid]})}')

                # Dependencies
                seen_deps: set = set()
                for dep in dependencies:
                    dh = self._hash_id(f"{dep['name']}@{dep.get('version', '')}")
                    did = f"_:package-{dh}"
                    if did in seen_deps:
                        continue
                    seen_deps.add(did)
                    purl = generate_purl(dep)
                    spdx_pkg: Dict[str, Any] = {
                        "type": "software_Package",
                        "spdxId": did,
                        "creationInfo": creation_id,
                        "name": dep["name"],
                        "software_packageVersion": dep.get("version", "unknown"),
                        "software_primaryPurpose": "library",
                        "software_copyrightText": "NOASSERTION",
                        "externalIdentifiers": [
                            {
                                "type": "ExternalIdentifier",
                                "externalIdentifierType": "packageUrl",
                                "identifier": purl,
                            }
                        ],
                    }
                    out.write(f',\n    {json.dumps(spdx_pkg)}')
                    out.write(f',\n    {json.dumps({"type": "Relationship", "spdxId": f"_:rel-depends-{dh}", "creationInfo": creation_id, "from": main_id, "relationshipType": "dependsOn", "to": [did]})}')
                    if dep.get("license") and dep["license"] != "NOASSERTION":
                        lid = _lic_id(dep["license"])
                        out.write(f',\n    {json.dumps({"type": "Relationship", "spdxId": f"_:rel-lic-dep-{dh}", "creationInfo": creation_id, "from": did, "relationshipType": "hasDeclaredLicense", "to": [lid]})}')

                out.write('\n  ]\n}\n')

            os.replace(tmp, output_path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def generate(
        self, files: List[Dict[str, Any]], dependencies: List[Dict[str, Any]],
        max_files: int = HTML_FILES_CAP,
    ) -> Dict[str, Any]:
        creation_id = "_:creationinfo"
        main_id = "_:package-main"
        truncated = len(files) > max_files
        visible_files = files[:max_files] if truncated else files

        doc: Dict[str, Any] = {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": [],
        }

        # ── CreationInfo ──────────────────────────────────────────────
        doc["@graph"].append({
            "type": "CreationInfo",
            "spdxId": creation_id,
            "specVersion": "3.0.1",
            "created": self.creation_time,
            "createdBy": self._created_by(),
        })

        # ── SpdxDocument ──────────────────────────────────────────────
        spdx_doc: Dict[str, Any] = {
            "type": "SpdxDocument",
            "spdxId": self.namespace,
            "creationInfo": creation_id,
            "profileConformance": ["core", "software", "simpleLicensing"],
            "rootElement": [main_id],
            "name": self.project_name,
        }
        if truncated:
            spdx_doc["comment"] = (
                f"File list truncated to {max_files} of {len(files)} total files. "
                "Use the SPDX 3 JSON output for the complete list."
            )
        doc["@graph"].append(spdx_doc)

        # ── Main package ──────────────────────────────────────────────
        doc["@graph"].append(self._main_pkg(creation_id, main_id))

        # ── DOCUMENT describes MAIN ───────────────────────────────────
        doc["@graph"].append({
            "type": "Relationship",
            "spdxId": f"_:rel-doc-{self._hash_id(self.project_name)}",
            "creationInfo": creation_id,
            "from": self.namespace,
            "relationshipType": "describes",
            "to": [main_id],
        })

        # ── License expression cache ──────────────────────────────────
        lic_cache: Dict[str, str] = {}

        def _lic_id(lic_str: str) -> str:
            if lic_str in lic_cache:
                return lic_cache[lic_str]
            lid = f"_:lic-{self._hash_id(lic_str)}"
            doc["@graph"].append({
                "type": "simplelicensing_LicenseExpression",
                "spdxId": lid,
                "creationInfo": creation_id,
                "simplelicensing_licenseExpression": lic_str,
            })
            lic_cache[lic_str] = lid
            return lid

        # ── Files ─────────────────────────────────────────────────────
        for f in visible_files:
            ph = self._hash_id(f["path"])
            fid = f"_:file-{ph}"

            spdx_file: Dict[str, Any] = {
                "type": "software_File",
                "spdxId": fid,
                "creationInfo": creation_id,
                "name": f["path"],
                "software_copyrightText": "NOASSERTION",
            }
            hashes = []
            if f.get("sha256"):
                hashes.append({"type": "Hash", "algorithm": "sha256", "hashValue": f["sha256"]})
            if f.get("sha1"):
                hashes.append({"type": "Hash", "algorithm": "sha1", "hashValue": f["sha1"]})
            if hashes:
                spdx_file["verifiedUsing"] = hashes

            doc["@graph"].append(spdx_file)

            doc["@graph"].append({
                "type": "Relationship",
                "spdxId": f"_:rel-contains-{ph}",
                "creationInfo": creation_id,
                "from": main_id,
                "relationshipType": "contains",
                "to": [fid],
            })

            if f.get("license") and f["license"] != "NOASSERTION":
                doc["@graph"].append({
                    "type": "Relationship",
                    "spdxId": f"_:rel-lic-file-{ph}",
                    "creationInfo": creation_id,
                    "from": fid,
                    "relationshipType": "hasDeclaredLicense",
                    "to": [_lic_id(f["license"])],
                })

        # ── Dependencies ──────────────────────────────────────────────
        added: set = set()
        for dep in dependencies:
            dh = self._hash_id(f"{dep['name']}@{dep.get('version', '')}")
            did = f"_:package-{dh}"
            if did in added:
                continue
            added.add(did)

            purl = generate_purl(dep)
            spdx_pkg: Dict[str, Any] = {
                "type": "software_Package",
                "spdxId": did,
                "creationInfo": creation_id,
                "name": dep["name"],
                "software_packageVersion": dep.get("version", "unknown"),
                "software_primaryPurpose": "library",
                "software_copyrightText": "NOASSERTION",
                "externalIdentifiers": [
                    {
                        "type": "ExternalIdentifier",
                        "externalIdentifierType": "packageUrl",
                        "identifier": purl,
                    }
                ],
            }
            doc["@graph"].append(spdx_pkg)

            doc["@graph"].append({
                "type": "Relationship",
                "spdxId": f"_:rel-depends-{dh}",
                "creationInfo": creation_id,
                "from": main_id,
                "relationshipType": "dependsOn",
                "to": [did],
            })

            if dep.get("license") and dep["license"] != "NOASSERTION":
                doc["@graph"].append({
                    "type": "Relationship",
                    "spdxId": f"_:rel-lic-dep-{dh}",
                    "creationInfo": creation_id,
                    "from": did,
                    "relationshipType": "hasDeclaredLicense",
                    "to": [_lic_id(dep["license"])],
                })

        return doc
