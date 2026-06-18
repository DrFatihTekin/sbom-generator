"""CX-0158 compliant SPDX 3.0.1 JSON-LD generator for Catena-X.

CX-0158 mandates:
- SPDX 3.0 JSON-LD format, file ending .spdx.jsonld
- Only DEPENDS_ON relationships (all others are forbidden)
- Package-level components only — no file-level elements
- Propagation options 1-4 for n-tier supply chain merging

Out of scope for this generator (requires Catena-X infrastructure):
- Digital twin / AAS registration
- Dataspace connector (EDC) integration
- 1-up-1-down notification API
"""
import datetime
import hashlib
import json
import os
import uuid
from typing import Any, Dict, List, Optional

from sbom_extractor import __version__
from sbom_extractor.purl import generate_purl


class CatenaXGenerator:
    """Generate a CX-0158 compliant SPDX 3.0.1 JSON-LD SBOM.

    propagation_option controls the n-tier supply chain merging strategy:
      1 – anonymous nodes (most supply-chain detail, requires bilateral compliance check)
      2 – flat merge, structural info lost (default/recommended by CX-0158)
      3 – tier-n+1 preserved, deeper tiers flattened
      4 – fully flattened (maximum IP protection, minimum information)
    """

    ALLOWED_RELATIONSHIPS = {"dependsOn"}

    def __init__(
        self,
        project_name: str,
        project_version: str = "1.0.0",
        git_info: Optional[Dict[str, str]] = None,
        supplier: Optional[str] = None,
        reproducible: bool = False,
        propagation_option: int = 2,
    ) -> None:
        if propagation_option not in (1, 2, 3, 4):
            raise ValueError("propagation_option must be 1, 2, 3, or 4")
        self.project_name = project_name
        self.project_version = project_version
        self.supplier = supplier
        self.git_info = git_info or {}
        self.propagation_option = propagation_option

        if reproducible:
            self.creation_time = "1970-01-01T00:00:00Z"
            self.namespace = (
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
            self.namespace = f"https://spdx.org/spdxdocs/{project_name}-{uuid.uuid4()}"

    # ── Internal helpers ──────────────────────────────────────────────

    def _md5(self, value: str) -> str:
        return hashlib.md5(value.encode()).hexdigest()[:12]

    def _sha3(self, value: str) -> str:
        """SHA3-256 as required by CX-0158 Option 1 anonymous node IDs."""
        return hashlib.sha3_256(value.encode()).hexdigest()

    def _created_by(self) -> List[str]:
        creators = [f"urn:spdx:tool:sbom-generator-{__version__}"]
        if self.supplier:
            creators.append(f"urn:spdx:organization:{self.supplier.replace(' ', '-')}")
        return creators

    def _root_pkg(self, creation_id: str, main_id: str) -> Dict[str, Any]:
        pkg: Dict[str, Any] = {
            "type": "software_Package",
            "spdxId": main_id,
            "creationInfo": creation_id,
            "name": self.project_name,
            "software_packageVersion": self.project_version,
            "software_primaryPurpose": "application",
            "software_copyrightText": "NOASSERTION",
        }
        if self.supplier:
            pkg["supplier"] = f"Organization: {self.supplier}"
        if self.git_info.get("remote_url"):
            commit_ref = self.git_info.get("tag") or self.git_info.get("commit", "")
            remote = self.git_info["remote_url"]
            vcs_url = f"git+{remote}@{commit_ref}" if commit_ref else f"git+{remote}"
            pkg["externalIdentifiers"] = [{
                "type": "ExternalIdentifier",
                "externalIdentifierType": "other",
                "identifier": vcs_url,
                "comment": "VCS repository location",
            }]
        return pkg

    def _dep_pkg(self, dep: Dict[str, Any], creation_id: str, spdx_id: str) -> Dict[str, Any]:
        purl = generate_purl(dep)
        pkg: Dict[str, Any] = {
            "type": "software_Package",
            "spdxId": spdx_id,
            "creationInfo": creation_id,
            "name": dep["name"],
            "software_packageVersion": dep.get("version", "unknown"),
            "software_primaryPurpose": "library",
            "software_copyrightText": "NOASSERTION",
            "externalIdentifiers": [{
                "type": "ExternalIdentifier",
                "externalIdentifierType": "packageUrl",
                "identifier": purl,
            }],
        }
        if dep.get("license") and dep["license"] != "NOASSERTION":
            pkg["software_licenseDeclared"] = dep["license"]
        return pkg

    def _depends_on_rel(self, from_id: str, to_id: str, rel_id: str, creation_id: str) -> Dict[str, Any]:
        return {
            "type": "Relationship",
            "spdxId": rel_id,
            "creationInfo": creation_id,
            "from": from_id,
            "relationshipType": "dependsOn",
            "to": [to_id],
        }

    # ── Public API ────────────────────────────────────────────────────

    def generate(self, dependencies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build and return the CX-0158 SPDX 3.0 document as a dict."""
        creation_id = "_:creationinfo"
        main_id = f"_:pkg-{self._md5(self.project_name + self.project_version)}"

        graph: List[Dict[str, Any]] = []

        graph.append({
            "type": "CreationInfo",
            "spdxId": creation_id,
            "specVersion": "3.0.1",
            "created": self.creation_time,
            "createdBy": self._created_by(),
        })
        graph.append({
            "type": "SpdxDocument",
            "spdxId": self.namespace,
            "creationInfo": creation_id,
            "profileConformance": ["core", "software"],
            "rootElement": [main_id],
            "name": self.project_name,
            "comment": (
                f"CX-0158 compliant SBOM. "
                f"Propagation option: {self.propagation_option}. "
                "Infrastructure integration (EDC, AAS) required for Catena-X dataspace exchange."
            ),
        })
        graph.append(self._root_pkg(creation_id, main_id))

        seen: set = set()
        for dep in dependencies:
            key = f"{dep['name']}@{dep.get('version', '')}@{dep.get('type', '')}"
            dh = self._md5(key)
            did = f"_:pkg-{dh}"
            if did in seen:
                continue
            seen.add(did)

            if self.propagation_option == 1:
                # Option 1: wrap each dependency in an anonymous node
                # Anonymous node ID = "catena-x-sbom-option-1-" + SHA3-256(dep key)
                anon_id = f"catena-x-sbom-option-1-{self._sha3(key)}"
                anon_pkg: Dict[str, Any] = {
                    "type": "software_Package",
                    "spdxId": anon_id,
                    "creationInfo": creation_id,
                    "name": "Anonymous node",
                    "software_packageVersion": "unknown",
                    "software_primaryPurpose": "library",
                    "software_copyrightText": "NOASSERTION",
                }
                graph.append(anon_pkg)
                graph.append(self._depends_on_rel(main_id, anon_id, f"_:rel-anon-{dh}", creation_id))
                graph.append(self._dep_pkg(dep, creation_id, did))
                graph.append(self._depends_on_rel(anon_id, did, f"_:rel-dep-{dh}", creation_id))
            else:
                # Options 2, 3, 4: flat DEPENDS_ON from root to each dependency
                graph.append(self._dep_pkg(dep, creation_id, did))
                graph.append(self._depends_on_rel(main_id, did, f"_:rel-{dh}", creation_id))

        return {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": graph,
        }

    def write(self, dependencies: List[Dict[str, Any]], output_path: str) -> None:
        """Write CX-0158 compliant SPDX 3.0 JSON-LD to output_path atomically."""
        doc = self.generate(dependencies)
        tmp = output_path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(doc, f, indent=2)
            os.replace(tmp, output_path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
