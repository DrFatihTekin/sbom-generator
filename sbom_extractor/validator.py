"""Structural validation for generated SBOM documents."""
import re
from typing import Any, Dict, List

_SPDX_ID_RE = re.compile(r"^SPDXRef-[a-zA-Z0-9\.\-]+$")


def validate_spdx(doc: Dict[str, Any]) -> List[str]:
    """Return structural validation errors for an SPDX 2.3 JSON document."""
    errors: List[str] = []

    for field in ("spdxVersion", "dataLicense", "SPDXID", "name", "documentNamespace", "creationInfo"):
        if field not in doc:
            errors.append(f"Missing required top-level field: {field!r}")

    if doc.get("spdxVersion") != "SPDX-2.3":
        errors.append(f"Unexpected spdxVersion: {doc.get('spdxVersion')!r}")

    if doc.get("dataLicense") != "CC0-1.0":
        errors.append(f"dataLicense must be 'CC0-1.0', got {doc.get('dataLicense')!r}")

    # Collect all defined SPDX IDs
    all_ids: set = {doc.get("SPDXID", "")}
    for pkg in doc.get("packages", []):
        sid = pkg.get("SPDXID", "")
        if not _SPDX_ID_RE.match(sid):
            errors.append(f"Invalid SPDX ID format: {sid!r}")
        all_ids.add(sid)
        for field in ("name", "versionInfo", "downloadLocation", "filesAnalyzed"):
            if field not in pkg:
                errors.append(f"Package {sid!r} missing required field: {field!r}")

    for f in doc.get("files", []):
        sid = f.get("SPDXID", "")
        if not _SPDX_ID_RE.match(sid):
            errors.append(f"Invalid SPDX ID format: {sid!r}")
        all_ids.add(sid)

    # Validate relationship element references
    for rel in doc.get("relationships", []):
        src = rel.get("spdxElementId", "")
        dst = rel.get("relatedSpdxElement", "")
        if src not in all_ids:
            errors.append(f"Relationship src {src!r} references undefined SPDX ID")
        if dst not in all_ids:
            errors.append(f"Relationship dst {dst!r} references undefined SPDX ID")

    return errors


def validate_cyclonedx(doc: Dict[str, Any]) -> List[str]:
    """Return structural validation errors for a CycloneDX 1.5 JSON document."""
    errors: List[str] = []

    if doc.get("bomFormat") != "CycloneDX":
        errors.append(f"bomFormat must be 'CycloneDX', got {doc.get('bomFormat')!r}")

    if doc.get("specVersion") != "1.5":
        errors.append(f"specVersion must be '1.5', got {doc.get('specVersion')!r}")

    if "serialNumber" not in doc:
        errors.append("Missing required field: serialNumber")
    elif not doc["serialNumber"].startswith("urn:uuid:"):
        errors.append(f"serialNumber must be a urn:uuid URN, got {doc['serialNumber']!r}")

    # Collect bom-refs
    refs: set = set()
    root_ref = doc.get("metadata", {}).get("component", {}).get("bom-ref", "")
    if root_ref:
        refs.add(root_ref)

    for comp in doc.get("components", []):
        ref = comp.get("bom-ref", "")
        if ref:
            refs.add(ref)
        for field in ("type", "name"):
            if field not in comp:
                errors.append(
                    f"Component {comp.get('name', '?')!r} missing required field: {field!r}"
                )

    for dep in doc.get("dependencies", []):
        if dep.get("ref") not in refs:
            errors.append(f"Dependency references unknown bom-ref: {dep.get('ref')!r}")

    return errors
