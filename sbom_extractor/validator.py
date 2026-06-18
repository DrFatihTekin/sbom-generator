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


def validate_catena_x(doc: Dict[str, Any]) -> List[str]:
    """Return CX-0158 compliance errors for a Catena-X SPDX 3.0 JSON-LD document."""
    errors: List[str] = []

    if doc.get("@context") != "https://spdx.org/rdf/3.0.1/spdx-context.jsonld":
        errors.append(
            f"@context must be the SPDX 3.0.1 JSON-LD context, got {doc.get('@context')!r}"
        )

    graph = doc.get("@graph", [])
    if not graph:
        errors.append("@graph is empty or missing")
        return errors

    # Check CreationInfo and SpdxDocument exist
    types = {e.get("type") for e in graph}
    if "CreationInfo" not in types:
        errors.append("Missing CreationInfo element")
    if "SpdxDocument" not in types:
        errors.append("Missing SpdxDocument element")

    # Check specVersion
    for elem in graph:
        if elem.get("type") == "CreationInfo":
            if elem.get("specVersion") != "3.0.1":
                errors.append(f"specVersion must be '3.0.1', got {elem.get('specVersion')!r}")

    # Collect all spdxIds for reference validation
    all_ids = {e["spdxId"] for e in graph if "spdxId" in e}

    # Validate relationships: only DEPENDS_ON is allowed per CX-0158 §3.2.3
    for elem in graph:
        if elem.get("type") == "Relationship":
            rel_type = elem.get("relationshipType", "")
            if rel_type != "dependsOn":
                errors.append(
                    f"CX-0158 §3.2.3: only 'dependsOn' relationships allowed, "
                    f"found {rel_type!r} (spdxId: {elem.get('spdxId', '?')})"
                )
            # Validate from/to references
            from_id = elem.get("from", "")
            if from_id not in all_ids:
                errors.append(f"Relationship 'from' references unknown spdxId: {from_id!r}")
            for to_id in elem.get("to", []):
                if to_id not in all_ids:
                    errors.append(f"Relationship 'to' references unknown spdxId: {to_id!r}")

    # Check no file-level elements (CX-0158 is package-only)
    for elem in graph:
        if elem.get("type") == "software_File":
            errors.append(
                f"CX-0158 does not allow file-level elements "
                f"(found software_File: {elem.get('name', '?')})"
            )

    # Validate packages have required fields
    for elem in graph:
        if elem.get("type") == "software_Package":
            for field in ("name", "software_packageVersion"):
                if field not in elem:
                    errors.append(
                        f"Package {elem.get('spdxId', '?')!r} missing required field: {field!r}"
                    )

    # Check rootElement is defined in SpdxDocument and references a known spdxId
    for elem in graph:
        if elem.get("type") == "SpdxDocument":
            root_elements = elem.get("rootElement", [])
            if not root_elements:
                errors.append("SpdxDocument.rootElement is missing or empty")
            for rid in root_elements:
                if rid not in all_ids:
                    errors.append(f"rootElement {rid!r} references unknown spdxId")

    return errors
