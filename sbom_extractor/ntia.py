"""NTIA minimum elements compliance check.

Reference: "The Minimum Elements For a Software Bill of Materials (SBOM)"
           NTIA, July 2021  — https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials
"""
from typing import Any, Dict, List, Optional


def check(
    project_name: str,
    project_version: str,
    dependencies: List[Dict[str, Any]],
    supplier: Optional[str],
    has_timestamp: bool = True,
) -> List[str]:
    """Return a list of human-readable NTIA compliance issues (empty = compliant)."""
    issues: List[str] = []

    # §2.2.1 — Supplier Name
    if not supplier:
        issues.append(
            "Supplier name not set (NTIA §2.2.1) — use --supplier to specify"
        )

    # §2.2.2 — Component Name  (always present in our tool)
    if not project_name:
        issues.append("Component name is empty (NTIA §2.2.2)")

    # §2.2.3 — Version of the Component
    if not project_version or project_version == "unknown":
        issues.append(
            "Component version is unspecified (NTIA §2.2.3) — use --project-version"
        )

    # §2.2.4 — Other Unique Identifiers
    # Every dependency should have a PURL (we always generate these).
    # Flag deps where *both* version and identifier are absent.
    missing_id = [
        d["name"]
        for d in dependencies
        if d.get("version", "unknown") == "unknown"
    ]
    if missing_id:
        issues.append(
            f"{len(missing_id)} dependenc{'y' if len(missing_id) == 1 else 'ies'} "
            f"have unknown version, making unique identification unreliable (NTIA §2.2.4)"
        )

    # §2.2.5 — Dependency Relationship: always present (CONTAINS / DEPENDS_ON).

    # §2.2.6 — Author of SBOM Data: always present (tool name in creationInfo).

    # §2.2.7 — Timestamp
    if not has_timestamp:
        issues.append("SBOM timestamp is absent (NTIA §2.2.7)")

    return issues
