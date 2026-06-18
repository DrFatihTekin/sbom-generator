"""Best-effort CPE 2.3 generation for package dependencies.

CPE vendor/product names are not standardised across ecosystems — values
produced here match common NVD conventions but will not be perfect for every
package.  Consumers should treat these as hints for vulnerability matching
rather than authoritative identifiers.
"""
import re
from typing import Any, Dict


def _san(s: str) -> str:
    """Sanitise a string for CPE: keep only [a-zA-Z0-9\\-_.], collapse runs."""
    s = re.sub(r"[^a-zA-Z0-9\-_\.]", "_", s)
    s = re.sub(r"_+", "_", s).strip("_.-")
    return s or "unknown"


def generate_cpe(dep: Dict[str, Any]) -> str:
    """Return a CPE 2.3 formatted-string for *dep*.

    Format: ``cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*``
    """
    raw_type = dep.get("type", "")
    name = dep.get("name", "unknown").lower()
    version = dep.get("version", "*")

    if raw_type == "maven" and ":" in name:
        group, artifact = name.split(":", 1)
        vendor = _san(group)
        product = _san(artifact)

    elif raw_type == "golang":
        # e.g. github.com/user/repo → user : repo
        parts = [p for p in name.split("/") if p]
        product = _san(parts[-1]) if parts else "unknown"
        vendor = _san(parts[-2]) if len(parts) >= 2 else product

    elif raw_type == "npm":
        # Strip URL-encoded @ prefix from scoped packages
        clean = re.sub(r"^%40[^/]+/", "", name)
        product = _san(clean.split("/")[-1])
        vendor = product

    else:
        product = _san(name.split("/")[-1])
        vendor = product

    cpe_ver = _san(version) if version not in ("unknown", "*", "") else "*"
    return f"cpe:2.3:a:{vendor}:{product}:{cpe_ver}:*:*:*:*:*:*:*"
