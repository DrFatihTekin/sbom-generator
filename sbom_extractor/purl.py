import re
from typing import Any, Dict

# Maps the internal ecosystem label to the canonical PURL type
_ECOSYSTEM_TO_PURL: Dict[str, str] = {
    "pip": "pypi",
    "pypi": "pypi",
    "npm": "npm",
    "cargo": "cargo",
    "go": "golang",
    "golang": "golang",
    "maven": "maven",
    "gem": "gem",
    "nuget": "nuget",
    "conan": "conan",
}


def generate_purl(dep: Dict[str, Any]) -> str:
    """Return a Package URL string for a dependency dict."""
    raw = dep.get("type", "generic")
    # Strip suffixes like " (prod)" or " (dev)"
    raw = re.split(r"[\s(]", raw.strip())[0].lower()
    purl_type = _ECOSYSTEM_TO_PURL.get(raw, raw)

    name = dep["name"]
    version = dep.get("version", "unknown")

    if purl_type == "golang":
        return f"pkg:golang/{name}@{version}"

    if purl_type == "maven":
        if ":" in name:
            group, artifact = name.split(":", 1)
            return f"pkg:maven/{group}/{artifact}@{version}"
        return f"pkg:maven/{name}@{version}"

    if purl_type == "npm" and name.startswith("@"):
        # Encode the leading @ of scoped npm packages
        return f"pkg:npm/{name.replace('@', '%40', 1)}@{version}"

    return f"pkg:{purl_type}/{name}@{version}"
