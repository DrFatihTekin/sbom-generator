import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional


class ManifestParser:
    """Parse package-manager manifests and lock files to extract third-party dependencies."""

    def __init__(self, root_dir: str) -> None:
        self.root_dir = os.path.abspath(root_dir)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def scan_manifests(self) -> List[Dict[str, Any]]:
        """Scan the project root for dependency manifests and lock files.

        Lock files take precedence over loose manifests when both exist,
        because they record exact pinned versions.
        """
        deps: List[Dict[str, Any]] = []
        seen: set = set()  # (name_lower, type) dedup key

        def add(new: List[Dict[str, Any]]) -> None:
            for d in new:
                key = (d["name"].lower(), d["type"])
                if key not in seen:
                    seen.add(key)
                    deps.append(d)

        root = self.root_dir

        # ── Python ────────────────────────────────────────────────────
        if os.path.exists(os.path.join(root, "poetry.lock")):
            add(self.parse_poetry_lock(os.path.join(root, "poetry.lock")))
        elif os.path.exists(os.path.join(root, "requirements.txt")):
            add(self.parse_requirements_txt(os.path.join(root, "requirements.txt")))

        if os.path.exists(os.path.join(root, "pyproject.toml")):
            add(self.parse_pyproject_toml(os.path.join(root, "pyproject.toml")))

        # ── Node.js ───────────────────────────────────────────────────
        if os.path.exists(os.path.join(root, "package-lock.json")):
            add(self.parse_package_lock_json(os.path.join(root, "package-lock.json")))
        elif os.path.exists(os.path.join(root, "package.json")):
            add(self.parse_package_json(os.path.join(root, "package.json")))

        # ── Rust ──────────────────────────────────────────────────────
        if os.path.exists(os.path.join(root, "Cargo.lock")):
            add(self.parse_cargo_lock(os.path.join(root, "Cargo.lock")))
        elif os.path.exists(os.path.join(root, "Cargo.toml")):
            add(self.parse_cargo_toml(os.path.join(root, "Cargo.toml")))

        # ── Go ────────────────────────────────────────────────────────
        if os.path.exists(os.path.join(root, "go.sum")):
            add(self.parse_go_sum(os.path.join(root, "go.sum")))
        elif os.path.exists(os.path.join(root, "go.mod")):
            add(self.parse_go_mod(os.path.join(root, "go.mod")))

        # ── Java / Maven ──────────────────────────────────────────────
        if os.path.exists(os.path.join(root, "pom.xml")):
            add(self.parse_pom_xml(os.path.join(root, "pom.xml")))

        # ── Java / Gradle (prefer lock file) ─────────────────────────
        if os.path.exists(os.path.join(root, "gradle.lockfile")):
            add(self.parse_gradle_lockfile(os.path.join(root, "gradle.lockfile")))
        elif os.path.exists(os.path.join(root, "build.gradle")):
            add(self.parse_build_gradle(os.path.join(root, "build.gradle")))
        elif os.path.exists(os.path.join(root, "build.gradle.kts")):
            add(self.parse_build_gradle(os.path.join(root, "build.gradle.kts")))

        return deps

    # ------------------------------------------------------------------
    # Python
    # ------------------------------------------------------------------

    def parse_requirements_txt(self, filepath: str) -> List[Dict[str, Any]]:
        deps: List[Dict[str, Any]] = []
        pattern = re.compile(
            r"^\s*([a-zA-Z0-9_\-\[\]\.]+)\s*(?:==|>=|<=|>|<|~=|!=)\s*([a-zA-Z0-9\.\-\+]+)"
        )
        try:
            with open(filepath, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    m = pattern.match(line)
                    if m:
                        name, version = m.groups()
                    else:
                        name = re.split(r"[><=#\s]", line)[0].strip()
                        version = "unknown"
                    if name:
                        deps.append(self._dep(name, version, "pypi", filepath))
        except Exception as e:
            print(f"Warning: could not parse {filepath}: {e}", file=sys.stderr)
        return deps

    def parse_poetry_lock(self, filepath: str) -> List[Dict[str, Any]]:
        deps: List[Dict[str, Any]] = []
        current: Dict[str, Any] = {}
        in_package = False
        try:
            with open(filepath, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line == "[[package]]":
                        if current.get("name"):
                            deps.append(current)
                        current = {}
                        in_package = True
                    elif line.startswith("[") and not line.startswith("[["):
                        in_package = False
                    elif in_package:
                        if line.startswith("name = "):
                            current["name"] = line.split('"')[1]
                        elif line.startswith("version = "):
                            current["version"] = line.split('"')[1]
                        elif line.startswith("optional = "):
                            current["optional"] = "true" in line.lower()
            if current.get("name"):
                deps.append(current)
        except Exception as e:
            print(f"Warning: could not parse {filepath}: {e}", file=sys.stderr)

        return [
            self._dep(d["name"], d.get("version", "unknown"), "pypi", filepath)
            for d in deps
            if not d.get("optional", False)
        ]

    def parse_pyproject_toml(self, filepath: str) -> List[Dict[str, Any]]:
        """Parse PEP 621 [project.dependencies] and Poetry [tool.poetry.dependencies]."""
        deps: List[Dict[str, Any]] = []
        section = ""
        try:
            with open(filepath, encoding="utf-8") as f:
                lines = f.readlines()

            i = 0
            while i < len(lines):
                line = lines[i].rstrip()
                stripped = line.strip()
                i += 1

                if not stripped or stripped.startswith("#"):
                    continue

                # Section header
                if stripped.startswith("[") and not stripped.startswith("[["):
                    section = stripped.strip("[]").strip()
                    continue

                # PEP 621: dependencies = ["pkg>=ver", ...]
                if section == "project" and re.match(r"dependencies\s*=\s*\[", stripped):
                    # Collect until closing ]
                    array_str = stripped[stripped.index("[") + 1:]
                    while "]" not in array_str and i < len(lines):
                        array_str += lines[i]
                        i += 1
                    array_str = array_str[: array_str.index("]")]
                    for item in array_str.split(","):
                        item = item.strip().strip('"\'')
                        if item and not item.startswith("#"):
                            dep = self._parse_pep621_dep(item, filepath)
                            if dep:
                                deps.append(dep)
                    continue

                # Poetry: name = "^version" or name = { version = "^x", ... }
                if section in (
                    "tool.poetry.dependencies",
                    "tool.poetry.dev-dependencies",
                    "tool.poetry.group.dev.dependencies",
                ):
                    if "=" in stripped and not stripped.startswith("["):
                        name = stripped.split("=")[0].strip()
                        if name.lower() == "python":
                            continue
                        rest = stripped.split("=", 1)[1].strip()
                        version = "unknown"
                        if rest.startswith(('"', "'")):
                            version = re.sub(r"^[\^~>=<!]+", "", rest.strip("\"'"))
                        elif rest.startswith("{"):
                            vm = re.search(r'version\s*=\s*["\']([^"\']+)["\']', rest)
                            if vm:
                                version = re.sub(r"^[\^~>=<!]+", "", vm.group(1))
                        deps.append(self._dep(name, version or "unknown", "pypi", filepath))
        except Exception as e:
            print(f"Warning: could not parse {filepath}: {e}", file=sys.stderr)
        return deps

    def _parse_pep621_dep(self, dep_str: str, source: str) -> Optional[Dict[str, Any]]:
        m = re.match(r"^([a-zA-Z0-9_\-\.]+)", dep_str.strip())
        if not m:
            return None
        name = m.group(1)
        vm = re.search(r"[>=<!~^]+\s*([a-zA-Z0-9\.\-\+]+)", dep_str)
        version = vm.group(1) if vm else "unknown"
        return self._dep(name, version, "pypi", source)

    # ------------------------------------------------------------------
    # Node.js
    # ------------------------------------------------------------------

    def parse_package_json(self, filepath: str) -> List[Dict[str, Any]]:
        deps: List[Dict[str, Any]] = []
        try:
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)

            def _add(dep_dict: Optional[Dict], scope: str) -> None:
                if not dep_dict:
                    return
                for name, ver_spec in dep_dict.items():
                    version = ver_spec.lstrip("^~>=< ") if isinstance(ver_spec, str) else "unknown"
                    deps.append({
                        **self._dep(name, version or "unknown", "npm", filepath),
                        "scope": scope,
                    })

            _add(data.get("dependencies"), "prod")
            _add(data.get("devDependencies"), "dev")
        except Exception as e:
            print(f"Warning: could not parse {filepath}: {e}", file=sys.stderr)
        return deps

    def parse_package_lock_json(self, filepath: str) -> List[Dict[str, Any]]:
        """Parse npm package-lock.json (lockfileVersion 2 or 3)."""
        deps: List[Dict[str, Any]] = []
        try:
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)

            packages = data.get("packages", {})
            for pkg_path, pkg_data in packages.items():
                if not pkg_path:  # root entry
                    continue
                # Strip "node_modules/" prefix(es)
                name = pkg_path
                if name.startswith("node_modules/"):
                    name = name[len("node_modules/"):]
                if "/node_modules/" in name:
                    name = name.rsplit("/node_modules/", 1)[-1]

                version = pkg_data.get("version", "unknown")
                license_str = pkg_data.get("license", "NOASSERTION") or "NOASSERTION"
                scope = "dev" if pkg_data.get("dev") else "prod"
                deps.append({
                    **self._dep(name, version, "npm", filepath),
                    "license": license_str,
                    "scope": scope,
                    "source": "lock",
                })
        except Exception as e:
            print(f"Warning: could not parse {filepath}: {e}", file=sys.stderr)
        return deps

    # ------------------------------------------------------------------
    # Rust
    # ------------------------------------------------------------------

    def parse_cargo_toml(self, filepath: str) -> List[Dict[str, Any]]:
        deps: List[Dict[str, Any]] = []
        in_deps = False
        dep_pattern = re.compile(
            r"^\s*([a-zA-Z0-9_\-]+)\s*=\s*(?:\"([^\"]+)\"|(\{[^}]+\}))"
        )
        try:
            with open(filepath, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("[dependencies]") or line.startswith("[dev-dependencies]"):
                        in_deps = True
                        continue
                    if line.startswith("[") and "dependencies" not in line:
                        in_deps = False
                        continue
                    if in_deps:
                        m = dep_pattern.match(line)
                        if m:
                            name, plain_ver, table_ver = m.groups()
                            version = plain_ver or "unknown"
                            if table_ver:
                                vm = re.search(r'version\s*=\s*"([^"]+)"', table_ver)
                                version = vm.group(1) if vm else "unknown"
                            deps.append(self._dep(name, version, "cargo", filepath))
        except Exception as e:
            print(f"Warning: could not parse {filepath}: {e}", file=sys.stderr)
        return deps

    def parse_cargo_lock(self, filepath: str) -> List[Dict[str, Any]]:
        """Parse Cargo.lock for exact pinned dependency versions."""
        packages: List[Dict[str, Any]] = []
        current: Dict[str, Any] = {}
        try:
            with open(filepath, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line == "[[package]]":
                        if current.get("name"):
                            packages.append(current)
                        current = {}
                    elif line.startswith("name = "):
                        current["name"] = line.split('"')[1]
                    elif line.startswith("version = "):
                        current["version"] = line.split('"')[1]
                    elif line.startswith("source = "):
                        current["source"] = line.split('"')[1]
            if current.get("name"):
                packages.append(current)
        except Exception as e:
            print(f"Warning: could not parse {filepath}: {e}", file=sys.stderr)

        return [
            {**self._dep(p["name"], p.get("version", "unknown"), "cargo", filepath), "source": "lock"}
            for p in packages
            if p.get("source")  # source field absent = workspace member (not a dep)
        ]

    # ------------------------------------------------------------------
    # Go
    # ------------------------------------------------------------------

    def parse_go_mod(self, filepath: str) -> List[Dict[str, Any]]:
        deps: List[Dict[str, Any]] = []
        in_require = False
        single = re.compile(r"^\s*require\s+(\S+)\s+(\S+)")
        block = re.compile(r"^\s*(\S+)\s+(\S+)")
        try:
            with open(filepath, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("//"):
                        continue
                    if line.startswith("require ("):
                        in_require = True
                        continue
                    if line == ")" and in_require:
                        in_require = False
                        continue
                    if in_require:
                        m = block.match(line)
                        if m:
                            name, ver = m.groups()
                            deps.append(self._dep(name, ver.lstrip("v"), "golang", filepath))
                    else:
                        m = single.match(line)
                        if m:
                            name, ver = m.groups()
                            deps.append(self._dep(name, ver.lstrip("v"), "golang", filepath))
        except Exception as e:
            print(f"Warning: could not parse {filepath}: {e}", file=sys.stderr)
        return deps

    def parse_go_sum(self, filepath: str) -> List[Dict[str, Any]]:
        """Parse go.sum for the full set of pinned module versions."""
        seen: Dict[str, str] = {}
        try:
            with open(filepath, encoding="utf-8") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    module, version = parts[0], parts[1]
                    # Skip go.mod-only hash lines
                    if version.endswith("/go.mod"):
                        continue
                    version = version.lstrip("v")
                    if module not in seen:
                        seen[module] = version
        except Exception as e:
            print(f"Warning: could not parse {filepath}: {e}", file=sys.stderr)

        return [
            {**self._dep(name, ver, "golang", filepath), "source": "lock"}
            for name, ver in seen.items()
        ]

    # ------------------------------------------------------------------
    # Java / Maven
    # ------------------------------------------------------------------

    def parse_pom_xml(self, filepath: str) -> List[Dict[str, Any]]:
        """Parse Maven pom.xml for declared dependencies."""
        deps: List[Dict[str, Any]] = []
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()

            # Strip namespace so tag lookups are uniform
            ns = ""
            if root.tag.startswith("{"):
                ns = root.tag.split("}")[0] + "}"

            for dep_elem in root.iter(f"{ns}dependency"):
                group_id = (dep_elem.findtext(f"{ns}groupId") or "").strip()
                artifact_id = (dep_elem.findtext(f"{ns}artifactId") or "").strip()
                version = (dep_elem.findtext(f"{ns}version") or "unknown").strip()
                scope = (dep_elem.findtext(f"{ns}scope") or "compile").strip()

                if not group_id or not artifact_id:
                    continue
                # Version properties like ${spring.version} cannot be resolved statically
                if version.startswith("${"):
                    version = "unknown"

                d = self._dep(f"{group_id}:{artifact_id}", version, "maven", filepath)
                d["scope"] = scope
                deps.append(d)
        except Exception as e:
            print(f"Warning: could not parse {filepath}: {e}", file=sys.stderr)
        return deps

    # ------------------------------------------------------------------
    # Java / Gradle
    # ------------------------------------------------------------------

    # Configuration names that indicate a dependency declaration
    _GRADLE_CONFIGS = (
        "implementation", "api", "compileOnly", "runtimeOnly",
        "testImplementation", "testRuntimeOnly", "testCompileOnly",
        "annotationProcessor", "kapt", "ksp",
        "compile", "runtime", "testCompile",  # legacy
        "classpath",
    )

    def parse_build_gradle(self, filepath: str) -> List[Dict[str, Any]]:
        """Parse Gradle build files (Groovy or Kotlin DSL) for dependency declarations."""
        deps: List[Dict[str, Any]] = []

        configs = "|".join(self._GRADLE_CONFIGS)

        # String notation: impl 'group:artifact:version' or impl("group:artifact:version")
        string_re = re.compile(
            rf'(?:{configs})\s*\(?["\']'
            r'([a-zA-Z0-9_\-\.]+):([a-zA-Z0-9_\-\.]+):([a-zA-Z0-9_\-\.\+]+)'
            r'["\']'
        )
        # Map notation: group: 'x', name: 'y', version: 'z'
        map_re = re.compile(
            r"group:\s*[\"']([a-zA-Z0-9_\-\.]+)[\"'],\s*"
            r"name:\s*[\"']([a-zA-Z0-9_\-\.]+)[\"'],\s*"
            r"version:\s*[\"']([a-zA-Z0-9_\-\.\+]+)[\"']"
        )

        try:
            content = open(filepath, encoding="utf-8").read()
            seen: set = set()
            for m in string_re.finditer(content):
                group_id, artifact_id, version = m.groups()
                key = (group_id, artifact_id)
                if key not in seen:
                    seen.add(key)
                    deps.append(self._dep(f"{group_id}:{artifact_id}", version, "maven", filepath))
            for m in map_re.finditer(content):
                group_id, artifact_id, version = m.groups()
                key = (group_id, artifact_id)
                if key not in seen:
                    seen.add(key)
                    deps.append(self._dep(f"{group_id}:{artifact_id}", version, "maven", filepath))
        except Exception as e:
            print(f"Warning: could not parse {filepath}: {e}", file=sys.stderr)
        return deps

    def parse_gradle_lockfile(self, filepath: str) -> List[Dict[str, Any]]:
        """Parse a Gradle dependency lock file for exact pinned versions."""
        deps: List[Dict[str, Any]] = []
        try:
            with open(filepath, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("empty="):
                        continue
                    # Format: group:artifact:version=configuration1,configuration2
                    coords = line.split("=")[0].strip().split(":")
                    if len(coords) >= 3:
                        group_id, artifact_id, version = coords[0], coords[1], coords[2]
                        d = self._dep(f"{group_id}:{artifact_id}", version, "maven", filepath)
                        d["source"] = "lock"
                        deps.append(d)
        except Exception as e:
            print(f"Warning: could not parse {filepath}: {e}", file=sys.stderr)
        return deps

    # ------------------------------------------------------------------
    # Internal helper
    # ------------------------------------------------------------------

    @staticmethod
    def _dep(name: str, version: str, dep_type: str, path: str) -> Dict[str, Any]:
        return {
            "name": name,
            "version": version,
            "type": dep_type,
            "license": "NOASSERTION",
            "path": os.path.basename(path),
        }
