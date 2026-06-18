import os
import re
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

DEFAULT_EXCLUDES: Set[str] = {
    '.git', '.github', '.svn', '.hg', 'node_modules',
    '__pycache__', '.venv', 'venv', 'env', '.pytest_cache', '.mypy_cache',
    'build', 'dist', 'out', 'target', '.idea', '.vscode',
}

# Capture everything after the tag up to end-of-line; we clean up comment
# syntax afterwards rather than splitting on | (which is valid in SPDX).
_SPDX_RE = re.compile(
    r"SPDX-License-Identifier:\s*([^\n\r]+)",
    re.IGNORECASE,
)

TEXT_EXTENSIONS: Set[str] = {
    '.c', '.h', '.cpp', '.hpp', '.cc', '.hh', '.cxx', '.hxx',
    '.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.rs', '.java',
    '.kt', '.swift', '.cs', '.sh', '.bash', '.pl', '.pm', '.rb',
    '.php', '.lua', '.s', '.S', '.asm',
    '.xml', '.yaml', '.yml', '.json', '.ini', '.cfg',
    '.md', '.rst', '.txt', '.toml',
}

_TEXT_BASENAMES: Set[str] = {'Makefile', 'Kconfig', 'Dockerfile', 'configure'}


def is_text_file(filepath: str) -> bool:
    ext = os.path.splitext(filepath)[1]
    if not ext:
        return os.path.basename(filepath) in _TEXT_BASENAMES
    return ext.lower() in TEXT_EXTENSIONS


def calculate_hashes(filepath: str, block_size: int = 65536) -> Tuple[str, str]:
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    try:
        with open(filepath, 'rb') as f:
            for block in iter(lambda: f.read(block_size), b''):
                sha256.update(block)
                sha1.update(block)
        return sha256.hexdigest(), sha1.hexdigest()
    except Exception:
        return "", ""


def extract_spdx_license(filepath: str) -> str:
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for _ in range(100):
                line = f.readline()
                if not line:
                    break
                m = _SPDX_RE.search(line)
                if m:
                    lic = m.group(1).strip()
                    # Remove trailing C/C++ block-comment closer "*/" and anything after
                    lic = re.sub(r'\s*\*/.*$', '', lic).strip()
                    # Strip stray trailing asterisks left by single-line comments
                    lic = lic.rstrip('* ').strip()
                    return lic if lic else "NOASSERTION"
    except Exception:
        pass
    return "NOASSERTION"


def process_file_batch(
    file_entries: List[Tuple[str, str, str]],
    calculate_hashes_flag: bool = True,
    on_progress: Optional[Callable[[int, int], None]] = None,
    max_workers: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Process a list of (abs_path, rel_path, name) entries in parallel.

    Shared by directory-scan mode and compilation-database mode.
    """
    if max_workers is None:
        max_workers = min(32, (os.cpu_count() or 4) * 2)

    total = len(file_entries)
    results: List[Dict[str, Any]] = []
    errors: List[str] = []
    completed = 0
    lock = threading.Lock()

    def _process(entry: Tuple[str, str, str]) -> Optional[Dict[str, Any]]:
        abs_path, rel_path, name = entry
        if not os.path.exists(abs_path):
            return None
        try:
            size = os.path.getsize(abs_path)
            is_src = is_text_file(abs_path)
            lic = extract_spdx_license(abs_path) if is_src else "NOASSERTION"
            sha256, sha1 = ("", "")
            if calculate_hashes_flag:
                sha256, sha1 = calculate_hashes(abs_path)
            return {
                "name": name,
                "path": rel_path,
                "size": size,
                "is_source": is_src,
                "license": lic,
                "sha256": sha256,
                "sha1": sha1,
            }
        except PermissionError:
            with lock:
                errors.append(f"Permission denied: {abs_path}")
            return None
        except Exception as exc:
            with lock:
                errors.append(f"Skipped {abs_path}: {exc}")
            return None

    if on_progress:
        on_progress(0, total)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_process, e): e for e in file_entries}
        for future in as_completed(futures):
            result = future.result()
            with lock:
                completed += 1
                if result:
                    results.append(result)
            if on_progress:
                on_progress(completed, total)

    if errors:
        import sys
        print(
            f"Warning: {len(errors)} file(s) skipped due to errors "
            f"(first: {errors[0]})",
            file=sys.stderr,
        )

    return results


class ProjectScanner:
    """Walk a project directory and collect per-file SBOM metadata."""

    def __init__(
        self,
        root_dir: str,
        exclude_dirs: Optional[Set[str]] = None,
        calculate_file_hashes: bool = True,
        max_workers: Optional[int] = None,
    ) -> None:
        self.root_dir = os.path.abspath(root_dir)
        self.exclude_dirs = exclude_dirs if exclude_dirs is not None else DEFAULT_EXCLUDES
        self.calculate_file_hashes = calculate_file_hashes
        self.max_workers = max_workers
        self.scanned_files: List[Dict[str, Any]] = []
        self.detected_licenses: Set[str] = set()

    def _collect_entries(self) -> List[Tuple[str, str, str]]:
        entries: List[Tuple[str, str, str]] = []
        for root, dirs, files in os.walk(self.root_dir, followlinks=False):
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs]
            for filename in files:
                filepath = os.path.join(root, filename)
                if os.path.islink(filepath):
                    continue
                rel = os.path.relpath(filepath, self.root_dir)
                entries.append((filepath, rel, filename))
        return entries

    def scan(
        self, on_progress: Optional[Callable[[int, int], None]] = None
    ) -> List[Dict[str, Any]]:
        entries = self._collect_entries()
        results = process_file_batch(
            entries,
            calculate_hashes_flag=self.calculate_file_hashes,
            on_progress=on_progress,
            max_workers=self.max_workers,
        )
        self.detected_licenses = {
            f["license"]
            for f in results
            if f.get("license") and f["license"] != "NOASSERTION"
        }
        self.scanned_files = results
        return results
