import subprocess
from typing import Dict


def get_git_metadata(path: str) -> Dict[str, str]:
    """Extract VCS metadata from a git repository rooted at path."""
    info: Dict[str, str] = {}
    try:
        def _run(*cmd: str) -> str:
            r = subprocess.run(
                list(cmd), cwd=path, capture_output=True, text=True, timeout=5
            )
            return r.stdout.strip() if r.returncode == 0 else ""

        commit = _run("git", "rev-parse", "HEAD")
        if not commit:
            return info

        info["commit"] = commit
        info["commit_short"] = commit[:12]

        branch = _run("git", "rev-parse", "--abbrev-ref", "HEAD")
        if branch and branch != "HEAD":
            info["branch"] = branch

        tag = _run("git", "describe", "--tags", "--exact-match", "HEAD")
        if tag:
            info["tag"] = tag

        remote = _run("git", "remote", "get-url", "origin")
        if remote:
            info["remote_url"] = remote

    except Exception:
        pass

    return info
