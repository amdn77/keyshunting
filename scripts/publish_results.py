"""Publish scan state files to the scan-state branch via the GitHub Contents API.

Per-file PUTs are race-free across shards. Large files should go to the
scan-data release instead (see workflow). Usage:

  GH_TOKEN=... GH_REPO=owner/name python scripts/publish_results.py state/<shard>.json ...
"""
from __future__ import annotations

import base64
import os
import sys
import time
from pathlib import Path

import requests

MAX_API_BYTES = 45 * 1024 * 1024  # Contents API: files above this are rejected


def api(repo: str, token: str, method: str, path: str, **kw):
    url = f"https://api.github.com/repos/{repo}/contents/{path}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    return requests.request(method, url, headers=headers, timeout=60, **kw)


def publish_file(repo: str, token: str, branch: str, local: Path, remote: str) -> bool:
    size = local.stat().st_size
    if size > MAX_API_BYTES:
        print(f"SKIP {remote} ({size/1e6:.1f} MB > API limit; use release assets)")
        return False
    content = base64.b64encode(local.read_bytes()).decode()
    sha = None
    r = api(repo, token, "GET", remote, params={"ref": branch})
    if r.status_code == 200:
        sha = r.json().get("sha")
    payload = {"message": f"publish {remote}", "content": content, "branch": branch}
    if sha:
        payload["sha"] = sha
    for attempt in range(5):
        r = api(repo, token, "PUT", remote, json=payload)
        if r.status_code in (200, 201):
            print(f"published {remote}")
            return True
        print(f"PUT {remote}: {r.status_code} {r.text[:140]}")
        time.sleep(2.0 * (attempt + 1))
    return False


def main() -> None:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GH_REPO") or os.environ.get("GITHUB_REPOSITORY")
    branch = os.environ.get("SCAN_BRANCH", "scan-state")
    if not token or not repo:
        print("missing GH_TOKEN/GH_REPO")
        sys.exit(2)
    ok = True
    targets: list[Path] = []
    for arg in sys.argv[1:] or ["state", "results"]:
        p = Path(arg)
        if p.is_dir():
            targets.extend(sorted(f for f in p.rglob("*") if f.is_file()))
        elif p.exists():
            targets.append(p)
    for f in targets:
        remote = f.as_posix()
        if not publish_file(repo, token, branch, f, remote):
            ok = False
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
