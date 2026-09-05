"""
PUBLISH.py - Put a drafted write-up on GitHub the way Peter already does it:
a branch, one commit, a push, and a pull request against main.

Safety: the repo's secret-scan hooks (scripts/git-hooks, wired via core.hooksPath)
run on the commit and on the push. Nothing is force-pushed, main is never touched
directly, and the analyst confirms before anything leaves the machine.
"""

from __future__ import annotations

import os
import re
import subprocess
from datetime import datetime

REPORT_DIR = "Threat_Hunting_Projects"


class PublishError(RuntimeError):
    pass


def _run(cmd, cwd, check=True):
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise PublishError(f"{' '.join(cmd)}\n{proc.stderr.strip() or proc.stdout.strip()}")
    return proc.stdout.strip()


def repo_root(start: str | None = None) -> str:
    start = start or os.path.dirname(os.path.abspath(__file__))
    return _run(["git", "rev-parse", "--show-toplevel"], cwd=start)


def slugify(title: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return s[:60] or "threat-hunt"


def write_report_file(markdown: str, filename: str, root: str | None = None) -> str:
    root = root or repo_root()
    path = os.path.join(root, REPORT_DIR, filename)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(markdown)
    return path


def preflight(root: str) -> dict:
    """Facts the analyst should see before agreeing to push."""
    info = {"root": root}
    info["remote"] = _run(["git", "remote", "get-url", "origin"], cwd=root, check=False) or "(no remote)"
    info["branch"] = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=root, check=False)
    info["hooks"] = _run(["git", "config", "core.hooksPath"], cwd=root, check=False) or "(none)"
    info["gh"] = subprocess.run(["gh", "auth", "status"], capture_output=True, text=True).returncode == 0
    info["dirty"] = _run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=root, check=False)
    return info


def update_index(entry: str, root: str | None = None) -> str:
    """Insert the hunt's block into Threat_Hunting_Projects/README.md (newest first). Returns the path."""
    import REPORT_GENERATOR
    root = root or repo_root()
    path = os.path.join(root, REPORT_DIR, "README.md")
    text = open(path, encoding="utf-8").read() if os.path.exists(path) else f"# 🎯 Threat Hunting Projects\n\n{REPORT_GENERATOR.INDEX_HEADER}\n\n"
    with open(path, "w", encoding="utf-8") as f:
        f.write(REPORT_GENERATOR.insert_index_entry(text, entry))
    return path


def publish(report_path: str, title: str, body: str = "", base: str = "main", root: str | None = None,
            extra_paths=()) -> str:
    """
    Branch → commit the report (+ the index README and any extra_paths) → push → PR.
    Returns the PR URL. Raises PublishError with the exact git/gh message on any failure.
    """
    root = root or repo_root()
    rel = os.path.relpath(report_path, root)
    if not os.path.exists(report_path):
        raise PublishError(f"Report file not found: {report_path}")
    rels = [rel] + [os.path.relpath(p, root) for p in extra_paths if os.path.exists(p)]

    stamp = datetime.now().strftime("%Y%m%d")
    branch = f"threat-hunt-{slugify(title)}-{stamp}"
    current = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=root)

    # Create (or reuse) the branch from the current HEAD, carrying only the report
    existing = _run(["git", "branch", "--list", branch], cwd=root, check=False)
    if existing:
        _run(["git", "checkout", branch], cwd=root)
    else:
        _run(["git", "checkout", "-b", branch], cwd=root)
    try:
        _run(["git", "add", "--", *rels], cwd=root)
        staged = _run(["git", "diff", "--cached", "--name-only"], cwd=root, check=False)
        if not staged:
            raise PublishError("Nothing new to commit - the report is unchanged.")
        _run(["git", "commit", "-m", f"Add threat hunt write-up: {title}"], cwd=root)   # pre-commit hook runs here
        _run(["git", "push", "-u", "origin", branch], cwd=root)                         # pre-push hook runs here
    finally:
        # Go back to where the analyst was, whatever happened
        _run(["git", "checkout", current], cwd=root, check=False)

    pr_body = body or (f"Threat hunt write-up drafted by the SOC analyst tool on {datetime.now():%Y-%m-%d}.\n\n"
                       "Narrative sections are marked DRAFT for review; screenshots to be added.")
    try:
        url = _run(["gh", "pr", "create", "--base", base, "--head", branch, "--title", f"Threat hunt write-up: {title}",
                    "--body", pr_body], cwd=root)
        return url.splitlines()[-1] if url else f"branch {branch} pushed (PR URL not returned)"
    except PublishError as e:
        if "already exists" in str(e):
            return _run(["gh", "pr", "view", branch, "--json", "url", "--jq", ".url"], cwd=root, check=False) or f"branch {branch} (PR exists)"
        raise PublishError(f"Pushed branch {branch}, but the pull request could not be opened:\n{e}\n"
                           f"Open it by hand: gh pr create --base {base} --head {branch}")
