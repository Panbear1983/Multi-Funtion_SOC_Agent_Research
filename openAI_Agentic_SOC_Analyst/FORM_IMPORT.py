"""
FORM_IMPORT.py - Pull a whole CTF hunt (every flag, hint, format, MITRE reference)
straight from the Cyber Range Google Form link, so nothing has to be copied by hand.

How it works: a public Google Form's `viewform` page embeds its structure in a
JavaScript variable (FB_PUBLIC_LOAD_DATA_). Section titles carry the flag text
("🚩 FLAG 1: ..." plus What-to-Hunt, Hint 1/2, Reference, Flag Format) and the short-
answer item right after it carries the question and the form's entry id.

Fetching uses curl (python's HTTPS fails certificate checks on this Mac). The form
must be viewable without sign-in - Cyber Range forms are.
"""

from __future__ import annotations

import html
import json
import re
import subprocess
from datetime import datetime

FORM_ID_RE = re.compile(r"docs\.google\.com/forms/(?:u/\d+/)?d/(?:e/)?([A-Za-z0-9_-]+)")
FLAG_HEAD_RE = re.compile(r"^\s*(?:🚩\s*)?FLAG\s*(\d+)\s*[:\-–]\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)


class FormImportError(RuntimeError):
    pass


def normalize_form_url(url: str) -> str:
    """Accept viewform / formResponse / edit links; return the public viewform URL."""
    url = (url or "").strip()
    m = FORM_ID_RE.search(url)
    if not m:
        raise FormImportError("That does not look like a Google Form link (expected docs.google.com/forms/...).")
    form_id = m.group(1)
    prefix = "d/e/" if "/d/e/" in url else "d/"
    return f"https://docs.google.com/forms/{prefix}{form_id}/viewform"


def fetch_html(url: str, timeout: int = 30) -> str:
    try:
        proc = subprocess.run(["curl", "-sL", "--max-time", str(timeout), url],
                              capture_output=True, text=True, timeout=timeout + 5)
    except FileNotFoundError:
        raise FormImportError("curl is not installed - cannot fetch the form.")
    except subprocess.TimeoutExpired:
        raise FormImportError("Timed out fetching the form. Check the internet connection and the link.")
    if proc.returncode != 0 or not proc.stdout:
        raise FormImportError(f"Could not fetch the form (curl exit {proc.returncode}).")
    if "accounts.google.com" in proc.stdout[:3000] and "FB_PUBLIC_LOAD_DATA_" not in proc.stdout:
        raise FormImportError("The form requires a Google sign-in to view, so it cannot be imported automatically.")
    return proc.stdout


def extract_form_data(page_html: str):
    m = re.search(r"FB_PUBLIC_LOAD_DATA_\s*=\s*(\[.*?\]);\s*</script>", page_html, re.S)
    if not m:
        raise FormImportError("This page does not contain a readable Google Form (no form data found).")
    try:
        return json.loads(m.group(1))
    except json.JSONDecodeError as e:
        raise FormImportError(f"The form data could not be parsed: {e}")


def _clean(text) -> str:
    if not text:
        return ""
    t = html.unescape(str(text))
    t = re.sub(r"<br\s*/?>", "\n", t, flags=re.I)
    t = re.sub(r"<[^>]+>", "", t)
    return t.replace("\r", "").strip()


def _parse_section_text(title: str, desc: str) -> dict:
    """Split a flag section into what-to-hunt, hints, reference(s), format."""
    out = {"what_to_hunt": "", "hints": [], "references": [], "format": ""}
    # Title's second line (after the FLAG n: name) is usually the what-to-hunt paragraph
    title_lines = [l.strip() for l in title.split("\n") if l.strip()]
    if len(title_lines) > 1:
        out["what_to_hunt"] = " ".join(title_lines[1:])
    body = [l.strip(" |") for l in re.split(r"\n|\s\|\s", desc) if l.strip(" |")]
    extra = []
    for line in body:
        low = line.lower()
        if low.startswith("hint"):
            out["hints"].append(re.sub(r"^hint\s*\d*\s*[:\-–]\s*", "", line, flags=re.I).strip())
        elif low.startswith("reference"):
            out["references"].append(re.sub(r"^references?\s*[:\-–]\s*", "", line, flags=re.I).strip())
        elif low.startswith("flag format") or low.startswith("format"):
            out["format"] = re.sub(r"^(?:flag\s*)?format\s*[:\-–]\s*", "", line, flags=re.I).strip()
        else:
            extra.append(line)
    if not out["what_to_hunt"] and extra:
        out["what_to_hunt"] = " ".join(extra)
    return out


def parse_flags(form_data) -> dict:
    """Return {title, description, flags:[...]} from the decoded FB_PUBLIC_LOAD_DATA_ array."""
    try:
        form = form_data[1]
        items = form[1] or []
    except (IndexError, TypeError):
        raise FormImportError("Unexpected form layout - could not find the question list.")
    form_title = _clean(form_data[3] if len(form_data) > 3 and form_data[3] else (form[8] if len(form) > 8 else ""))
    description = _clean(form[0] if form else "")

    flags = []
    pending = None   # flag section waiting for its question item
    for it in items:
        if not isinstance(it, list) or len(it) < 4:
            continue
        q_title, q_desc, q_type = _clean(it[1]), _clean(it[2]), it[3]
        head = FLAG_HEAD_RE.search(q_title)
        if q_type == 6 and head:      # section text = flag header + intel
            number, name = int(head.group(1)), head.group(2).strip()
            parsed = _parse_section_text(q_title, q_desc)
            pending = {"number": number, "title": f"FLAG {number}: {name}", "name": name, **parsed,
                       "question": "", "entry_id": None}
            flags.append(pending)
        elif q_type in (0, 1) and pending is not None:   # short/paragraph answer right after a flag
            question = re.sub(r"^question\s*[:\-–]\s*", "", q_title, flags=re.I).strip()
            pending["question"] = question
            try:
                pending["entry_id"] = it[4][0][0]
            except (IndexError, TypeError):
                pending["entry_id"] = None
            pending = None
    if not flags:
        raise FormImportError("No '🚩 FLAG n:' sections were found in this form.")
    flags.sort(key=lambda f: f["number"])
    return {"title": form_title, "description": description, "flags": flags}


def import_hunt(url: str) -> dict:
    """Fetch + parse. Returns {url, title, description, flags, imported_at}."""
    view_url = normalize_form_url(url)
    data = parse_flags(extract_form_data(fetch_html(view_url)))
    data["url"] = view_url
    data["imported_at"] = datetime.now().isoformat(timespec="seconds")
    return data


def flag_to_intel(flag: dict, flag_number: int | None = None) -> dict:
    """Shape one imported flag like the dict parse_flag_intel() produces from pasted text."""
    refs = "; ".join(flag.get("references", []))
    raw = [flag["title"]]
    if flag.get("what_to_hunt"):
        raw.append(flag["what_to_hunt"])
    for i, h in enumerate(flag.get("hints", []), 1):
        raw.append(f"Hint {i}: {h}")
    if refs:
        raw.append(f"Reference: {refs}")
    if flag.get("format"):
        raw.append(f"Flag Format: {flag['format']}")
    if flag.get("question"):
        raw.append(f"Question: {flag['question']}")
    return {
        "raw_intel": "\n".join(raw),
        "flag_number": flag_number or flag["number"],
        "title": flag["title"],
        "objective": flag.get("question") or flag.get("what_to_hunt", ""),
        "hints": list(flag.get("hints", [])),
        "mitre": refs,
        "format": flag.get("format", ""),
        "what_to_hunt": flag.get("what_to_hunt", ""),
        "entry_id": flag.get("entry_id"),
        "source": "google_form",
    }


def summarize(hunt: dict) -> str:
    lines = [f"{hunt.get('title', 'Untitled hunt')} - {len(hunt['flags'])} flags"]
    for f in hunt["flags"]:
        q = f.get("question") or "(no question text)"
        lines.append(f"  {f['number']:>2}. {f['name']}  →  {q[:70]}{'...' if len(q) > 70 else ''}")
    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    print(summarize(import_hunt(sys.argv[1])))
