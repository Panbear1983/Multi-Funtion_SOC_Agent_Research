"""
EVIDENCE_FILTER.py - Deterministic evidence extraction that runs BEFORE the model.

The model is slow and window-limited; Python is neither. So plain code scans the
FULL query result for values that match what the flag is asking for (an IP, a file
name, a command line, an account, a named pipe, a base64 payload...), decodes what
can be decoded, ranks the candidates, and hands the model a short candidates table
plus the exact rows they came from - with their original RowIds.

A small model reading the right twenty rows beats a big model skimming two thousand.
Nothing here guesses the answer for the analyst: it narrows, the human decides
(coach mode decides how much of this is shown).
"""

from __future__ import annotations

import base64
import csv
import io
import re
from collections import Counter, defaultdict

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
FILE_RE = re.compile(r"[\w\-\. ]+?\.(?:exe|dll|ps1|bat|cmd|vbs|js|zip|7z|rar|txt|kdbx|csv|docx|xlsx|pdf|lnk|log|db|jpg|png|msi|scr|cab|dat)\b", re.I)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9\-]+\.)+(?:com|net|org|io|sh|cc|xyz|ru|cn|top|info|me|co|us|de|uk|ly|gg|app|dev|cloud)\b", re.I)
URL_RE = re.compile(r"https?://[^\s\"',]+", re.I)
PIPE_RE = re.compile(r"(?:\\\\\.\\pipe\\|\\Device\\NamedPipe\\|\\pipe\\)[\w\-\.]+", re.I)
PIPENAME_JSON_RE = re.compile(r"\"PipeName\"\s*:\s*\"([^\"]+)\"", re.I)
ENC_RE = re.compile(r"(?:-enc(?:odedcommand)?|-e|-ec)\s+([A-Za-z0-9+/=]{16,})", re.I)
B64_CALL_RE = re.compile(r"FromBase64String\(['\"]([A-Za-z0-9+/=]{16,})['\"]\)", re.I)
LONG_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
WINPATH_RE = re.compile(r"[A-Za-z]:\\(?:[^\\\"',\s]+\\)*[^\\\"',\s]*", re.I)

LOLBINS = ("powershell", "pwsh", "cmd.exe", "certutil", "curl", "wget", "bitsadmin", "mshta", "rundll32",
           "regsvr32", "wscript", "cscript", "schtasks", "reg.exe", "reg add", "net.exe", "net user", "net localgroup",
           "whoami", "nltest", "netstat", "qwinsta", "quser", "query user", "tasklist", "procdump", "mimikatz",
           "7z", "tar ", "xcopy", "robocopy", "copy ", "attrib", "icacls", "wmic", "psexec", "ipconfig", "systeminfo",
           "findstr", "dir ", "where ", "forfiles", "dsquery", "dsget")

FAMILY_WORDS = {
    "ip": ("ip address", "ip", "xxx.xxx", "source ip", "server ip", "destination"),
    "filename": ("filename", "file name", "file ", "beacon", "implant", "archive", "document", "database"),
    "command": ("command", "command line", "cmdline"),
    "account": ("account", "username", "user name", "credential", "backdoor account"),
    "domain": ("domain", "service", "url", "hosting", "website"),
    "pipe": ("pipe",),
    "base64": ("base64", "decoded", "encoded", "obfuscated"),
    "path": ("directory", "path", "folder", "staging"),
    "count": ("number of", "how many", "total", "count"),
    "device": ("device name", "hostname", "computer name", "target device", "machine"),
}


def detect_families(flag_intel: dict) -> list[str]:
    fmt = ((flag_intel or {}).get("format") or "").lower()
    obj = ((flag_intel or {}).get("objective") or "").lower()
    hints = " ".join((flag_intel or {}).get("hints", []) or []).lower()
    text = f"{fmt} | {obj} | {hints}"
    fams = []
    for fam, words in FAMILY_WORDS.items():
        if any(w in fmt for w in words) or any(w in obj for w in words):
            fams.append(fam)
    # weaker signals from hints
    if "pipe" in hints and "pipe" not in fams:
        fams.append("pipe")
    if ("base64" in hints or "decode" in hints) and "base64" not in fams:
        fams.append("base64")
    if "command" in hints and "command" not in fams and not fams:
        fams.append("command")
    if not fams:
        fams = ["command", "filename", "ip"]   # sensible default for MDE hunts
    return fams


def _read_csv(csv_text: str):
    lines = [l for l in csv_text.split("\n") if l.strip() and not l.startswith("#")]
    if len(lines) < 2:
        return [], []
    reader = csv.reader(io.StringIO("\n".join(lines)))
    rows = list(reader)
    header = rows[0]
    has_rowid = header and header[0].strip().lower() == "rowid"
    out = []
    for i, r in enumerate(rows[1:], start=1):
        if not any(c.strip() for c in r):
            continue
        rid = i
        cells = r
        if has_rowid:
            try:
                rid = int(r[0])
            except ValueError:
                pass
            cells = r[1:]
        out.append((rid, dict(zip(header[1:] if has_rowid else header, cells))))
    return (header[1:] if has_rowid else header), out


def _decode_powershell_b64(b64: str) -> str:
    try:
        raw = base64.b64decode(b64 + "=" * (-len(b64) % 4))
    except Exception:
        return ""
    for enc in ("utf-16-le", "utf-8"):
        try:
            txt = raw.decode(enc)
            if txt and sum(c.isprintable() for c in txt) / max(1, len(txt)) > 0.9:
                return txt.strip()
        except Exception:
            continue
    return ""


def _col(row: dict, *names):
    for n in names:
        for k, v in row.items():
            if k.lower() == n.lower():
                return v or ""
    return ""


def extract_candidates(csv_text: str, flag_intel: dict, max_candidates: int = 8) -> dict:
    """
    Returns {
      families, total_rows, candidates: [{value, family, count, row_ids, why}],
      decoded: [{row_id, decoded}], counts: {...}
    }
    """
    families = detect_families(flag_intel)
    header, rows = _read_csv(csv_text)
    total = len(rows)
    keywords = _keywords(flag_intel)

    found: dict[tuple[str, str], list[int]] = defaultdict(list)
    decoded_all = []

    for rid, row in rows:
        blob = " ".join(v for v in row.values() if v)
        cmd = _col(row, "ProcessCommandLine", "InitiatingProcessCommandLine")
        if "ip" in families:
            for ip in set(IP_RE.findall(blob)):
                if not ip.startswith(("0.", "127.", "255.")):
                    found[("ip", ip)].append(rid)
        if "filename" in families:
            fn = _col(row, "FileName")
            if fn:
                found[("filename", fn.strip())].append(rid)
            for f in set(m.group(0).strip() for m in FILE_RE.finditer(blob)):
                found[("filename", f)].append(rid)
        if "command" in families and cmd:
            low = cmd.lower()
            if any(t in low for t in LOLBINS):
                found[("command", cmd.strip())].append(rid)
        if "account" in families:
            acct = _col(row, "AccountName", "InitiatingProcessAccountName", "UserPrincipalName")
            if acct:
                found[("account", acct.strip())].append(rid)
        if "device" in families:
            dev = _col(row, "DeviceName", "RemoteDeviceName")
            if dev:
                found[("device", dev.strip())].append(rid)
        if "domain" in families:
            for u in set(URL_RE.findall(blob)):
                found[("domain", u)].append(rid)
            for d in set(DOMAIN_RE.findall(blob)):
                if not IP_RE.fullmatch(d):
                    found[("domain", d.lower())].append(rid)
        if "pipe" in families:
            for p in set(PIPE_RE.findall(blob)) | set(PIPENAME_JSON_RE.findall(blob)):
                found[("pipe", p)].append(rid)
        if "base64" in families or "command" in families:
            for m in list(ENC_RE.finditer(blob)) + list(B64_CALL_RE.finditer(blob)):
                dec = _decode_powershell_b64(m.group(1))
                if dec:
                    decoded_all.append({"row_id": rid, "decoded": dec[:400]})
                    found[("base64", dec[:400])].append(rid)
        if "path" in families:
            fp = _col(row, "FolderPath")
            if fp:
                found[("path", fp.strip())].append(rid)
            for pth in set(WINPATH_RE.findall(cmd)):
                if len(pth) > 6:
                    found[("path", pth)].append(rid)

    # Score: rarity (rare values are interesting), keyword hits, suspicious markers
    scored = []
    for (fam, value), rids in found.items():
        count = len(rids)
        low = value.lower()
        score = 0.0
        score += 3.0 if count == 1 else (2.0 if count <= 3 else (1.0 if count <= 10 else 0.2))
        kw_hits = [k for k in keywords if k in low]
        score += 1.5 * len(kw_hits)
        sus = [g for g in ("temp", "public", "programdata", "appdata", "-enc", "bypass", "hidden", "downloadstring",
                           "iex", "invoke", "http", ".zip", ".7z", "password", "kdbx", "pipe", "beacon", "kb") if g in low]
        score += 0.5 * len(sus)
        if fam == "base64":
            # a decoded payload is exactly what a "decoded command" flag wants - rank it above the raw line
            score += 5.0 if "base64" in families else 2.0
        elif fam == "command" and "base64" in families and ENC_RE.search(value):
            score -= 2.0   # the still-encoded command line is the wrapper, not the answer
        why = []
        if count == 1:
            why.append("appears once")
        elif count <= 3:
            why.append(f"appears {count}x")
        else:
            why.append(f"appears {count}x")
        if kw_hits:
            why.append("matches hint words: " + ", ".join(kw_hits[:3]))
        if sus:
            why.append("suspicious markers: " + ", ".join(sus[:3]))
        scored.append({"value": value, "family": fam, "count": count, "row_ids": sorted(rids)[:6],
                       "score": round(score, 2), "why": "; ".join(why)})

    scored.sort(key=lambda c: (-c["score"], c["count"], c["value"]))
    counts = {}
    if "count" in families:
        # e.g. "how many archives were created" - count unique archive names / matching rows
        archives = {v for (f, v) in found if f == "filename" and re.search(r"\.(zip|7z|rar|tar|gz|cab)$", v, re.I)}
        counts["unique_archive_filenames"] = len(archives)
        counts["matching_rows"] = total
    return {"families": families, "total_rows": total, "candidates": scored[:max_candidates],
            "decoded": decoded_all[:10], "counts": counts}


def _keywords(flag_intel: dict) -> set[str]:
    stop = {"what", "which", "that", "this", "with", "from", "into", "identify", "question", "answer",
            "used", "were", "there", "their", "flag", "find", "search", "look", "field", "query", "table",
            "the", "and", "for", "was", "command", "file", "name", "address"}
    text = " ".join([(flag_intel or {}).get("objective", "") or "", (flag_intel or {}).get("format", "") or ""]
                    + list((flag_intel or {}).get("hints", []) or [])).lower()
    return {w for w in re.findall(r"[a-z0-9_\-\.]{3,}", text) if w not in stop}


def candidate_row_ids(result: dict) -> list[int]:
    ids = []
    for c in result.get("candidates", []):
        ids.extend(c["row_ids"])
    for d in result.get("decoded", []):
        ids.append(d["row_id"])
    return sorted(set(ids))


def render_for_prompt(result: dict, level: int = 3) -> str:
    """
    Text block for the model. level 1 = families + counts only (coach), 2 = candidates
    without ranking words, 3 = full ranked candidates + decoded payloads.
    """
    lines = [f"PRE-EXTRACTED EVIDENCE (deterministic scan of all {result['total_rows']} rows; "
             f"looking for: {', '.join(result['families'])})"]
    if result.get("counts"):
        lines.append("Counts: " + ", ".join(f"{k}={v}" for k, v in result["counts"].items()))
    if level >= 2 and result["candidates"]:
        lines.append("Candidate values (value | family | rows | why):")
        for c in result["candidates"]:
            v = c["value"] if len(c["value"]) <= 160 else c["value"][:157] + "..."
            lines.append(f"- {v} | {c['family']} | rows {c['row_ids']} | {c['why']}")
    if level >= 3 and result.get("decoded"):
        lines.append("Decoded base64 payloads:")
        for d in result["decoded"]:
            lines.append(f"- row {d['row_id']}: {d['decoded'][:200]}")
    if level < 2:
        lines.append(f"({len(result['candidates'])} candidate values found - hidden at coach level 1)")
    return "\n".join(lines)


def render_for_human(result: dict, level: int) -> str:
    """What the analyst is allowed to see at the current coach level."""
    if level <= 1:
        fams = ", ".join(result["families"])
        n = len(result["candidates"])
        return (f"Scanned {result['total_rows']} rows for {fams}. {n} candidate value(s) stand out. "
                f"Look at the fields that carry {fams} values and at rows that appear only once.")
    if level == 2:
        out = [f"Candidate values (unranked) from {result['total_rows']} rows:"]
        for c in sorted(result["candidates"], key=lambda c: c["row_ids"][0] if c["row_ids"] else 0):
            v = c["value"] if len(c["value"]) <= 120 else c["value"][:117] + "..."
            out.append(f"  • {v}   (rows {', '.join(map(str, c['row_ids'][:4]))})")
        return "\n".join(out)
    return render_for_prompt(result, level=3)
