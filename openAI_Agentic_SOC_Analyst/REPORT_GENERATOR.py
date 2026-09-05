"""
REPORT_GENERATOR.py - Draft the GitHub threat-hunt write-up from a CTF session.

Template = Peter's published reports in Threat_Hunting_Projects/ (e.g. "(CTF) Threat
Hunt SAGA#2: Cargo Hold.md"): header + contributors, 📏 Perimeters, 📄 Overview,
💠 Diamond Model, 🥋 MITRE ATT&CK table, ⛨ Remediation, ✍️ Lessons Learned,
🏔️ Conclusion, then 🎯 Capture The Flags: 🕙 Timeline, 🚩 Completed Flag Map, one
block per flag (Objective / What to Hunt / Hints / Reference / KQL / Output / Finding /
screenshot), and 🔎 Analyst Workflow.

Everything structured comes straight from the session (imported form flags + captured
answers, KQL, notes). The narrative sections are drafted by the selected model from
those facts only and are clearly marked DRAFT for Peter to edit. Screenshots stay manual.
"""

from __future__ import annotations

import json
import re
from datetime import datetime

HR = '<hr style="height: 4px; background-color: grey; border: none; margin-top: 40px;">'
DRAFT = "<!-- DRAFT (AI-written from session facts) - review and edit before publishing -->"
SHOT = "<!-- screenshot: upload to the GitHub PR and paste the <img> line here -->"

TECH_RE = re.compile(r"\(?\b(TA?\d{4}(?:\.\d{3})?)\b\)?")
TS_RE = re.compile(r"\b(20\d\d-\d\d-\d\d[T ]\d\d:\d\d(?::\d\d)?|\d{1,2}/\d{1,2}/20\d\d,? \d{1,2}:\d\d(?::\d\d)?(?:\.\d+)? ?[AP]?M?)")
DEVICE_RE = re.compile(r"\b([a-z0-9]+-(?:adminpc|fileserver\d*|sl|dc\d*|srv\d*|ws\d+|pc\d+|vm\d+)|azuki-[\w\-]+)\b", re.I)


# ═══════════════════════════════════════════════════════════════════════
# FACTS FROM THE SESSION
# ═══════════════════════════════════════════════════════════════════════

def _planned_by_number(state):
    return {int(f["number"]): f for f in (state.get("flags_planned") or []) if str(f.get("number", "")).isdigit()}


def _captured(state):
    out = []
    for f in state.get("flags_captured", []):
        try:
            n = int(str(f.get("flag_number", "")).strip())
        except ValueError:
            continue
        out.append((n, f))
    out.sort(key=lambda t: t[0])
    return out


def _tactic_from_name(name: str) -> str:
    """'LATERAL MOVEMENT - Source System' -> 'Lateral Movement'."""
    head = re.split(r"\s+[-–—]\s+", name or "", maxsplit=1)[0]
    return head.strip().title().replace("And", "and").replace("&", "&") if head else ""


def _techniques(refs):
    """['Valid Accounts (T1078)', 'Named Pipe Examples'] -> [('T1078', 'Valid Accounts')]."""
    out = []
    for r in refs or []:
        m = TECH_RE.search(r)
        if m:
            name = TECH_RE.sub("", r).strip(" :-–—()")
            if m.group(1).startswith("TA") and "tactic" not in name.lower():
                name = f"{name} (tactic)"
            out.append((m.group(1), name))
    return out


def _normalize_ts(txt: str) -> str:
    """'11/25/2025, 6:09:18.203 AM' or '2025-11-25T06:09:18Z' → '2025-11-25 06:09:18' (unchanged if unknown)."""
    t = txt.strip()
    for fmt in ("%m/%d/%Y, %I:%M:%S.%f %p", "%m/%d/%Y, %I:%M:%S %p", "%m/%d/%Y %I:%M:%S.%f %p", "%m/%d/%Y %I:%M:%S %p",
                "%m/%d/%Y, %I:%M %p", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(t, fmt).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    m = re.match(r"(\d{4}-\d\d-\d\d)[T ](\d\d:\d\d:\d\d)", t)
    return f"{m.group(1)} {m.group(2)}" if m else t


def _first_timestamp(text: str):
    m = TS_RE.search(text or "")
    return _normalize_ts(m.group(1)) if m else ""


def _device_hint(*texts):
    for t in texts:
        m = DEVICE_RE.search(t or "")
        if m:
            return m.group(1)
    return ""


def collect_facts(state: dict) -> dict:
    planned = _planned_by_number(state)
    captured = _captured(state)
    hunt = state.get("hunt_form") or {}
    flags = []
    for n, f in captured:
        p = planned.get(n, {})
        flags.append({
            "number": n,
            "name": p.get("name") or re.sub(r"^FLAG\s*\d+\s*[:\-–]\s*", "", f.get("title", ""), flags=re.I) or f.get("title", f"Flag {n}"),
            "tactic": _tactic_from_name(p.get("name", "")) or (f.get("stage") or ""),
            "objective": p.get("question") or "",
            "what_to_hunt": p.get("what_to_hunt", ""),
            "hints": p.get("hints", []),
            "references": p.get("references", []),
            "format": p.get("format", ""),
            "techniques": _techniques(p.get("references", [])) or _techniques([f.get("mitre", "")]),
            "answer": f.get("answer", ""),
            "kql": f.get("kql_used", ""),
            "table": f.get("table_queried", ""),
            "notes": f.get("notes", ""),
            "finding": _finding_text(f.get("notes", "")),
            "timestamp": _first_timestamp(f.get("notes", "")),
            "device": _device_hint(f.get("answer", ""), f.get("notes", ""), f.get("kql_used", "")),
            "captured_at": f.get("captured_at", ""),
        })
    devices = [x["device"] for x in flags if x["device"]]
    primary_host = max(set(devices), key=devices.count) if devices else ""
    stamps = [x["timestamp"] for x in flags if x["timestamp"]]
    return {
        "title": state.get("project_name") or hunt.get("title") or "Threat Hunt",
        "hunt_title": hunt.get("title", ""),
        "hunt_url": hunt.get("url", ""),
        "hunt_description": hunt.get("description", ""),
        "date_completed": (state.get("last_updated") or datetime.now().isoformat())[:10],
        "primary_host": primary_host,
        "date_range": f"{min(stamps)[:10]} to {max(stamps)[:10]}" if stamps else "",
        "flags": flags,
        "iocs": state.get("accumulated_iocs", {}),
        "total_planned": len(planned) or state.get("total_flags") or len(flags),
    }


def _finding_text(notes: str) -> str:
    """The analyst's own finding notes without the pasted query output block."""
    if not notes:
        return ""
    txt = notes
    if "QUERY OUTPUT:" in txt:
        # notes = "QUERY OUTPUT:\n...rows...\n\nFINDING:\n..." or similar - keep the prose part
        parts = re.split(r"\n\s*(?:FINDING|NOTES?|ANALYSIS)\s*:\s*\n", txt, maxsplit=1, flags=re.I)
        txt = parts[1] if len(parts) > 1 else ""
    return txt.strip()


# ═══════════════════════════════════════════════════════════════════════
# AI-DRAFTED NARRATIVE (facts in, prose out, marked DRAFT)
# ═══════════════════════════════════════════════════════════════════════

NARRATIVE_SCHEMA = {
    "type": "object",
    "properties": {
        "overview": {"type": "string"},
        "diamond": {"type": "object", "properties": {
            "adversary": {"type": "string"}, "infrastructure": {"type": "string"},
            "capability": {"type": "string"}, "victim": {"type": "string"}},
            "required": ["adversary", "infrastructure", "capability", "victim"], "additionalProperties": False},
        "remediation": {"type": "array", "items": {"type": "object", "properties": {
            "title": {"type": "string"}, "actions": {"type": "array", "items": {"type": "string"}}},
            "required": ["title", "actions"], "additionalProperties": False}},
        "lessons": {"type": "array", "items": {"type": "string"}},
        "conclusion": {"type": "string"},
        "workflow": {"type": "array", "items": {"type": "object", "properties": {
            "flag": {"type": "integer"}, "line": {"type": "string"}},
            "required": ["flag", "line"], "additionalProperties": False}},
        "timeline_events": {"type": "array", "items": {"type": "object", "properties": {
            "flag": {"type": "integer"}, "event": {"type": "string"}},
            "required": ["flag", "event"], "additionalProperties": False}},
    },
    "required": ["overview", "diamond", "remediation", "lessons", "conclusion", "workflow", "timeline_events"],
    "additionalProperties": False,
}


def draft_narrative(facts: dict, model: str, openai_client=None) -> dict:
    import LLM_ROUTER
    if openai_client is not None:
        LLM_ROUTER.set_openai_client(openai_client)
    flag_lines = []
    for f in facts["flags"]:
        techs = ", ".join(f"{t} {n}".strip() for t, n in f["techniques"]) or "n/a"
        flag_lines.append(f"Flag {f['number']} [{f['tactic'] or '?'}] {f['name']}: Q: {f['objective']} | ANSWER: {f['answer']} | "
                          f"technique: {techs} | analyst notes: {f['finding'][:300] or 'none'}")
    prompt = f"""You are writing the narrative sections of a SOC threat-hunt write-up for GitHub.
Use ONLY the facts below. Never invent IPs, hosts, accounts, commands or tools that are not in the facts.
Write in the analyst's voice: concise, professional, past tense, like a published incident report.

HUNT: {facts['title']} ({facts['hunt_title']})
SCENARIO BRIEF: {facts['hunt_description'][:1200] or 'n/a'}
PRIMARY HOST: {facts['primary_host'] or 'unknown'}   INCIDENT DATES: {facts['date_range'] or 'unknown'}
FLAGS AND ANSWERS:
{chr(10).join(flag_lines)}

Produce:
- overview: 2 short paragraphs (what happened end to end; tradecraft assessment)
- diamond: adversary / infrastructure / capability / victim - one dense sentence each, citing the actual values
- remediation: 5-7 groups, each with a title and 2 concrete actions tied to the observed techniques
- lessons: 5-6 bullets, each "**Bold lead:** one sentence"
- conclusion: 1 paragraph describing the kill chain with arrows (a → b → c), naming the tools used
- workflow: for EVERY flag number, one sentence in this exact style: "<what the step established>; the <thing> was **\\"<answer>\\"**."
- timeline_events: for EVERY flag number, a 3-6 word event label (e.g. "RDP pivot to admin PC")
"""
    text = LLM_ROUTER.chat([{"role": "user", "content": prompt}], model, json_mode=True,
                           json_schema=NARRATIVE_SCHEMA, temperature=0.3, think=False,
                           max_tokens=6000, timeout=900, purpose="report_narrative")
    data = LLM_ROUTER.extract_json(text)
    return data if isinstance(data, dict) and data.get("overview") else {}


# ═══════════════════════════════════════════════════════════════════════
# MARKDOWN
# ═══════════════════════════════════════════════════════════════════════

def _esc(v: str) -> str:
    return (v or "").replace("|", "\\|").replace("\n", " ")


def build_report(state: dict, model: str | None = None, openai_client=None, contributors: dict | None = None) -> str:
    facts = collect_facts(state)
    nar = {}
    if model and facts["flags"]:
        try:
            nar = draft_narrative(facts, model, openai_client)
        except Exception as e:  # the structured report is still produced without prose
            nar = {"_error": str(e)}
    c = {"sandbox": "[Cyber Range AZURE LAW by Josh Madakor's team](https://www.skool.com/cyber-community)",
         "designer": "<!-- Hunt Design Master name -->",
         "wingbot": "[MixLocalAgentic_SOC_Analyst](https://github.com/Panbear1983/Multi-Funtion_SOC_Agent_Research/tree/main/openAI_Agentic_SOC_Analyst)"}
    c.update(contributors or {})
    wf = {w.get("flag"): w.get("line", "") for w in nar.get("workflow", []) if isinstance(w, dict)}
    ev = {w.get("flag"): w.get("event", "") for w in nar.get("timeline_events", []) if isinstance(w, dict)}
    dm = nar.get("diamond") or {}

    L = []
    L.append(f"# 🚩 {facts['title']}\n")
    L.append("<!-- cover image: upload to the PR and paste the <img> line here -->\n")
    L.append(f"**Sandbox Contributor:** {c['sandbox']}  ")
    L.append(f"**Hunt Design Master:** {c['designer']}  ")
    L.append(f"**Loyal Wingbot:** {c['wingbot']}\n")
    L.append(HR + "\n")

    L.append("## 📏 Perimeters")
    L.append(f"Date Completed: ***{facts['date_completed']}***    ")
    L.append("Simulated Environment: `Cyber Range AZURE LAW`  ")
    L.append(f"Primary Impacted Host: `{facts['primary_host'] or 'TBD'}`  ")
    L.append(f"Incident Date Range: ***{facts['date_range'] or 'TBD'}***  ")
    if facts["hunt_url"]:
        L.append(f"Hunt Link: [Cyber Range SOC - {facts['hunt_title'] or facts['title']}]({facts['hunt_url']})  ")
    L.append("Frameworks Applied: ***MITRE ATT&CK***, ***NIST 800-61***\n")
    L.append(HR + "\n")

    L.append("## 📄 Overview")
    L.append(DRAFT)
    L.append((nar.get("overview") or "_Write 2 short paragraphs: what happened end to end, and the tradecraft assessment._") + "\n")
    L.append(HR + "\n")

    L.append("## 💠 Diamond Model Analysis")
    L.append(DRAFT)
    L.append("| Feature | Details |\n|---|---|")
    L.append(f"| **Adversary** | {_esc(dm.get('adversary') or 'TBD')} |")
    L.append(f"| **Infrastructure** | {_esc(dm.get('infrastructure') or 'TBD')} |")
    L.append(f"| **Capability** | {_esc(dm.get('capability') or 'TBD')} |")
    L.append(f"| **Victim** | {_esc(dm.get('victim') or 'TBD')} |\n")
    L.append(HR + "\n")

    L.append("## 🥋 MITRE ATT&CK Table\n")
    L.append("| Stage | Flag | Tactic | Technique ID | Technique |\n|---|---|---|---|---|")
    for f in facts["flags"]:
        techs = f["techniques"] or [("TBD", "")]
        for tid, tname in techs[:2]:
            L.append(f"| {f['tactic'] or 'TBD'} | {f['number']} | {f['tactic'] or 'TBD'} | **{tid}** | {_esc(tname) or 'TBD'} |")
    L.append("")
    L.append(HR + "\n")

    L.append("## ⛨ Remediation Actions")
    L.append(DRAFT)
    rem = nar.get("remediation") or []
    if rem:
        for i, g in enumerate(rem, 1):
            L.append(f"{i}. **{g.get('title', '')}**")
            for a in g.get("actions", []):
                L.append(f"   - {a}")
            L.append("")
    else:
        L.append("1. **TBD**\n   - TBD\n")
    L.append(HR + "\n")

    L.append("## ✍️ Lessons Learned")
    L.append(DRAFT)
    for item in (nar.get("lessons") or ["**TBD:** TBD"]):
        L.append(f"- {item}")
    L.append("")
    L.append(HR + "\n")

    L.append("## 🏔️ Conclusion")
    L.append(DRAFT)
    L.append((nar.get("conclusion") or "_One paragraph: the kill chain as a → b → c, naming the tools._") + "\n")
    L.append(HR)
    L.append(HR + "\n")

    L.append("# 🎯 Capture The Flags\n")
    L.append("## 🕙 Timeline of Events\n")
    L.append("| **Timestamp (UTC)** | **Event** | **Target Device** | **Details** |\n|---|---|---|---|")
    for f in facts["flags"]:
        ts = f["timestamp"] or f"{facts['date_range'][:10] if facts['date_range'] else 'TBD'} ~"
        event = ev.get(f["number"]) or f["name"]
        L.append(f"| **{_esc(ts)}** | {_esc(event)} | {_esc(f['device'] or facts['primary_host'] or 'TBD')} | `{_esc(f['answer'])[:80]}` (Flag {f['number']}) |")
    L.append("")
    L.append(HR + "\n")

    L.append("## 🚩 Completed Flag Map\n")
    L.append("| Flag | Objective | Value |\n|--------|---------------------------------------------|--------------------------------------------------|")
    for f in facts["flags"]:
        L.append(f"| **{f['number']}** | {_esc(f['name'])} | {_esc(f['answer'])} |")
    L.append("")
    L.append(HR + "\n")

    for f in facts["flags"]:
        L.append(f"### 🚩 Flag {f['number']}: {f['name']}\n")
        L.append(f"**Objective:** {f['objective'] or 'TBD'}\n")
        if f["what_to_hunt"]:
            L.append(f"**What to Hunt:** {f['what_to_hunt']}\n")
        for i, h in enumerate(f["hints"], 1):
            L.append(f"**Hint {i}:** {h}\n")
        ref = f["table"] or ", ".join(f"{n} ({t})".strip() for t, n in f["techniques"]) or "TBD"
        L.append(f"**Reference:** {ref}\n")
        L.append("**KQL Query:**\n")
        L.append("```kql\n" + (f["kql"].strip() or "-- paste the query used --") + "\n```\n")
        L.append(f"**Output:** `{f['answer']}`  ")
        L.append(f"**Finding:** {f['finding'] or 'TBD - describe what the rows showed and why this is the answer.'}")
        L.append(SHOT + "\n")
        L.append("---\n")

    L.append("## 🔎 Analyst Workflow\n")
    L.append("### From an investigative standpoint, the workflow progressed as follows:\n")
    for f in facts["flags"]:
        line = wf.get(f["number"]) or f"{f['name']}; the value was **\"{f['answer']}\"**."
        L.append(f"**{f['number']} 🚩:** {line}  \n")

    if nar.get("_error"):
        L.append(f"\n<!-- narrative drafting failed: {nar['_error'][:200]} -->")
    return "\n".join(L)


def default_filename(state: dict) -> str:
    title = (state.get("project_name") or (state.get("hunt_form") or {}).get("title") or "Threat Hunt").strip()
    safe = re.sub(r'[\\/*?"<>|]+', "", title).strip()   # ':' kept - matches "(CTF) Threat Hunt SAGA#2: Cargo Hold.md"
    return f"(CTF) {safe}.md"


# ═══════════════════════════════════════════════════════════════════════
# HUNT INDEX (Threat_Hunting_Projects/README.md) - newest first, numbered
# ═══════════════════════════════════════════════════════════════════════

INDEX_HEADER = "## 📚 Threat Hunt Reports"


def index_entry(state: dict, emoji: str = "🚩", focus: str = "", blurb: str = "") -> str:
    """One index block for this hunt, in the exact shape of the existing entries."""
    from urllib.parse import quote
    facts = collect_facts(state)
    fname = default_filename(state)
    link = "./" + quote(fname, safe="")
    tactics = []
    for f in facts["flags"]:
        t = f["tactic"]
        if t and t not in tactics:
            tactics.append(t)
    focus = focus or ", ".join(tactics[:7]) or "threat hunt"
    n_flags = len(facts["flags"])
    body = blurb or (facts.get("hunt_description") or "").split("\n")[0][:400] or "See the report."
    return (f"### 1. {emoji} [{facts['title']}]({link})\n"
            f"**Date Completed:** {facts['date_completed']}  \n"
            f"**Environment:** Cyber Range AZURE LAW  \n"
            f"**Focus:** {focus}  \n"
            f"**Flags:** {n_flags}\n\n{body}\n\n---\n\n")


def insert_index_entry(readme_text: str, entry: str) -> str:
    """
    Insert `entry` as ### 1. right under the reports header and renumber the rest.
    Idempotent: if an entry with the same title link already exists it is replaced in place.
    """
    title = re.search(r"### 1\. .*?\[(.+?)\]", entry).group(1)
    blocks = re.split(r"(?m)^(?=### \d+\. )", readme_text)
    head, rest = blocks[0], blocks[1:]
    # drop an existing block for the same title (re-publish)
    rest = [b for b in rest if f"[{title}]" not in b.split("\n", 1)[0]]
    rest.insert(0, entry)
    out = []
    for i, b in enumerate(rest, 1):
        out.append(re.sub(r"^### \d+\. ", f"### {i}. ", b, count=1))
    return head + "".join(out)
