"""Write-up generator (model-free) - structure must match Peter's published format."""
import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import FORM_IMPORT
import REPORT_GENERATOR
import PUBLISH

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "bridge_takeover_form_data.json")


def make_state():
    with open(FIXTURE, encoding="utf-8") as f:
        hunt = FORM_IMPORT.parse_flags(json.load(f))
    return {
        "project_name": "Threat Hunt SAGA#3: Bridge Takeover",
        "hunt_form": {"url": "https://docs.google.com/forms/d/e/x/viewform", "title": hunt["title"], "description": hunt["description"]},
        "flags_planned": hunt["flags"],
        "total_flags": 25,
        "last_updated": "2026-09-03T15:00:00",
        "flags_captured": [
            {"flag_number": "1", "title": "FLAG 1: LATERAL MOVEMENT - Source System", "answer": "10.1.0.188",
             "kql_used": "DeviceLogonEvents\n| where LogonType == 'RemoteInteractive'", "table_queried": "DeviceLogonEvents",
             "notes": "QUERY OUTPUT:\n\n3/15/2026, 10:02:11.000 AM\nazuki-adminpc\nLogonSuccess\nkenji.sato\n10.1.0.188\n\nFINDING:\nThe only RemoteInteractive logon to azuki-adminpc came from 10.1.0.188, the workstation compromised in CTF 1.",
             "captured_at": "2026-09-03T14:00:00"},
            {"flag_number": "3", "title": "FLAG 3: LATERAL MOVEMENT - Target Device", "answer": "azuki-adminpc",
             "kql_used": "DeviceLogonEvents | where RemoteIP == '10.1.0.188'", "table_queried": "DeviceLogonEvents",
             "notes": "FINDING:\nDeviceName for the pivot session is azuki-adminpc.", "captured_at": "2026-09-03T14:10:00"},
        ],
        "accumulated_iocs": {"ips": ["10.1.0.188"], "devices": ["azuki-adminpc"]},
    }


def test_report_has_every_template_section_in_order():
    md = REPORT_GENERATOR.build_report(make_state(), model=None)
    order = ["# 🚩 Threat Hunt SAGA#3: Bridge Takeover", "**Sandbox Contributor:**", "## 📏 Perimeters", "## 📄 Overview",
             "## 💠 Diamond Model Analysis", "## 🥋 MITRE ATT&CK Table", "## ⛨ Remediation Actions", "## ✍️ Lessons Learned",
             "## 🏔️ Conclusion", "# 🎯 Capture The Flags", "## 🕙 Timeline of Events", "## 🚩 Completed Flag Map",
             "### 🚩 Flag 1: LATERAL MOVEMENT - Source System", "### 🚩 Flag 3: LATERAL MOVEMENT - Target Device", "## 🔎 Analyst Workflow"]
    pos = [md.index(h) for h in order]
    assert pos == sorted(pos), "sections out of order"


def test_flag_block_is_filled_from_form_and_session():
    md = REPORT_GENERATOR.build_report(make_state(), model=None)
    block = md[md.index("### 🚩 Flag 1:"):md.index("### 🚩 Flag 3:")]
    assert "**Objective:** Identify the source IP address for lateral movement to the admin PC?" in block
    assert "**Hint 1:** Query DeviceLogonEvents" in block and "**Hint 2:**" in block
    assert "```kql" in block and "RemoteInteractive" in block
    assert "**Output:** `10.1.0.188`" in block
    assert "compromised in CTF 1" in block and "QUERY OUTPUT" not in block, "finding prose in, pasted rows out"
    assert REPORT_GENERATOR.SHOT in block


def test_mitre_table_uses_form_references():
    md = REPORT_GENERATOR.build_report(make_state(), model=None)
    assert "| Lateral Movement | 3 | Lateral Movement | **T1082** | System Information Discovery |" in md


def test_perimeters_and_map():
    md = REPORT_GENERATOR.build_report(make_state(), model=None)
    assert "Primary Impacted Host: `azuki-adminpc`" in md
    assert "Hunt Link: [Cyber Range SOC - AZUKI-TRADING - BRIDGE TAKEOVER]" in md
    assert "| **1** | LATERAL MOVEMENT - Source System | 10.1.0.188 |" in md
    assert md.count(REPORT_GENERATOR.DRAFT) >= 5, "every narrative section is marked DRAFT when no model ran"


def test_filename_matches_convention():
    assert REPORT_GENERATOR.default_filename(make_state()) == "(CTF) Threat Hunt SAGA#3: Bridge Takeover.md"
    assert PUBLISH.slugify("Threat Hunt SAGA#3: Bridge Takeover") == "saga-3-bridge-takeover"


# ── generator fixes + hunt index (2026-09-05) ──────────────────────────────

def test_timestamps_are_normalised_and_tactic_ids_accepted():
    st = make_state()
    st["flags_captured"][0]["notes"] = "QUERY OUTPUT:\n11/25/2025, 6:09:18.203 AM\nazuki-adminpc\n\nFINDING:\nok"
    facts = REPORT_GENERATOR.collect_facts(st)
    f1 = facts["flags"][0]
    assert f1["timestamp"] == "2025-11-25 06:09:18"
    assert facts["date_range"] == "2025-11-25 to 2025-11-25"
    assert ("TA0008", "Lateral Movement (tactic)") in f1["techniques"]


def test_device_guess_never_picks_ordinary_words():
    assert REPORT_GENERATOR._device_hint("rows 1-5 show nothing", "the ws value") == ""
    assert REPORT_GENERATOR._device_hint("logon to azuki-adminpc at 06:09") == "azuki-adminpc"


INDEX_FIXTURE = """# 🎯 Threat Hunting Projects - CTF Collection

Intro paragraph.

## 📚 Threat Hunt Reports

### 1. 🚢 [Threat Hunt SAGA#2: Cargo Hold](./x.md)
**Flags:** 20

blurb

---

### 2. 🚪 [Threat Hunt SAGA#1: Port of Entry](./y.md)
**Flags:** 20

blurb

---

## 🎓 Learning Objectives

- **Initial Access Techniques:** RDP
"""


def test_index_entry_shape_and_insertion_renumbers():
    st = make_state()
    entry = REPORT_GENERATOR.index_entry(st, emoji="🌉", focus="RDP pivot, C2, exfiltration", blurb="Third act.")
    assert entry.startswith("### 1. 🌉 [Threat Hunt SAGA#3: Bridge Takeover](./%28CTF%29%20Threat%20Hunt%20SAGA%233%3A%20Bridge%20Takeover.md)")
    assert "**Flags:** 2" in entry and "**Date Completed:** 2026-09-03" in entry
    out = REPORT_GENERATOR.insert_index_entry(INDEX_FIXTURE, entry)
    heads = [l for l in out.splitlines() if l.startswith("### ")]
    assert heads[0].startswith("### 1. 🌉 [Threat Hunt SAGA#3")
    assert heads[1].startswith("### 2. 🚢 [Threat Hunt SAGA#2") and heads[2].startswith("### 3. 🚪 [Threat Hunt SAGA#1")
    assert "## 🎓 Learning Objectives" in out and out.index("Learning Objectives") > out.index("### 3.")


def test_index_insertion_is_idempotent():
    st = make_state()
    entry = REPORT_GENERATOR.index_entry(st, blurb="v1")
    once = REPORT_GENERATOR.insert_index_entry(INDEX_FIXTURE, entry)
    twice = REPORT_GENERATOR.insert_index_entry(once, REPORT_GENERATOR.index_entry(st, blurb="v2"))
    assert twice.count("Threat Hunt SAGA#3") == 1 and "v2" in twice and "v1" not in twice
    assert [l[:6] for l in twice.splitlines() if l.startswith("### ")] == ["### 1.", "### 2.", "### 3."]


# ── full publish chain: draft -> PR -> merge -> profile page (2026-09-07) ──────

def test_draft_and_render_split_matches_build_report():
    st = make_state()
    combined = REPORT_GENERATOR.build_report(st, model=None)
    facts, nar = REPORT_GENERATOR.draft_facts_and_narrative(st, model=None)
    split = REPORT_GENERATOR.render_report(facts, nar)
    assert combined == split


def test_profile_bullet_format_and_encoding():
    st = make_state()
    facts, _ = REPORT_GENERATOR.draft_facts_and_narrative(st, model=None)
    nar = {"profile_intro": "a scripted proof that the bullet format matches the profile page."}
    bullet = REPORT_GENERATOR.profile_bullet(facts, nar)
    assert bullet.startswith("- **[Threat Hunt SAGA#3: Bridge Takeover](<https://github.com/Panbear1983/"
                             "Multi-Funtion_SOC_Agent_Research/blob/main/Threat_Hunting_Projects/"
                             "%28CTF%29%20Threat%20Hunt%20SAGA%233%3A%20Bridge%20Takeover.md>)** — ")
    assert bullet.rstrip().endswith("profile page.")


def test_profile_bullet_falls_back_without_a_narrative():
    st = make_state()
    facts, _ = REPORT_GENERATOR.draft_facts_and_narrative(st, model=None)
    bullet = REPORT_GENERATOR.profile_bullet(facts, {})
    assert "see the write-up" in bullet


def test_narrative_schema_requires_profile_intro():
    assert "profile_intro" in REPORT_GENERATOR.NARRATIVE_SCHEMA["required"]
    assert REPORT_GENERATOR.NARRATIVE_SCHEMA["properties"]["profile_intro"]["type"] == "string"


def test_merge_calls_gh_pr_merge_with_the_branch(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(PUBLISH, "_run", lambda cmd, cwd, check=True: calls.append((cmd, cwd)) or "Merged")
    PUBLISH.merge("threat-hunt-x-20260907", root=str(tmp_path))
    assert calls == [(["gh", "pr", "merge", "threat-hunt-x-20260907", "--merge"], str(tmp_path))]


def test_publish_returns_url_and_branch_tuple(tmp_path, monkeypatch):
    report = tmp_path / "report.md"; report.write_text("hi")

    def fake_run(cmd, cwd, check=True):
        if cmd == ["git", "rev-parse", "--abbrev-ref", "HEAD"]:
            return "main"
        if cmd[:3] == ["git", "branch", "--list"]:
            return ""
        if cmd == ["git", "diff", "--cached", "--name-only"]:
            return "report.md"
        if cmd[:3] == ["gh", "pr", "create"]:
            return "https://github.com/x/y/pull/9"
        return ""
    monkeypatch.setattr(PUBLISH, "_run", fake_run)
    url, branch = PUBLISH.publish(str(report), title="Threat Hunt SAGA#9: Test", root=str(tmp_path))
    assert url == "https://github.com/x/y/pull/9"
    assert branch == "threat-hunt-saga-9-test-" + __import__("datetime").datetime.now().strftime("%Y%m%d")


def _init_profile_repo(tmp_path, dirty=False):
    root = tmp_path / "profile"
    root.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=root, check=True)
    (root / "README.md").write_text(
        "# Peter\n\n### Threat Hunting Case Studies\n\nIntro line.\n\n"
        "- **[Old Hunt](<https://x/old.md>)** — an old one.\n\n## Applied Automation\n\nMore text.\n"
    )
    subprocess.run(["git", "add", "README.md"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=root, check=True)
    origin = tmp_path / "profile-origin.git"
    subprocess.run(["git", "clone", "-q", "--bare", str(root), str(origin)], check=True)
    subprocess.run(["git", "remote", "add", "origin", str(origin)], cwd=root, check=True)
    subprocess.run(["git", "push", "-q", "-u", "origin", "main"], cwd=root, check=True)
    if dirty:
        (root / "README.md").write_text((root / "README.md").read_text() + "\nuncommitted local edit\n")
    return root, origin


def test_update_profile_page_inserts_before_next_section_and_pushes(tmp_path):
    root, origin = _init_profile_repo(tmp_path)
    bullet = "- **[New Hunt](<https://x/new.md>)** — a brand new case study."
    path = PUBLISH.update_profile_page(bullet, profile_root=str(root))
    text = open(path).read()
    assert text.index("Old Hunt") < text.index("New Hunt") < text.index("Applied Automation")
    pushed = subprocess.run(["git", "show", "main:README.md"], cwd=origin, capture_output=True, text=True, check=True).stdout
    assert "New Hunt" in pushed


def test_update_profile_page_is_idempotent(tmp_path):
    root, _ = _init_profile_repo(tmp_path)
    bullet = "- **[New Hunt](<https://x/new.md>)** — first version of the intro."
    PUBLISH.update_profile_page(bullet, profile_root=str(root))
    before = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True).stdout
    PUBLISH.update_profile_page("- **[New Hunt](<https://x/new.md>)** — a different intro text.", profile_root=str(root))
    after = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True).stdout
    assert before == after   # same title link already present -> no second commit


def test_update_profile_page_refuses_when_dirty(tmp_path):
    root, _ = _init_profile_repo(tmp_path, dirty=True)
    with pytest.raises(PUBLISH.PublishError, match="uncommitted changes"):
        PUBLISH.update_profile_page("- **[X](<y>)** — z.", profile_root=str(root))
    assert "New Hunt" not in (root / "README.md").read_text()


def test_update_profile_page_refuses_without_a_repo(tmp_path):
    with pytest.raises(PUBLISH.PublishError, match="No git repo"):
        PUBLISH.update_profile_page("- **[X](<y>)** — z.", profile_root=str(tmp_path / "nope"))
