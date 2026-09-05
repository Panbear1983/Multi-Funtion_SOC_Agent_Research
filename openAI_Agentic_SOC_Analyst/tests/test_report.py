"""Write-up generator (model-free) - structure must match Peter's published format."""
import json
import os
import sys

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
