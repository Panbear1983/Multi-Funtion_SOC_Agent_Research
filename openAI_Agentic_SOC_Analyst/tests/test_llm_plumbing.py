"""
Fast, model-free tests for the LLM plumbing fixed on 2026-09-03.

Run:  .venv/bin/python -m pytest tests -q
Each test pins one of the defects found in the audit so it cannot come back:
  - Ollama window sizing (num_ctx must cover the prompt; never silently truncate)
  - CSV-aware token estimate (tiktoken under-counted log data 2x)
  - registry/routing: every menu model resolves to a provider; retired names alias to local
  - table detection survives sampling; sampling keeps RowIds and is deterministic
  - JSON extraction tolerates fences/prose; the fallback never invents an answer
"""

import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import LLM_ROUTER
import OLLAMA_CLIENT
import RESPONSE_PARSER
import CTF_HUNT_MODE
import GUARDRAILS
import MODEL_SELECTOR


CSV_HEADER = "Timestamp,DeviceName,AccountName,ProcessCommandLine,FolderPath"


def make_csv(rows=300, needle_row=25):
    lines = [CSV_HEADER]
    for i in range(1, rows + 1):
        if i == needle_row:
            lines.append(f'2026-03-15T10:{i % 60:02d}:00Z,BRIDGE-VM01,svc_admin,"powershell.exe -enc zebra-7741",C:\\Users\\Public\\stage\\')
        else:
            lines.append(f'2026-03-15T10:{i % 60:02d}:00Z,BRIDGE-VM0{i % 9},user{i % 40},"svchost.exe -k netsvcs -p -s Schedule",C:\\Windows\\System32\\')
    return "\n".join(lines)


# ── window sizing ──────────────────────────────────────────────────────

def test_num_ctx_covers_prompt_and_output():
    ctx = OLLAMA_CLIENT.choose_num_ctx(est_tokens=10_000, num_predict=4_096, model_name="qwen3:8b")
    assert ctx >= 10_000 * 1.1 + 4_096
    assert ctx % 1024 == 0
    assert ctx <= OLLAMA_CLIENT.MAX_CTX["qwen3:8b"]


def test_num_ctx_has_floor():
    assert OLLAMA_CLIENT.choose_num_ctx(50, 512, "qwen3:8b") == OLLAMA_CLIENT.MIN_CTX


def test_prompt_too_large_raises_instead_of_truncating():
    with pytest.raises(OLLAMA_CLIENT.PromptTooLargeError):
        OLLAMA_CLIENT.choose_num_ctx(est_tokens=40_000, num_predict=4_096, model_name="qwen3:8b")


def test_router_fit_check_raises_before_calling_provider():
    big = [{"role": "user", "content": "Log Data:\n" + make_csv(rows=3000)}]
    with pytest.raises(LLM_ROUTER.PromptTooLargeError):
        LLM_ROUTER.chat(big, "qwen3:8b")


# ── token estimate ─────────────────────────────────────────────────────

def test_csv_estimate_is_conservative_vs_prose():
    csv = "Log Data:\n" + make_csv(rows=200)
    prose = "word " * (len(csv) // 5)
    assert LLM_ROUTER.estimate_tokens(csv) > LLM_ROUTER.estimate_tokens(prose) * 1.5


def test_estimate_accepts_messages_and_strings():
    msgs = [{"role": "system", "content": "hi"}, {"role": "user", "content": "there"}]
    assert LLM_ROUTER.estimate_tokens(msgs) > 0
    assert LLM_ROUTER.estimate_tokens("hello world") > 0


# ── registry / routing ─────────────────────────────────────────────────

@pytest.mark.parametrize("name", LLM_ROUTER.CLOUD_MENU + LLM_ROUTER.LOCAL_MENU)
def test_every_menu_model_has_a_provider(name):
    assert LLM_ROUTER.provider_of(name) in ("ollama", "openai", "claude")
    assert name in GUARDRAILS.ALLOWED_MODELS


@pytest.mark.parametrize("old", ["qwen", "local-mix", "gpt-oss:20b", "gemma4:26b", "gemma4:e4b", "mixtral"])
def test_retired_names_alias_to_the_one_local_model(old):
    assert LLM_ROUTER.resolve(old) == "qwen3:8b"
    assert MODEL_SELECTOR.is_offline_model(old) is True


def test_claude_names_route_to_claude():
    assert LLM_ROUTER.is_claude("claude-opus-5")
    assert LLM_ROUTER.resolve("claude") == "claude-opus-5"
    assert not MODEL_SELECTOR.is_offline_model("claude-opus-5")


def test_retired_models_are_not_in_the_menu():
    for gone in ("gemma4:26b", "gemma4:e4b", "gpt-oss:20b", "mixtral", "local-mix"):
        assert gone not in GUARDRAILS.ALLOWED_MODELS
        assert gone not in LLM_ROUTER.CLOUD_MENU + LLM_ROUTER.LOCAL_MENU


def test_local_window_is_hardware_realistic():
    assert LLM_ROUTER.context_limit("qwen3:8b") <= 32_768


# ── sampling + table detection ─────────────────────────────────────────

def test_table_detection_ignores_summary_header_and_rowid():
    csv = "# CSV DATA SUMMARY\n# Total Rows: 5\nRowId,TimeGenerated,DeviceName,AccountName,ActionType,RemoteIP,LogonType\n1,a,b,c,d,e,f"
    assert CTF_HUNT_MODE._detect_table_from_csv(csv) == "DeviceLogonEvents"


def test_table_detection_device_events():
    csv = "TimeGenerated,DeviceName,ActionType,AdditionalFields\n1,x,NamedPipeEvent,{}"
    assert CTF_HUNT_MODE._detect_table_from_csv(csv) == "DeviceEvents"


def test_sampling_keeps_needle_row_with_original_rowid_and_is_deterministic():
    csv = make_csv(rows=400, needle_row=25)
    flag = {"objective": "What command was used to download the malicious archive?", "format": "Full command line",
            "hints": ["Search DeviceProcessEvents for PowerShell executions with encoded commands"]}
    a = CTF_HUNT_MODE._smart_sample_csv_for_ctf(csv, flag["objective"], max_chars=4000, flag_intel=flag)
    b = CTF_HUNT_MODE._smart_sample_csv_for_ctf(csv, flag["objective"], max_chars=4000, flag_intel=flag)
    assert a == b, "sampling must be deterministic"
    data_lines = [l for l in a.split("\n") if l and not l.startswith("#")]
    assert data_lines[0].startswith("RowId,")
    assert any(l.startswith("25,") and "zebra-7741" in l for l in data_lines), "needle row must survive with RowId 25"
    assert len(a) <= 4000 + 400  # summary header allowance


def test_sampling_budget_scales_with_provider():
    assert CTF_HUNT_MODE._ctf_log_budget_chars("qwen3:8b") < CTF_HUNT_MODE._ctf_log_budget_chars("claude-opus-5")


# ── JSON handling ──────────────────────────────────────────────────────

def test_extract_json_handles_fences_and_prose():
    txt = 'Sure! Here you go:\n```json\n{"suggested_answer": "10.0.0.5", "confidence": "High"}\n```\nHope this helps.'
    assert LLM_ROUTER.extract_json(txt)["suggested_answer"] == "10.0.0.5"


def test_extract_json_strips_leaked_thinking():
    txt = "<think>let me reason</think>{\"a\": 1}"
    assert LLM_ROUTER.extract_json(txt) == {"a": 1}


def test_ctf_fallback_never_invents_an_answer():
    res = RESPONSE_PARSER.parse_response("The attacker used 10.0.0.5 and dropped beacon.exe", "ctf")
    assert res["suggested_answer"] == ""
    assert "10.0.0.5" in res["explanation"]


def test_ctf_parse_valid_json():
    res = RESPONSE_PARSER.parse_response(json.dumps({"suggested_answer": "azuki-adminpc", "confidence": "High",
                                                     "evidence_rows": [3], "evidence_fields": ["DeviceName"],
                                                     "explanation": "x", "correlation": ""}), "ctf")
    assert res["suggested_answer"] == "azuki-adminpc"
    assert res["evidence_rows"] == [3]


# ── CTF chat: no regex-guessed answers ─────────────────────────────────

class _FakeSession:
    def get_llm_context(self, **kw):
        return "none"


def test_refined_analysis_only_uses_explicit_answer_section():
    s = CTF_HUNT_MODE.CtfChatSession.__new__(CTF_HUNT_MODE.CtfChatSession)
    s.coach_level = 3
    s.llm_analysis = {"suggested_answer": "", "confidence": "Low"}
    s.conversation_history = [
        {"role": "user", "content": "look at rows 1-5"},
        {"role": "assistant", "content": "Row 3 shows 10.0.0.5 but I am not sure. **ANSWER EXTRACTION:**\nazuki-adminpc\n\n**CONFIDENCE:**\n[High] - clear evidence"},
    ]
    refined = s._extract_refined_analysis()
    assert refined["suggested_answer"] == "azuki-adminpc"
    assert refined["confidence"] == "High"

    s.conversation_history = [{"role": "assistant", "content": "I saw 10.0.0.5 in row 3 and beacon.exe in row 4."}]
    refined = s._extract_refined_analysis()
    assert refined["suggested_answer"] == "", "must not grab the first IP from prose"


# ── Google Form import (offline fixture = the real Bridge Takeover form) ─────

import FORM_IMPORT

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "bridge_takeover_form_data.json")


def _hunt():
    with open(FIXTURE, encoding="utf-8") as f:
        return FORM_IMPORT.parse_flags(json.load(f))


def test_form_url_normalization():
    u = FORM_IMPORT.normalize_form_url("https://docs.google.com/forms/d/e/1FAIpQLSf5PNshNzWJbp54MlIRONDzf6wpFKlydHF-KN54_NLeX1n7Iw/formResponse")
    assert u.endswith("/viewform") and "/d/e/1FAIpQLSf5PNshNzWJbp54MlIRONDzf6wpFKlydHF-KN54_NLeX1n7Iw/" in u
    with pytest.raises(FORM_IMPORT.FormImportError):
        FORM_IMPORT.normalize_form_url("https://example.com/not-a-form")


def test_form_parses_all_25_flags_in_order():
    h = _hunt()
    assert h["title"] == "AZUKI-TRADING - BRIDGE TAKEOVER"
    assert [f["number"] for f in h["flags"]] == list(range(1, 26))
    assert all(f["question"] for f in h["flags"])
    assert all(f["entry_id"] for f in h["flags"])


def test_form_flag_fields_are_split_correctly():
    f8 = _hunt()["flags"][7]
    assert f8["title"] == "FLAG 8: PERSISTENCE - Named Pipe"
    assert len(f8["hints"]) == 2 and f8["hints"][0].startswith("Query DeviceEvents")
    assert f8["format"] == "\\Device\\NamedPipe\\pipe-name"
    assert any("T1090.001" in r for r in f8["references"])
    assert f8["question"].startswith("Identify the named pipe")


def test_flag_to_intel_matches_pasted_intel_shape():
    intel = FORM_IMPORT.flag_to_intel(_hunt()["flags"][0])
    for key in ("raw_intel", "flag_number", "title", "objective", "hints", "mitre", "format"):
        assert key in intel
    assert intel["flag_number"] == 1
    assert intel["objective"].startswith("Identify the source IP")
    assert "Hint 1:" in intel["raw_intel"] and "Question:" in intel["raw_intel"]


def test_pasted_intel_parser_accepts_numbered_hints():
    class S:
        state = {"flags_completed": 0}
    intel = CTF_HUNT_MODE.parse_flag_intel("🚩 FLAG 2: X\nHint 1: look here\nHint 2: then there\nFlag Format: username\nQuestion: who?", S())
    assert intel["hints"] == ["look here", "then there"]
    assert intel["format"] == "username"
    assert intel["objective"] == "who?"


# ── KQL entry hygiene (2026-09-03: leftover paste lines were sent to Azure) ──────

def test_clean_kql_drops_leftover_intel_and_transcript_prompts():
    pasted = [
        "Reference: Ingress Tool Transfer (T1105)",
        "Flag Format: domain",
        "Question: What file hosting service was used to stage malware?",
        "KQL > KQL > DeviceNetworkEvents",
        "| where TimeGenerated between (datetime(2025-11-24) .. datetime(2026-11-25))",
        '| where DeviceName contains "azuki-adminpc"',
        "| where RemoteUrl != ''",
        "| project TimeGenerated, RemoteUrl, InitiatingProcessFileName",
        "| order by TimeGeneratedKQL > KQL >",
        "", "",
    ]
    kept, dropped = CTF_HUNT_MODE.clean_kql_lines(pasted)
    assert kept[0] == "DeviceNetworkEvents"
    assert kept[-1] == "| order by TimeGenerated"
    assert len(dropped) == 3 and all("Format" not in k for k in kept)
    assert "\n".join(kept).count("KQL >") == 0


def test_clean_kql_keeps_let_statements_and_blank_lines_inside():
    kept, dropped = CTF_HUNT_MODE.clean_kql_lines(["let start = datetime(2026-01-01);", "", "DeviceLogonEvents", "| take 5"])
    assert kept == ["let start = datetime(2026-01-01);", "", "DeviceLogonEvents", "| take 5"] and not dropped
