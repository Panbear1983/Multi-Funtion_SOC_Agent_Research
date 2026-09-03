"""
CTF Hunt Mode V3 - Human-Driven with LLM Advisory
Major redesign: Human writes KQL, LLM provides guidance

Canonical implementation: This module is the single active CTF Hunt Mode.
Legacy variants have been archived under `archive/` and are no longer
imported or maintained.

Model access goes through LLM_ROUTER (local qwen3:8b, OpenAI, or Claude) so the
same code path serves every provider and every call is logged.
"""

import json
import os
import re
import glob
import time
from datetime import timedelta, datetime

from color_support import Fore
import CTF_SESSION_MANAGER
import GUARDRAILS
import LLM_ROUTER
import AZURE_SCHEMA_REFERENCE
import FORM_IMPORT
import EVIDENCE_FILTER
import PROMPT_MANAGEMENT
import REPORT_GENERATOR
import PUBLISH
import pandas as pd


def is_local_model(model_name):
    """Determine if a model is local/Ollama (any alias) or cloud"""
    return LLM_ROUTER.is_local(model_name) if model_name else False


def get_ollama_model_name(model_name):
    """Map friendly / legacy model names to the canonical registry name"""
    return LLM_ROUTER.resolve(model_name)


COACH_LEVELS = {
    1: "GUIDE   - the AI says where to look and what pattern to filter; it never shows candidate values",
    2: "NARROW  - the AI also lists a few candidate values with their row numbers, unranked",
    3: "REVEAL  - the AI shows its best answer with evidence (also reachable per flag with /reveal)",
}


def coach_level(session) -> int:
    try:
        return int(session.state.get('coach_level', 1))
    except (TypeError, ValueError):
        return 1


def set_coach_level(session, level: int):
    session.state['coach_level'] = max(1, min(3, int(level)))
    session.save_state()


def prompt_coach_level(session):
    """Ask how much help the AI may give (Peter: 'challenging without serving up the answer')."""
    print(f"\n{Fore.LIGHTCYAN_EX}How much should the AI coach reveal by default?{Fore.RESET}")
    for n, d in COACH_LEVELS.items():
        print(f"  {Fore.LIGHTGREEN_EX}[{n}]{Fore.RESET} {d}")
    print(f"{Fore.LIGHTBLACK_EX}You can always type /hint (one level up) or /reveal in the chat for a single flag.{Fore.RESET}")
    try:
        choice = input(f"{Fore.LIGHTGREEN_EX}Coach level [1]: {Fore.RESET}").strip()
    except (KeyboardInterrupt, EOFError):
        choice = ""
    set_coach_level(session, int(choice) if choice in ("1", "2", "3") else 1)
    print(f"{Fore.LIGHTGREEN_EX}✓ Coach level {coach_level(session)}{Fore.RESET}\n")


def run_ctf_hunt(openai_client, law_client, workspace_id, timerange_hours, start_date, end_date,
                 model=None, severity_config=None):
    """
    Human-driven CTF hunting with LLM advisory
    - Human writes all KQL queries
    - Uses Azure Sentinel / Log Analytics exclusively (longer data retention)
    - LLM provides interpretation and guidance
    - Complete documentation of hunt process
    """
    
    # DEBUG: Verify client received
    print(f"{Fore.LIGHTYELLOW_EX}🔍 DEBUG run_ctf_hunt: Received law_client type = '{type(law_client).__name__}'{Fore.RESET}")
    print(f"{Fore.LIGHTYELLOW_EX}🔍 DEBUG run_ctf_hunt: Has query_workspace = {hasattr(law_client, 'query_workspace')}{Fore.RESET}")
    print(f"{Fore.LIGHTYELLOW_EX}🔍 DEBUG run_ctf_hunt: Has query_advanced_hunting = {hasattr(law_client, 'query_advanced_hunting')}{Fore.RESET}")
    print(f"{Fore.LIGHTYELLOW_EX}🔍 DEBUG run_ctf_hunt: workspace_id = '{workspace_id}'{Fore.RESET}\n")
    
    # ═══════════════════════════════════════════════════════════════
    # CHECK FOR EXISTING SESSIONS
    # ═══════════════════════════════════════════════════════════════
    
    existing_sessions = find_existing_sessions()
    
    if existing_sessions:
        session = prompt_resume_or_new(existing_sessions)
        
        if session:
            # Resumed existing session
            project_name = session.state.get('project_name', 'CTF Hunt')
            print(f"\n{Fore.LIGHTGREEN_EX}✓ Resumed: {project_name}{Fore.RESET}")
            print(f"{Fore.WHITE}Flags captured so far: {session.state['flags_completed']}{Fore.RESET}\n")
        else:
            # User selected 'N' - create new session
            session = create_new_session()
    else:
        # No existing sessions - create new
        session = create_new_session()
    
    # ═══════════════════════════════════════════════════════════════
    # MAIN FLAG HUNTING LOOP
    # ═══════════════════════════════════════════════════════════════
    
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}🏆 DYNAMIC CTF ASSISTANT")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    print(f"{Fore.WHITE}Work through CTF flags one at a time.{Fore.RESET}")
    print(f"{Fore.WHITE}You write KQL, LLM provides guidance and interpretation.{Fore.RESET}\n")
    
    try:
        while True:
            # For first flag, skip menu and start hunting
            if session.state['flags_completed'] == 0:
                flag_captured = hunt_single_flag(
                    session, openai_client, law_client, workspace_id,
                    timerange_hours, start_date, end_date, model, severity_config
                )
                
                if not flag_captured:
                    print(f"{Fore.YELLOW}Hunt cancelled.{Fore.RESET}")
                    break
                
                continue
            
            # Show session context if flags already captured
            if session.state['flags_completed'] > 0:
                display_session_context(session)
            
            # Ask what to do next
            action = prompt_next_action(session)
            
            if action == 'new_flag':
                flag_captured = hunt_single_flag(
                    session, openai_client, law_client, workspace_id,
                    timerange_hours, start_date, end_date, model, severity_config
                )
                
                if not flag_captured:
                    continue
            
            elif action == 'delete_and_redo':
                # Flag already deleted, just continue to hunt it again
                flag_captured = hunt_single_flag(
                    session, openai_client, law_client, workspace_id,
                    timerange_hours, start_date, end_date, model, severity_config
                )
                
                if not flag_captured:
                    continue
            
            elif action == 'pause':
                print(f"\n{Fore.LIGHTCYAN_EX}💾 Pausing investigation...{Fore.RESET}\n")
                session.state['status'] = 'in_progress'
                session.save_state()
                print(f"{Fore.LIGHTGREEN_EX}✓ Session paused. You can resume later.{Fore.RESET}\n")
                break
            
            elif action == 'writeup':
                writeup_stage(session, model=model, openai_client=openai_client)
                continue

            elif action == 'finish':
                # Flag logic flow stage
                flag_logic_flow_stage(session)
                session.state['status'] = 'completed'
                session.save_state()
                writeup_stage(session, model=model, openai_client=openai_client)
                break
    
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}{'='*70}")
        print(f"{Fore.YELLOW}Hunt interrupted (Ctrl+C)")
        print(f"{Fore.YELLOW}{'='*70}{Fore.RESET}\n")
        session.state['status'] = 'interrupted'
    
    # Final save
    session.save_state()
    
    print(f"{Fore.LIGHTCYAN_EX}💾 Session saved{Fore.RESET}")
    print(f"{Fore.LIGHTGREEN_EX}✓ State: {session.state_file}{Fore.RESET}")
    print(f"{Fore.LIGHTGREEN_EX}✓ Event log: {session.event_log}{Fore.RESET}\n")
    
    if session.state['status'] == 'completed':
        show_final_summary(session)
        report_path = session.generate_report()
        return session.state, report_path
    else:
        print(f"Session paused. Resume anytime by selecting CTF mode again.\n")
        return None, None


# ═══════════════════════════════════════════════════════════════
# MAIN FLAG HUNTING FUNCTION
# ═══════════════════════════════════════════════════════════════

def hunt_single_flag(session, openai_client, law_client, workspace_id, 
                     timerange_hours, start_date, end_date, model=None, severity_config=None):
    """
    Hunt a single flag - human-driven with LLM advisory
    Uses Azure Sentinel / Log Analytics exclusively
    """
    
    # ═══════════════════════════════════════════════════════════════
    # STAGE 1: FLAG INTEL CAPTURE
    # ═══════════════════════════════════════════════════════════════
    
    flag_intel = capture_flag_intel_stage(session)
    
    if flag_intel is None:
        return False
    
    # ═══════════════════════════════════════════════════════════════
    # MODEL & SEVERITY SELECTION (After Stage 1, before Stage 2)
    # User sees flag intel, then selects model for analysis
    # ═══════════════════════════════════════════════════════════════
    
    if model is None:
        print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
        print(f"{Fore.LIGHTCYAN_EX}SELECT LANGUAGE MODEL")
        print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
        print(f"{Fore.WHITE}Flag Intel Captured:{Fore.RESET}")
        print(f"{Fore.LIGHTYELLOW_EX}  Title: {flag_intel.get('title', 'Unnamed Flag')}{Fore.RESET}")
        if flag_intel.get('objective'):
            obj_preview = flag_intel.get('objective', '')
            if len(obj_preview) > 80:
                print(f"{Fore.WHITE}  Objective: {obj_preview[:80]}...{Fore.RESET}")
            else:
                print(f"{Fore.WHITE}  Objective: {obj_preview}{Fore.RESET}")
        if flag_intel.get('hints'):
            hints_display = ', '.join(flag_intel.get('hints', [])[:2])
            if len(flag_intel.get('hints', [])) > 2:
                hints_display += '...'
            print(f"{Fore.WHITE}  Hints: {hints_display}{Fore.RESET}")
        print(f"\n{Fore.LIGHTBLACK_EX}This model will be used for:{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}  • Bot's Intel Interpretation (Stage 2){Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}  • LLM Result Analysis (Stage 6){Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}  • Interactive LLM Conversation (Stage 7){Fore.RESET}\n")
        
        import MODEL_SELECTOR
        model = MODEL_SELECTOR.prompt_model_selection(input_tokens=None)
        session.state['model'] = model          # remembered for the write-up stage
        session.save_state()
        
        # Also select severity if not provided
        if severity_config is None:
            import SEVERITY_LEVELS
            severity_level = SEVERITY_LEVELS.prompt_severity_selection()
            severity_config = SEVERITY_LEVELS.get_severity_config(severity_level)
            SEVERITY_LEVELS.display_severity_banner(severity_level)
            
            # Select framework profile and merge into severity config
            import COMPLIANCE_PROFILES
            profile_key = COMPLIANCE_PROFILES.prompt_profile_selection()
            severity_config = COMPLIANCE_PROFILES.apply_profile(severity_config, profile_key)
    
    # ═══════════════════════════════════════════════════════════════
    # STAGE 2: BOT'S INTEL INTERPRETATION (uses selected model)
    # ═══════════════════════════════════════════════════════════════
    
    bot_guidance = bot_interpretation_stage(flag_intel, session, openai_client, model)
    
    if bot_guidance is None:
        return False
    
    # ═══════════════════════════════════════════════════════════════
    # STAGES 3-10: KQL ENTRY → EXECUTION → RESULTS → LLM ANALYSIS → CONVERSATION → DOCUMENTATION
    # Loop allows rewriting KQL without redoing intel capture
    # ═══════════════════════════════════════════════════════════════
    
    llm_analysis = None  # Track LLM analysis across loop iterations
    
    while True:
        # STAGE 3: HUMAN WRITES KQL
        kql_query = human_kql_entry_stage(bot_guidance)
        
        if kql_query is None:
            return False
        
        # STAGE 4: EXECUTE QUERY
        results = execution_stage(kql_query, law_client, workspace_id, timerange_hours,
                                 start_date, end_date, flag_intel)
        
        if results is None:
            retry = input(f"\n{Fore.YELLOW}Query failed. Retry? [Y/n]: {Fore.RESET}").strip().lower()
            if retry not in ['n', 'no']:
                continue  # Back to Stage 3 (KQL entry)
            return False
        
        # STAGE 5: RESULTS DISPLAY (Paginated)
        display_results_paginated(results)
        
        # STAGE 7: LLM RESULT ANALYSIS (NEW)
        print(f"\n{Fore.LIGHTCYAN_EX}Would you like the LLM to analyze these results?{Fore.RESET}")
        analyze_choice = input(f"{Fore.WHITE}Run LLM analysis? [Y/n]: {Fore.RESET}").strip().lower()
        
        if analyze_choice not in ['n', 'no']:
            llm_analysis = llm_result_analysis_stage(
                results_csv=results,
                flag_intel=flag_intel,
                kql_query=kql_query,
                session=session,
                openai_client=openai_client,
                model=model,
                severity_config=severity_config
            )
            
            if llm_analysis:
                # STAGE 8: INTERACTIVE LLM CONVERSATION (Dynamic based on model + confidence)
                import MODEL_SELECTOR
                is_offline = MODEL_SELECTOR.is_offline_model(model) if model else False
                confidence = llm_analysis.get('confidence', 'Low').lower()
                low_confidence = confidence in ['low', 'medium']
                
                # Option 2: Dynamic opening based on model + confidence
                # - Local models + Low confidence → Auto-open (needs refinement)
                # - Local models + High confidence → Prompt user (optional refinement)
                # - Cloud models → Always prompt (costs money)
                
                if is_offline and low_confidence:
                    # Local model + Low confidence → Auto-open chat for refinement
                    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
                    print(f"{Fore.LIGHTCYAN_EX}💬 AUTO-OPENING INTERACTIVE CONVERSATION")
                    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}")
                    print(f"{Fore.WHITE}Analysis confidence is {Fore.YELLOW}{confidence.upper()}{Fore.WHITE} - Opening chat for refinement")
                    print(f"{Fore.LIGHTGREEN_EX}Model: {model} (FREE - No API costs){Fore.RESET}\n")
                    
                    refined_analysis = interactive_llm_conversation_stage(
                        llm_analysis=llm_analysis,
                        results_csv=results,
                        flag_intel=flag_intel,
                        kql_query=kql_query,
                        session=session,
                        openai_client=openai_client,
                        model=model,
                        bot_guidance=bot_guidance  # Include bot's intel interpretation
                    )
                    if refined_analysis:
                        llm_analysis = refined_analysis  # Update with refined analysis
                
                elif is_offline and not low_confidence:
                    # Local model + High confidence → Prompt user (optional refinement)
                    print(f"\n{Fore.LIGHTCYAN_EX}Would you like to refine the analysis?{Fore.RESET}")
                    print(f"{Fore.WHITE}Confidence: {Fore.LIGHTGREEN_EX}{confidence.upper()}{Fore.WHITE} | Model: {Fore.LIGHTGREEN_EX}{model} (FREE){Fore.RESET}")
                    conv_choice = input(f"{Fore.WHITE}Start interactive conversation? [Y/n]: {Fore.RESET}").strip().lower()
                    
                    if conv_choice not in ['n', 'no']:
                        refined_analysis = interactive_llm_conversation_stage(
                            llm_analysis=llm_analysis,
                            results_csv=results,
                            flag_intel=flag_intel,
                            kql_query=kql_query,
                            session=session,
                            openai_client=openai_client,
                            model=model,
                            bot_guidance=bot_guidance  # Include bot's intel interpretation
                        )
                        if refined_analysis:
                            llm_analysis = refined_analysis  # Update with refined analysis
                
                else:
                    # Cloud model → Always prompt (costs money)
                    print(f"\n{Fore.LIGHTCYAN_EX}Would you like to have a conversation with the LLM about these results?{Fore.RESET}")
                    print(f"{Fore.LIGHTYELLOW_EX}Note: This will use {model} API calls (costs apply){Fore.RESET}")
                    conv_choice = input(f"{Fore.WHITE}Start interactive conversation? [Y/n]: {Fore.RESET}").strip().lower()
                    
                    if conv_choice not in ['n', 'no']:
                        refined_analysis = interactive_llm_conversation_stage(
                            llm_analysis=llm_analysis,
                            results_csv=results,
                            flag_intel=flag_intel,
                            kql_query=kql_query,
                            session=session,
                            openai_client=openai_client,
                            model=model,
                            bot_guidance=bot_guidance  # Include bot's intel interpretation
                        )
                        if refined_analysis:
                            llm_analysis = refined_analysis  # Update with refined analysis
        
        # STAGE 9: RESULT DOCUMENTATION MENU
        doc_action = result_documentation_menu(llm_analysis=llm_analysis)
        
        if doc_action == 'rewrite_kql':
            # Loop back to Stage 3 (HUMAN KQL ENTRY)
            print(f"\n{Fore.LIGHTCYAN_EX}Returning to KQL entry...{Fore.RESET}\n")
            llm_analysis = None  # Reset LLM analysis for new query
            continue  # Back to Stage 3
        
        elif doc_action == 'use_llm_answer':
            # Use LLM's suggested answer directly
            if llm_analysis and llm_analysis.get("suggested_answer"):
                answer = llm_analysis.get("suggested_answer")
                explanation = llm_analysis.get("explanation", "")
                evidence_rows = llm_analysis.get("evidence_rows", [])
                
                # Extract evidence rows from CSV
                import io
                query_output = "LLM Suggested Answer (auto-extracted)"
                try:
                    df = pd.read_csv(io.StringIO(results))
                    evidence_lines = []
                    for row_idx in evidence_rows:
                        if 0 <= row_idx < len(df):
                            evidence_lines.append(df.iloc[row_idx].to_string())
                    if evidence_lines:
                        query_output = '\n'.join(evidence_lines)
                except:
                    pass
                
                structured_notes = f"""QUERY OUTPUT:
{query_output}

FINDING (LLM Analysis):
{explanation}
"""
                
                session.capture_flag(
                    flag_number=flag_intel['flag_number'],
                    title=flag_intel['title'],
                    answer=answer,
                    notes=structured_notes,
                    kql_used=kql_query,
                    table_queried='',
                    stage=flag_intel.get('mitre', '').split('-')[0].strip() if '-' in flag_intel.get('mitre', '') else '',
                    mitre=flag_intel.get('mitre', '')
                )
                
                print(f"\n{Fore.LIGHTGREEN_EX}{'='*70}")
                print(f"{Fore.LIGHTGREEN_EX}✓ FLAG {flag_intel['flag_number']} CAPTURED: {answer}")
                print(f"{Fore.LIGHTGREEN_EX}{'='*70}{Fore.RESET}\n")
                
                return True
        
        elif doc_action == 'document':
            # Document the result for JSON
            documented = document_result_stage(flag_intel, session, kql_query, results, llm_analysis=llm_analysis)
            if not documented:
                return False
            
            return True  # Flag completed, exit loop
        
        return False


# ═══════════════════════════════════════════════════════════════
# STAGE 1: FLAG INTEL CAPTURE (Keep existing)
# ═══════════════════════════════════════════════════════════════


def import_hunt_form_into_session(session, url=None):
    """
    Pull every flag from the hunt's Google Form link into the session so no question
    ever has to be copied by hand. Returns True on success.
    """
    if url is None:
        print(f"\n{Fore.LIGHTCYAN_EX}Paste the hunt's Google Form link (viewform or formResponse), or press Enter to skip:{Fore.RESET}")
        try:
            url = input(f"{Fore.LIGHTGREEN_EX}Form link: {Fore.RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            url = ""
    if not url:
        return False
    try:
        hunt = FORM_IMPORT.import_hunt(url)
    except FORM_IMPORT.FormImportError as e:
        print(f"{Fore.RED}Import failed: {e}{Fore.RESET}\n")
        return False
    session.state['hunt_form'] = {"url": hunt["url"], "title": hunt["title"], "description": hunt["description"],
                                  "imported_at": hunt["imported_at"]}
    session.state['flags_planned'] = hunt["flags"]
    session.state['total_flags'] = len(hunt["flags"])
    session.save_state()
    print(f"\n{Fore.LIGHTGREEN_EX}✓ Imported {len(hunt['flags'])} flags from \"{hunt['title']}\"{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}{FORM_IMPORT.summarize(hunt)}{Fore.RESET}\n")
    return True


def _planned_flag_status(session):
    """(planned flags, set of captured flag numbers)"""
    planned = session.state.get('flags_planned') or []
    captured = set()
    for f in session.state.get('flags_captured', []):
        try:
            captured.add(int(str(f.get('flag_number', '')).strip()))
        except ValueError:
            pass
    return planned, captured


def _pick_planned_flag(session):
    """Show the imported flag list and let the analyst choose one (default: next pending)."""
    planned, captured = _planned_flag_status(session)
    pending = [f for f in planned if f['number'] not in captured]
    default = pending[0]['number'] if pending else None

    flush_typeahead()
    print(f"{Fore.WHITE}Flags in this hunt ({session.state.get('hunt_form', {}).get('title', '')}):{Fore.RESET}")
    for f in planned:
        mark = f"{Fore.LIGHTGREEN_EX}✓" if f['number'] in captured else f"{Fore.LIGHTBLACK_EX}·"
        q = f.get('question') or f.get('what_to_hunt', '')
        print(f"  {mark} {Fore.WHITE}{f['number']:>2}. {f['name']}{Fore.LIGHTBLACK_EX}  {q[:60]}{'...' if len(q) > 60 else ''}{Fore.RESET}")
    print(f"\n{Fore.LIGHTBLACK_EX}Enter a flag number, Enter for flag {default if default else '-'}, or P to paste intel manually{Fore.RESET}")
    while True:
        try:
            choice = input(f"{Fore.LIGHTGREEN_EX}Flag: {Fore.RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            return None
        if choice.upper() == 'P':
            return 'paste'
        if not choice:
            if default is None:
                print(f"{Fore.YELLOW}All flags are captured. Enter a number to redo one, or P to paste.{Fore.RESET}")
                continue
            choice = str(default)
        if choice.isdigit():
            n = int(choice)
            match = next((f for f in planned if f['number'] == n), None)
            if match:
                if n in captured:
                    print(f"{Fore.YELLOW}Flag {n} is already captured - working on it again.{Fore.RESET}")
                return FORM_IMPORT.flag_to_intel(match, flag_number=n)
        print(f"{Fore.RED}Enter a valid flag number, or P.{Fore.RESET}")


def capture_flag_intel_stage(session):
    """Capture flag objective and intel from user"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}📋 FLAG {session.state['flags_completed'] + 1} INTEL CAPTURE")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")

    # Imported hunt (Google Form): pick the flag instead of pasting it
    if session.state.get('flags_planned'):
        picked = _pick_planned_flag(session)
        if picked is None:
            print(f"\n{Fore.YELLOW}Cancelled{Fore.RESET}")
            return None
        if picked != 'paste':
            print(f"\n{Fore.LIGHTGREEN_EX}✓ Flag intel loaded from the hunt form{Fore.RESET}")
            print(f"{Fore.WHITE}Title: {Fore.LIGHTYELLOW_EX}{picked['title']}{Fore.RESET}")
            print(f"{Fore.WHITE}Question: {Fore.LIGHTYELLOW_EX}{picked['objective']}{Fore.RESET}")
            if picked.get('format'):
                print(f"{Fore.WHITE}Format: {Fore.LIGHTYELLOW_EX}{picked['format']}{Fore.RESET}")
            for i, h in enumerate(picked.get('hints', []), 1):
                print(f"{Fore.WHITE}Hint {i}: {Fore.LIGHTBLACK_EX}{h}{Fore.RESET}")
            print()
            return picked
    elif not session.state.get('hunt_form_declined'):
        print(f"{Fore.LIGHTBLACK_EX}Tip: import the whole hunt from its Google Form link once, then just pick flags.{Fore.RESET}")
        if import_hunt_form_into_session(session):
            return capture_flag_intel_stage(session)
        session.state['hunt_form_declined'] = True
    
    flush_typeahead()
    print(f"{Fore.WHITE}Paste the flag intel below. End with the exact question to answer.{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}Include:{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  • Flag title")
    print(f"{Fore.LIGHTBLACK_EX}  • Context, hints, MITRE techniques, expected format")
    print(f"{Fore.LIGHTBLACK_EX}  • At the end: the exact flag question (e.g. Question: ... or Objective: ...)")
    print(f"{Fore.LIGHTBLACK_EX}Type 'DONE' on a new line when finished{Fore.RESET}\n")
    
    print(f"{Fore.LIGHTCYAN_EX}Example:{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}{'─'*70}")
    print(f"{Fore.LIGHTBLACK_EX}🚩 Flag 1: Attacker IP Address")
    print(f"{Fore.LIGHTBLACK_EX}MITRE: T1110.001 - Brute Force")
    print(f"{Fore.LIGHTBLACK_EX}Hint: Look for failed logins followed by success")
    print(f"{Fore.LIGHTBLACK_EX}Format: xxx.xxx.xxx.xxx")
    print(f"{Fore.LIGHTBLACK_EX}Question: What was the external IP that successfully logged in after the brute force?")
    print(f"{Fore.LIGHTBLACK_EX}DONE")
    print(f"{Fore.LIGHTBLACK_EX}{'─'*70}{Fore.RESET}\n")
    
    intel_lines = []
    
    try:
        while True:
            line = input()
            if line.strip().upper() == 'DONE':
                break
            intel_lines.append(line)
    except (KeyboardInterrupt, EOFError):
        print(f"\n{Fore.YELLOW}Cancelled{Fore.RESET}")
        return None
    
    if not intel_lines:
        print(f"{Fore.YELLOW}No intel provided. Skipping flag.{Fore.RESET}")
        return None
    
    intel_text = '\n'.join(intel_lines)
    
    # Parse intel
    flag_intel = parse_flag_intel(intel_text, session)
    
    print(f"\n{Fore.LIGHTGREEN_EX}✓ Flag intel captured{Fore.RESET}")
    print(f"{Fore.WHITE}Title: {Fore.LIGHTYELLOW_EX}{flag_intel.get('title', 'Unnamed Flag')}{Fore.RESET}")
    if flag_intel.get('objective'):
        obj_preview = flag_intel['objective'][:80] + ('...' if len(flag_intel['objective']) > 80 else '')
        print(f"{Fore.WHITE}Question: {Fore.LIGHTYELLOW_EX}{obj_preview}{Fore.RESET}\n")
    else:
        print(f"{Fore.LIGHTBLACK_EX}(No question/objective parsed — add 'Question: ...' or 'Objective: ...' at end of intel){Fore.RESET}\n")
    
    return flag_intel


def parse_flag_intel(intel_text, session):
    """Parse pasted intel to extract structured information"""
    
    intel = {
        'raw_intel': intel_text,
        'flag_number': session.state['flags_completed'] + 1,
        'title': 'Flag ' + str(session.state['flags_completed'] + 1),
        'objective': '',
        'hints': [],
        'mitre': '',
        'format': ''
    }
    
    lines = intel_text.split('\n')
    
    for line in lines:
        line_lower = line.lower().strip()
        
        # Extract title
        if '🚩' in line or 'flag' in line_lower[:20]:
            intel['title'] = line.replace('🚩', '').strip()
        
        # Extract objective / question (question at end takes precedence for "answer this")
        if 'question:' in line_lower:
            intel['objective'] = line.split(':', 1)[1].strip()
        elif 'objective:' in line_lower:
            intel['objective'] = line.split(':', 1)[1].strip()
        elif 'find' in line_lower or 'identify' in line_lower or 'determine' in line_lower or 'what is' in line_lower or 'what was' in line_lower:
            if not intel['objective']:
                intel['objective'] = line.strip()
        
        # Extract MITRE
        if 'mitre' in line_lower or 't1' in line_lower:
            intel['mitre'] = line.strip()
        
        # Extract hints ("Hint:", "Hint 1:", "Guidance:")
        if re.match(r'^\s*(?:hint\s*\d*|guidance)\s*:', line_lower):
            hint = line.split(':', 1)[1].strip()
            intel['hints'].append(hint)
        
        # Extract format
        if 'format:' in line_lower:
            intel['format'] = line.split(':', 1)[1].strip()
    
    return intel


# ═══════════════════════════════════════════════════════════════
# STAGE 2: BOT'S INTEL INTERPRETATION (NEW - Advisory Only)
# ═══════════════════════════════════════════════════════════════

def bot_interpretation_stage(flag_intel, session, openai_client, model):
    """LLM interprets the intel and provides guidance (no KQL generation)"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}🤖 BOT'S INTEL INTERPRETATION & GUIDANCE")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    # Get session context (previous flags)
    llm_context = session.get_llm_context(current_flag_config=flag_intel, context_type="compact")
    
    # The model does not reliably know the MDE schema (it guessed SigninLogs / "RDPLogon"
    # for RDP logons when asked cold) - so the real table directory goes in every time.
    schema_directory = AZURE_SCHEMA_REFERENCE.table_directory_prompt()

    interpretation_prompt = f"""You are a cybersecurity analyst COACH helping a human investigator with a CTF threat hunt.
The human writes every KQL query and submits every answer themselves. You guide, you do not solve.

{schema_directory}

{llm_context}

CURRENT FLAG INTEL:
{flag_intel['raw_intel']}

Your role is ADVISORY ONLY. Do NOT generate KQL queries and do NOT guess the final answer. Instead:

1. EXPLAIN what this flag is asking for in plain English
2. SUGGEST which log table to query (use the table directory above - exact table names)
3. RECOMMEND which fields should be projected in the query (exact field names from the directory)
4. IDENTIFY what patterns or conditions to look for (filters, keywords, time window, ordering)
5. MENTION any previous flag answers that could be used as filters

Be concise and practical. Format your response as:
INTERPRETATION: [What the flag is asking]
RECOMMENDED TABLE: [Table name]
KEY FIELDS: [List of fields to include]
SEARCH CRITERIA: [What to filter/look for]
CORRELATION: [How to use previous flags, if applicable]
"""
    
    if model is None:
        print(f"{Fore.YELLOW}No model selected. Skipping bot interpretation.{Fore.RESET}\n")
        return {'interpretation': "No interpretation available (model not selected)", 'flag_intel': flag_intel}
    
    print(f"{Fore.LIGHTBLACK_EX}{LLM_ROUTER.resolve(model)} is reading the flag intel...{Fore.RESET}\n")
    
    try:
        if openai_client is not None:
            LLM_ROUTER.set_openai_client(openai_client)
        # Free-text advisory: thinking ON for the local model (worth ~30 s here - it picked the
        # right table only with thinking), moderate temperature, generous output budget.
        interpretation = LLM_ROUTER.chat(
            [{"role": "user", "content": interpretation_prompt}],
            model, json_mode=False, temperature=0.3, think=True, purpose="ctf_interpretation",
        )
        print(f"{Fore.LIGHTCYAN_EX}BOT'S GUIDANCE:{Fore.RESET}\n")
        print(f"{Fore.WHITE}{interpretation.strip()}{Fore.RESET}\n")
        print(f"{Fore.LIGHTCYAN_EX}{'─'*70}{Fore.RESET}\n")
    except Exception as e:
        print(f"{Fore.RED}Error getting bot interpretation: {e}{Fore.RESET}\n")
        interpretation = "No interpretation available"
    
    return {'interpretation': interpretation, 'flag_intel': flag_intel}


# ═══════════════════════════════════════════════════════════════
# STAGE 3: HUMAN WRITES KQL (NEW)
# ═══════════════════════════════════════════════════════════════

KQL_START_RE = re.compile(r"^\s*(?:let\s|union\s|search\s|print\s|[A-Za-z_][A-Za-z0-9_]*\s*(?:\||$))", re.I)
INTEL_LINE_RE = re.compile(r"^\s*(?:🚩|flag\s*\d*\s*[:\-]|flag format\s*:|hint\s*\d*\s*:|reference\s*:|question\s*:|objective\s*:|format\s*:|mitre\s*:)", re.I)


def flush_typeahead():
    """
    Drop keystrokes typed/pasted BEFORE a prompt appeared. Text pasted while the model was
    still thinking used to be swallowed as the first lines of the next stage's input - on
    2026-09-03 three leftover flag-intel lines were sent to Azure as part of a KQL query.
    """
    try:
        import sys, termios
        if sys.stdin.isatty():
            termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
    except Exception:
        pass


def clean_kql_lines(lines):
    """
    Keep only the KQL: strip transcript prompts ('KQL > '), drop flag-intel lines and anything
    before the first line that looks like the start of a query. Returns (kept, dropped).
    """
    kept, dropped = [], []
    started = False
    for raw in lines:
        line = re.sub(r"^(?:\s*KQL\s*>\s*)+", "", raw)          # prompts echoed before the text
        line = re.sub(r"(?:\s*KQL\s*>\s*)+$", "", line)         # prompts glued after a pasted last line
        if not line.strip():
            if started:
                kept.append("")
            continue
        if INTEL_LINE_RE.match(line):
            dropped.append(line)
            continue
        if not started:
            if KQL_START_RE.match(line):
                started = True
            else:
                dropped.append(line)
                continue
        kept.append(line.rstrip())
    while kept and not kept[-1].strip():
        kept.pop()
    return kept, dropped


def human_kql_entry_stage(bot_guidance):
    """Human writes their own KQL query"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}✍️  HUMAN KQL QUERY ENTRY")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    print(f"{Fore.WHITE}Write your KQL query based on the bot's guidance.{Fore.RESET}\n")
    
    print(f"{Fore.LIGHTBLACK_EX}Instructions:{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  • Type each line of your KQL query{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  • Press Enter after each line{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  • Type 'DONE' on a new line when finished{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  • Query will execute after DONE{Fore.RESET}\n")
    
    print(f"{Fore.LIGHTCYAN_EX}Example:{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}{'─'*70}")
    print(f"{Fore.LIGHTBLACK_EX}KQL > DeviceLogonEvents")
    print(f"{Fore.LIGHTBLACK_EX}KQL > | where ActionType == \"LogonSuccess\"")
    print(f"{Fore.LIGHTBLACK_EX}KQL > | where isnotempty(RemoteIP)")
    print(f"{Fore.LIGHTBLACK_EX}KQL > | project TimeGenerated, RemoteIP, AccountName")
    print(f"{Fore.LIGHTBLACK_EX}KQL > DONE")
    print(f"{Fore.LIGHTBLACK_EX}{'─'*70}{Fore.RESET}\n")
    
    while True:
        flush_typeahead()
        query_lines = []
        try:
            while True:
                line = input(f"{Fore.WHITE}KQL > {Fore.RESET}")
                if line.strip().upper() == 'DONE':
                    break
                query_lines.append(line)
        except (KeyboardInterrupt, EOFError):
            print(f"\n{Fore.YELLOW}Cancelled{Fore.RESET}")
            return None

        kept, dropped = clean_kql_lines(query_lines)
        if dropped:
            print(f"\n{Fore.YELLOW}Ignored {len(dropped)} line(s) that are not KQL (leftover paste / flag intel):{Fore.RESET}")
            for d in dropped[:5]:
                print(f"{Fore.LIGHTBLACK_EX}   ✗ {d[:90]}{Fore.RESET}")
        if not kept:
            print(f"{Fore.YELLOW}No query entered.{Fore.RESET}")
            return None

        kql_query = '\n'.join(kept)
        print(f"\n{Fore.LIGHTCYAN_EX}This query will run:{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}{'─'*70}{Fore.RESET}")
        for ln in kept:
            print(f"{Fore.WHITE}{ln}{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}{'─'*70}{Fore.RESET}")
        try:
            flush_typeahead()
            ok = input(f"{Fore.LIGHTGREEN_EX}Run it? [Y/n/r=retype]: {Fore.RESET}").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{Fore.YELLOW}Cancelled{Fore.RESET}")
            return None
        if ok in ('', 'y', 'yes'):
            print(f"\n{Fore.LIGHTBLACK_EX}Processing query...{Fore.RESET}\n")
            return kql_query
        if ok in ('n', 'no'):
            return None
        print(f"{Fore.LIGHTBLACK_EX}OK - type the query again.{Fore.RESET}\n")


# ═══════════════════════════════════════════════════════════════
# STAGE 4: EXECUTE QUERY
# ═══════════════════════════════════════════════════════════════

def execution_stage(kql_query, law_client, workspace_id, timerange_hours,
                   start_date, end_date, flag_intel):
    """Execute KQL query against Azure Sentinel / Log Analytics"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}⚡ EXECUTING QUERY")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    # DEBUG: Verify which client we're using
    client_type = type(law_client).__name__
    has_query_workspace = hasattr(law_client, 'query_workspace')
    has_query_advanced_hunting = hasattr(law_client, 'query_advanced_hunting')
    
    print(f"{Fore.LIGHTYELLOW_EX}🔍 DEBUG: Client Type = '{client_type}'{Fore.RESET}")
    print(f"{Fore.LIGHTYELLOW_EX}🔍 DEBUG: Has query_workspace (Log Analytics) = {has_query_workspace}{Fore.RESET}")
    print(f"{Fore.LIGHTYELLOW_EX}🔍 DEBUG: Has query_advanced_hunting (MDE) = {has_query_advanced_hunting}{Fore.RESET}")
    print(f"{Fore.LIGHTYELLOW_EX}🔍 DEBUG: Workspace ID = '{workspace_id}'{Fore.RESET}\n")
    
    try:
        # CTF Mode always uses Azure Sentinel / Log Analytics
        print(f"{Fore.LIGHTBLACK_EX}[Querying Azure Log Analytics]{Fore.RESET}\n")
        
        if not hasattr(law_client, 'query_workspace'):
            print(f"{Fore.RED}ERROR: Log Analytics client required but not provided!{Fore.RESET}\n")
            print(f"{Fore.RED}Actual client type: {client_type}{Fore.RESET}\n")
            return None
        
        print(f"{Fore.LIGHTGREEN_EX}✓ Confirmed: Using Log Analytics API (query_workspace){Fore.RESET}\n")
        
        response = law_client.query_workspace(
            workspace_id=workspace_id,
            query=kql_query,
            timespan=timedelta(hours=timerange_hours)
        )
        
        print(f"{Fore.LIGHTGREEN_EX}✓ Query executed successfully via Log Analytics{Fore.RESET}\n")
        
        if not response.tables or len(response.tables[0].rows) == 0:
            print(f"{Fore.YELLOW}✗ Query returned 0 records{Fore.RESET}")
            return None
        
        table = response.tables[0]
        df = pd.DataFrame(table.rows, columns=table.columns)
        
        print(f"{Fore.LIGHTGREEN_EX}✓ Query completed{Fore.RESET}")
        print(f"{Fore.WHITE}Records: {Fore.LIGHTYELLOW_EX}{len(table.rows)}{Fore.RESET}\n")
        
        return df.to_csv(index=False)
        
    except Exception as e:
        print(f"{Fore.RED}Error executing query: {e}{Fore.RESET}")
        return None


# ═══════════════════════════════════════════════════════════════
# STAGE 5: RESULTS DISPLAY (Paginated)
# ═══════════════════════════════════════════════════════════════

def display_results_paginated(results_csv):
    """Display results with pagination - 100 entries per page"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}📊 QUERY RESULTS")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    import io
    df = pd.read_csv(io.StringIO(results_csv))
    
    total_rows = len(df)
    page_size = 100
    current_page = 0
    
    while True:
        start_idx = current_page * page_size
        end_idx = min(start_idx + page_size, total_rows)
        
        if start_idx >= total_rows:
            break
        
        print(f"{Fore.LIGHTCYAN_EX}RESULTS (rows {start_idx + 1}-{end_idx} of {total_rows}):{Fore.RESET}\n")
        page_df = df.iloc[start_idx:end_idx]
        
        # Wide format - show all columns
        pd.set_option('display.max_columns', None)
        pd.set_option('display.width', None)
        pd.set_option('display.max_colwidth', 150)
        
        print(page_df.to_string(index=False))
        print(f"\n{Fore.LIGHTCYAN_EX}{'─'*70}{Fore.RESET}\n")
        
        remaining_rows = total_rows - end_idx
        
        if remaining_rows > 0:
            print(f"{Fore.LIGHTGREEN_EX}[S]{Fore.RESET} Show next {min(page_size, remaining_rows)} rows")
            print(f"{Fore.LIGHTGREEN_EX}[ENTER]{Fore.RESET} Continue to next stage\n")
            
            try:
                user_input = input(f"{Fore.LIGHTCYAN_EX}→ {Fore.RESET}").strip().lower()
                
                if user_input == 's':
                    # User typed 's' - show next page
                    current_page += 1
                    print()
                    continue
                else:
                    # Any other input (including Enter/empty) - continue to next stage
                    break
            except (KeyboardInterrupt, EOFError):
                break
        else:
            print(f"{Fore.LIGHTGREEN_EX}[ENTER]{Fore.RESET} Continue to next stage\n")
            input(f"{Fore.LIGHTCYAN_EX}→ {Fore.RESET}")
            break
    
    print()


# ═══════════════════════════════════════════════════════════════
# STAGE 5.5: LLM RESULT ANALYSIS (NEW)
# ═══════════════════════════════════════════════════════════════

def llm_result_analysis_stage(results_csv, flag_intel, kql_query, session, 
                              openai_client, model, severity_config):
    """Analyze CTF query results with LLM - answer extraction focus"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}🤖 LLM ANALYSIS OF QUERY RESULTS")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    # Count rows for large dataset detection
    lines = results_csv.split('\n')
    row_count = len([l for l in lines if l.strip()]) - 1  # Exclude header

    # Detect the table from the ORIGINAL header (sampling prepends a summary block)
    table_name = _detect_table_from_csv(results_csv)

    # Keep the full result set with the session (gitignored folder) so a flag can be replayed
    # later against a different model or a fixed prompt - the old sessions only kept pasted rows.
    original_csv = results_csv
    try:
        safe = session._sanitize_filename(session.project_name) if hasattr(session, '_sanitize_filename') else 'session'
        os.makedirs(getattr(session, 'session_dir', 'ctf_sessions/'), exist_ok=True)
        with open(os.path.join(getattr(session, 'session_dir', 'ctf_sessions/'),
                               f"{safe}_flag{flag_intel.get('flag_number', 'x')}_results.csv"), "w", encoding="utf-8") as f:
            f.write(original_csv)
    except Exception:
        pass

    # Deterministic evidence pass over the FULL result set (fast, no model): candidate
    # values matching the flag's format/hints, decoded base64, with original row numbers.
    evidence = EVIDENCE_FILTER.extract_candidates(original_csv, flag_intel)
    print(f"{Fore.LIGHTBLACK_EX}Evidence scan: {evidence['total_rows']} rows, looking for {', '.join(evidence['families'])} → "
          f"{len(evidence['candidates'])} candidate value(s){Fore.RESET}")

    # Fit the data to the model: the local model's practical window is small and slow,
    # cloud models can take far more. Candidate rows are always included; RowId survives.
    max_chars = _ctf_log_budget_chars(model)
    if len(results_csv) > max_chars or row_count > 100:
        print(f"{Fore.YELLOW}⚠️  {row_count} rows ({len(results_csv):,} chars) - sampling to fit {LLM_ROUTER.resolve(model)} ({max_chars:,} chars max){Fore.RESET}")
        print(f"{Fore.WHITE}   Strategy: candidate rows first, then rows matching the flag's format/keywords, then a spread of the rest; RowId = original row number{Fore.RESET}\n")
        results_csv = _smart_sample_csv_for_ctf(results_csv, flag_intel.get('objective', ''), max_chars=max_chars,
                                                flag_intel=flag_intel,
                                                priority_row_ids=EVIDENCE_FILTER.candidate_row_ids(evidence))
        sampled_lines = len([l for l in results_csv.split('\n') if l.strip() and not l.startswith('#')]) - 1
        print(f"{Fore.LIGHTGREEN_EX}✓ Sampled {sampled_lines} rows for analysis (from {row_count} total){Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}  Note: If answer not found, use interactive conversation to analyze specific row ranges{Fore.RESET}\n")
    
    # Get previous flags context
    previous_flags_context = session.get_llm_context(current_flag_config=flag_intel, context_type="compact")
    
    # Build CTF-specific prompt
    ctf_user_prompt = f"""CTF FLAG ANALYSIS - Extract Specific Answer

FLAG: {flag_intel['title']}
OBJECTIVE: {flag_intel['objective']}
EXPECTED FORMAT: {flag_intel.get('format', 'any')}
HINTS: {', '.join(flag_intel.get('hints', []))}

KQL QUERY EXECUTED:
{kql_query}

PREVIOUS FLAGS CONTEXT:
{previous_flags_context}

TASK:
Analyze the log data below and extract THE SPECIFIC ANSWER that:
- Matches the objective: "{flag_intel['objective']}"
- Matches the format: "{flag_intel.get('format', 'any')}"
- Is supported by evidence in the logs

DEEP FIELD ANALYSIS REQUIRED:
- Decode base64/hex/URL encoding in ProcessCommandLine fields
- Parse obfuscated PowerShell commands
- Extract encoded data from RegistryKey values
- Analyze complex FolderPath patterns
- Decode filename encodings
- Correlate multiple fields (AccountName + ProcessCommandLine + FolderPath)

{AZURE_SCHEMA_REFERENCE.generate_schema_prompt(table_name) if table_name in AZURE_SCHEMA_REFERENCE.AZURE_TABLE_SCHEMAS else ''}

{EVIDENCE_FILTER.render_for_prompt(evidence, level=3)}

Return the answer with:
- The exact value/string that is the flag answer (must appear in the log data - never invent one)
- RowId numbers where evidence appears
- Brief explanation of why this is the answer
- Any decoding/parsing steps performed
- "guidance": where an analyst should look (fields + filter) WITHOUT giving the value away
- "candidates": up to 3 plausible values with RowIds if the answer is uncertain
"""
    
    # Build threat hunt prompt with CTF formatting
    import PROMPT_MANAGEMENT
    threat_hunt_user_message = PROMPT_MANAGEMENT.build_threat_hunt_prompt(
        user_prompt=ctf_user_prompt,
        table_name=table_name,
        log_data=results_csv,
        investigation_context=f"CTF Flag: {flag_intel['objective']}"
    )
    
    # Replace formatting instructions with CTF-specific ones
    user_content = threat_hunt_user_message["content"]
    # Replace FORMATTING_INSTRUCTIONS with CTF_FORMATTING_INSTRUCTIONS
    if "Formatting Instructions:" in user_content:
        parts = user_content.split("Formatting Instructions:")
        if len(parts) > 1:
            remaining = parts[1].split("logs below:", 1)
            if len(remaining) > 1:
                user_content = parts[0] + "Formatting Instructions:\n" + PROMPT_MANAGEMENT.CTF_FORMATTING_INSTRUCTIONS + "\nlogs below:" + remaining[1]
                threat_hunt_user_message["content"] = user_content
    
    # CTF-specific system prompt
    ctf_system_prompt = {
        "role": "system",
        "content": """You are a CTF (Capture The Flag) cybersecurity analyst specializing in deep log field investigation.

Your task is to EXTRACT SPECIFIC ANSWERS from log data, not to find general threats.

CAPABILITIES:
1. DEEP FIELD PARSING:
   - Decode base64/hex/URL encoding in ProcessCommandLine
   - Parse obfuscated PowerShell commands
   - Extract encoded data from RegistryKey values
   - Analyze complex FolderPath patterns
   - Decode filename encodings

2. PATTERN RECOGNITION:
   - Find patterns across multiple fields
   - Correlate AccountName + ProcessCommandLine + FolderPath
   - Identify sequences of events
   - Detect data exfiltration patterns

3. OBFUSCATION DETECTION:
   - Recognize caret insertion (p^o^w^e^r^s^h^e^l^l)
   - Detect string reversal
   - Identify encoding layers (base64 → hex → ASCII)
   - Parse concatenated commands

4. CONTEXTUAL ANALYSIS:
   - Understand MITRE techniques in command lines
   - Identify persistence mechanisms in paths
   - Recognize C2 communication patterns
   - Extract IOCs from complex fields

Focus on:
- Finding the exact value requested by the flag objective
- Matching the expected answer format
- Providing clear evidence from specific log rows
- Correlating with previous flags when relevant
- Explaining decoding/parsing steps

Return answers in the exact format requested."""
    }
    
    # Prepare investigation context for CTF mode
    investigation_context = {
        'mode': 'ctf',
        'flag_objective': flag_intel['objective'],
        'expected_format': flag_intel.get('format', 'any'),
        'table_name': table_name,
        'json_schema': PROMPT_MANAGEMENT.CTF_ANSWER_SCHEMA,
    }
    
    # Estimate tokens and get confirmation
    try:
        import CONFIRMATION_MANAGER
        import TIME_ESTIMATOR
        messages = [ctf_system_prompt, threat_hunt_user_message]
        approx_tokens = TIME_ESTIMATOR.estimate_tokens(messages, model)
        cost_info = CONFIRMATION_MANAGER.get_cost_info(model, input_tokens=approx_tokens)
        ok = CONFIRMATION_MANAGER.confirm_analysis_with_time_estimate(
            model_name=model,
            input_tokens=approx_tokens,
            cost_info=cost_info,
            investigation_mode="ctf",
            severity_config=severity_config
        )
        if not ok:
            print(f"{Fore.YELLOW}LLM analysis cancelled.{Fore.RESET}\n")
            return None
    except Exception:
        pass  # Continue without confirmation if estimation fails
    
    # Call EXECUTOR.hunt() with CTF context
    record_count = len([l for l in results_csv.split('\n') if l.strip()])
    print(f"{Fore.LIGHTBLACK_EX}Analyzing {record_count} records with {model}...{Fore.RESET}\n")
    
    import EXECUTOR
    hunt_results = EXECUTOR.hunt(
        openai_client=openai_client,
        threat_hunt_system_message=ctf_system_prompt,
        threat_hunt_user_message=threat_hunt_user_message,
        openai_model=model,
        severity_config=severity_config,
        table_name=table_name,
        investigation_context=investigation_context
    )
    
    if not hunt_results:
        print(f"{Fore.YELLOW}LLM analysis failed.{Fore.RESET}\n")
        return None
    
    # Parse CTF result - unified handling for all models
    if isinstance(hunt_results, dict) and "suggested_answer" in hunt_results:
        # Direct CTF format (from OpenAI models or enhancers that return CTF directly)
        llm_analysis = hunt_results
    elif isinstance(hunt_results, dict) and "findings" in hunt_results:
        # Check if CTF data is embedded in findings format (from local model enhancers)
        findings = hunt_results.get("findings", [])
        ctf_data = None
        
        # Look for _ctf_analysis field in findings (stored by enhancers)
        for finding in findings:
            if isinstance(finding, dict) and "_ctf_analysis" in finding:
                ctf_data = finding["_ctf_analysis"]
                break
        
        if ctf_data:
            # Extract CTF format from embedded data
            llm_analysis = {
                "suggested_answer": ctf_data.get("suggested_answer", ""),
                "confidence": ctf_data.get("confidence", "Low"),
                "evidence_rows": ctf_data.get("evidence_rows", []),
                "evidence_fields": ctf_data.get("evidence_fields", []),
                "explanation": ctf_data.get("explanation", ""),
                "correlation": ctf_data.get("correlation", "")
            }
        else:
            # Try to extract from finding title/IOC if no _ctf_analysis field
            suggested_answer = ""
            explanation = ""
            confidence = "Low"
            
            for finding in findings:
                if isinstance(finding, dict):
                    title = finding.get("title", "")
                    if "CTF Answer:" in title:
                        # Extract answer from title like "CTF Answer: <answer>"
                        suggested_answer = title.split("CTF Answer:")[-1].strip()
                    if finding.get("description"):
                        explanation = finding.get("description", "")
                    if finding.get("confidence"):
                        confidence = finding.get("confidence", "Low")
                    # Check IOCs for answer
                    iocs = finding.get("indicators_of_compromise", [])
                    if iocs and not suggested_answer:
                        suggested_answer = iocs[0] if isinstance(iocs[0], str) else ""
                    break
            
            llm_analysis = {
                "suggested_answer": suggested_answer,
                "confidence": confidence,
                "evidence_rows": [],
                "evidence_fields": [],
                "explanation": explanation if explanation else "LLM analysis completed but answer extraction failed",
                "correlation": ""
            }
    else:
        # No valid format found
        llm_analysis = {
            "suggested_answer": "",
            "confidence": "Low",
            "evidence_rows": [],
            "evidence_fields": [],
            "explanation": "LLM analysis completed but no answer extracted - invalid response format",
            "correlation": ""
        }
    
    llm_analysis['_evidence'] = evidence
    llm_analysis['revealed'] = coach_level(session) >= 3
    display_llm_analysis(llm_analysis, level=coach_level(session), evidence=evidence)
    
    return llm_analysis


def _ctf_log_budget_chars(model):
    """How many characters of log data to hand the model in one CTF analysis call."""
    m = LLM_ROUTER.resolve(model)
    if LLM_ROUTER.is_local(m):
        return 16_000     # ~8K tokens of CSV → ~2-3 min on this Mac; more is slower, not smarter
    if LLM_ROUTER.is_claude(m):
        return 120_000    # 1M window; keep the call snappy and the answer focused
    return 60_000         # OpenAI


FORMAT_HINT_PATTERNS = {
    # flag "format" text → regex that matches candidate values in a row
    "ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "filename": r"[\w\-\. ]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|zip|7z|rar|txt|kdbx|csv|docx|xlsx|pdf|lnk|log)\b",
    "command": r"(?:powershell|cmd\.exe|certutil|curl|wget|bitsadmin|7z|tar|xcopy|robocopy|net\.exe|whoami|nltest|netstat|qwinsta|quser|procdump|rundll32|mshta|wscript|schtasks|reg\.exe|attrib)",
    "account": r"[A-Za-z][\w\.\-]{2,}\\?[\w\.\-]*",
    "domain": r"\b[a-z0-9\-]+(?:\.[a-z0-9\-]+)+\b",
    "pipe": r"\\\\\.\\pipe\\[\w\-\.]+|\\pipe\\[\w\-\.]+|PipeName",
    "base64": r"(?:-enc|-encodedcommand|-e )\s*[A-Za-z0-9+/=]{20,}|FromBase64String",
    "path": r"[A-Za-z]:\\[^,\"]+",
}


def _format_family(flag_intel):
    """Map the flag's 'format' text / objective onto FORMAT_HINT_PATTERNS keys."""
    fmt = ((flag_intel or {}).get('format') or '').lower()
    obj = ((flag_intel or {}).get('objective') or '').lower()
    text = fmt + " " + obj
    fams = []
    if "ip" in fmt or "xxx.xxx" in fmt or "ip address" in obj:
        fams.append("ip")
    if "filename" in text or "file name" in text or "file " in fmt:
        fams.append("filename")
    if "command" in text:
        fams.append("command")
    if "account" in text or "username" in text or "user name" in text:
        fams.append("account")
    if "domain" in text or "service" in text or "url" in text:
        fams.append("domain")
    if "pipe" in text:
        fams.append("pipe")
    if "base64" in text or "decoded" in text or "encoded" in text:
        fams.append("base64")
    if "directory" in text or "path" in text or "folder" in text:
        fams.append("path")
    return fams


def _smart_sample_csv_for_ctf(csv_data, flag_objective, max_chars=50000, flag_intel=None, priority_row_ids=None):
    """
    Deterministically sample CSV rows for one CTF analysis call.

    1. A RowId column (original 1-based row number) is added so the model's evidence
       rows and later "analyze rows N-M" requests refer to the same numbering.
    2. Rows are scored: matches for the flag's expected format (IP, filename, command...)
       + objective/hint keywords + generic CTF signals (encoded data, suspicious paths).
       Highest scores go first; ties keep original order (no randomness).
    3. The remaining budget is filled with an even spread of the other rows so time
       coverage is preserved.
    4. A short summary header tells the model what it is looking at.
    """
    import re
    lines = [l for l in csv_data.split('\n') if l.strip()]
    if len(lines) < 2:
        return csv_data

    header = lines[0]
    data_lines = lines[1:]
    total_rows = len(data_lines)

    # Keywords from the objective + hints (words of 4+ chars, minus stop words)
    stop = {"what", "which", "that", "this", "with", "from", "into", "identify", "question", "answer",
            "used", "were", "there", "their", "flag", "find", "search", "look", "field", "query", "table"}
    kw_text = (flag_objective or "") + " " + " ".join((flag_intel or {}).get('hints', []) or [])
    keywords = {w for w in re.findall(r"[a-z0-9_\-\.]{4,}", kw_text.lower()) if w not in stop}
    families = _format_family(flag_intel or {'objective': flag_objective, 'format': ''})
    fam_res = [re.compile(FORMAT_HINT_PATTERNS[f], re.IGNORECASE) for f in families if f in FORMAT_HINT_PATTERNS]

    generic = ['base64', 'encodedcommand', ' -enc ', 'frombase64string', 'bypass', 'hidden', 'downloadstring',
               'invoke-', 'iex', 'webrequest', '\\temp\\', '\\public\\', 'downloads', 'appdata', 'programdata',
               'registry', 'certutil', 'rundll32', 'mshta', 'schtasks', '.kdbx', 'password']

    scored = []
    for idx, line in enumerate(data_lines, start=1):
        low = line.lower()
        score = 0
        for r in fam_res:
            if r.search(line):
                score += 3
        score += sum(2 for k in keywords if k in low)
        score += sum(1 for g in generic if g in low)
        if re.search(r"[A-Za-z0-9+/]{40,}={0,2}", line):   # long base64-looking token
            score += 2
        scored.append((score, idx, line))

    forced = set(priority_row_ids or [])
    scored = [(score + (100 if idx in forced else 0), idx, line) for score, idx, line in scored]
    priority = [t for t in sorted(scored, key=lambda t: (-t[0], t[1])) if t[0] > 0]
    chosen = {}
    used = len(header) + 6
    for score, idx, line in priority:
        if used + len(line) + 8 > max_chars:
            break
        chosen[idx] = line
        used += len(line) + 8

    # Fill the rest with an even spread of unchosen rows (keeps timeline coverage)
    rest = [t for t in scored if t[1] not in chosen]
    if rest and used < max_chars:
        avg = max(1, sum(len(t[2]) for t in rest) // len(rest)) + 8
        room = max(0, (max_chars - used) // avg)
        if room > 0:
            step = max(1, len(rest) // room)
            for _, idx, line in rest[::step]:
                if used + len(line) + 8 > max_chars:
                    break
                chosen[idx] = line
                used += len(line) + 8

    ordered = sorted(chosen.items())
    sampled_lines = ["RowId," + header] + [f"{idx},{line}" for idx, line in ordered]
    n_priority = sum(1 for idx in chosen if scored[idx - 1][0] > 0)

    summary = f"""# CSV DATA SUMMARY
# Total Rows in Dataset: {total_rows}
# Rows included here: {len(ordered)} (matched flag format/keywords: {n_priority}; spread sample: {len(ordered) - n_priority})
# RowId = the row's number in the FULL result set - cite it as evidence and use it to request more rows.
# Format families searched: {', '.join(families) if families else 'none detected'}
#
"""
    return summary + "\n".join(sampled_lines)


def _detect_table_from_csv(csv_text):
    """Detect which table the CSV data came from based on column headers"""
    lines = [l for l in csv_text.strip().split('\n') if l.strip() and not l.startswith('#')]
    if len(lines) < 2:
        return "Unknown"
    
    headers = lines[0].lower()

    # DeviceEvents is the only table with AdditionalFields - decide it before the loose matching below
    if 'additionalfields' in headers:
        return 'DeviceEvents'
    
    # Table signatures (unique field combinations)
    table_signatures = {
        'DeviceProcessEvents': ['processcommandline', 'initiatingprocesscommandline'],
        'DeviceNetworkEvents': ['remoteip', 'remoteport'],
        'DeviceLogonEvents': ['logontype', 'accountname', 'remoteip'],
        'DeviceFileEvents': ['filename', 'folderpath', 'sha256'],
        'DeviceRegistryEvents': ['registrykey', 'registryvaluename'],
        'AlertInfo': ['alertid', 'title', 'severity', 'status'],
        'AlertEvidence': ['alertid', 'evidencetype', 'evidencevalue'],
        'SigninLogs': ['userprincipalname', 'appdisplayname'],
        'AuditLogs': ['operationname', 'category', 'result', 'initiatedby'],
        'AzureActivity': ['operationnamevalue', 'caller'],
        'AzureNetworkAnalytics_CL': ['flowtype_s', 'srcpublicips_s'],
        'AzureNetworkAnalyticsIPDetails_CL': ['publicipaddress_s', 'publicipdetails_s', 'organization_s']
    }
    
    # Best match wins (most signature fields present), not the first "close enough" one -
    # a logon CSV used to be labelled DeviceNetworkEvents because RemoteIP matched first.
    header_fields = {h.strip().strip('"') for h in headers.split(',')}
    best, best_score = "Unknown", (0, 0.0)
    for table_name, signature_fields in table_signatures.items():
        matches = sum(1 for field in signature_fields if field in header_fields or field in headers)
        if matches == 0 or matches < len(signature_fields) - 1:
            continue
        score = (matches, matches / len(signature_fields))
        if score > best_score:
            best, best_score = table_name, score
    return best


def display_llm_analysis(llm_analysis, level=3, evidence=None):
    """Display the analysis - how much depends on the coach level (1 guide / 2 narrow / 3 reveal)."""
    import textwrap
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}🤖 AI COACH - LEVEL {level} ({COACH_LEVELS.get(level, '').split(' - ')[0].strip()})")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")

    suggested_answer = llm_analysis.get("suggested_answer", "")
    confidence = llm_analysis.get("confidence", "Low")
    evidence_rows = llm_analysis.get("evidence_rows", [])
    evidence_fields = llm_analysis.get("evidence_fields", [])
    guidance = llm_analysis.get("guidance", "")

    if level <= 2:
        if guidance:
            print(f"{Fore.LIGHTCYAN_EX}WHERE TO LOOK:{Fore.RESET}")
            print(f"{Fore.WHITE}{textwrap.fill(guidance, width=70)}{Fore.RESET}\n")
        if evidence_fields:
            print(f"{Fore.WHITE}Fields that matter: {Fore.LIGHTYELLOW_EX}{', '.join(evidence_fields)}{Fore.RESET}")
        if evidence_rows:
            print(f"{Fore.WHITE}Rows worth a close look: {Fore.LIGHTYELLOW_EX}{evidence_rows}{Fore.RESET}")
        if evidence:
            print(f"\n{Fore.WHITE}{EVIDENCE_FILTER.render_for_human(evidence, level)}{Fore.RESET}")
        status = "has a candidate answer" if suggested_answer else "did not settle on an answer"
        print(f"\n{Fore.LIGHTBLACK_EX}The AI {status} ({confidence} confidence). Type /hint for more, or /reveal in the chat to see it.{Fore.RESET}\n")
        return

    if suggested_answer:
        print(f"{Fore.LIGHTGREEN_EX}SUGGESTED ANSWER: {Fore.LIGHTYELLOW_EX}{suggested_answer}{Fore.RESET}")
        print(f"{Fore.WHITE}CONFIDENCE: {Fore.LIGHTYELLOW_EX}{confidence}{Fore.RESET}\n")
    else:
        print(f"{Fore.YELLOW}SUGGESTED ANSWER: {Fore.RED}None found{Fore.RESET}")
        print(f"{Fore.WHITE}CONFIDENCE: {Fore.LIGHTYELLOW_EX}{confidence}{Fore.RESET}\n")
    cands = llm_analysis.get("candidates") or []
    if cands:
        print(f"{Fore.LIGHTCYAN_EX}OTHER CANDIDATES:{Fore.RESET}")
        for c in cands[:5]:
            if isinstance(c, dict):
                print(f"  • {Fore.LIGHTYELLOW_EX}{c.get('value', '')}{Fore.RESET}  rows {c.get('row_ids', [])}  {Fore.LIGHTBLACK_EX}{c.get('why', '')}{Fore.RESET}")
        print()
    if evidence_rows:
        print(f"{Fore.LIGHTCYAN_EX}EVIDENCE:{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}{'─'*70}{Fore.RESET}")
        print(f"{Fore.WHITE}Evidence Rows (RowId): {Fore.LIGHTYELLOW_EX}{evidence_rows}{Fore.RESET}")
        if evidence_fields:
            print(f"{Fore.WHITE}Evidence Fields: {Fore.LIGHTYELLOW_EX}{', '.join(evidence_fields)}{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}{'─'*70}{Fore.RESET}\n")
    for label, key in (("EXPLANATION", "explanation"), ("CORRELATION", "correlation")):
        text = llm_analysis.get(key, "")
        if text:
            print(f"{Fore.LIGHTCYAN_EX}{label}:{Fore.RESET}")
            print(f"{Fore.LIGHTBLACK_EX}{'─'*70}{Fore.RESET}")
            print(f"{Fore.WHITE}{textwrap.fill(text, width=70)}{Fore.RESET}")
            print(f"{Fore.LIGHTBLACK_EX}{'─'*70}{Fore.RESET}\n")
    if evidence and evidence.get("decoded"):
        print(f"{Fore.LIGHTCYAN_EX}DECODED PAYLOADS (by code, not the model):{Fore.RESET}")
        for d in evidence["decoded"][:5]:
            print(f"  row {d['row_id']}: {Fore.WHITE}{d['decoded'][:160]}{Fore.RESET}")
        print()


# ═══════════════════════════════════════════════════════════════
# STAGE 5.6: INTERACTIVE LLM CONVERSATION (NEW)
# ═══════════════════════════════════════════════════════════════

class CtfChatSession:
    """CTF-specific chat session for interactive investigation"""
    
    def __init__(self, llm_analysis, results_csv, flag_intel, kql_query, session, model_name, openai_client=None, bot_guidance=None, coach_level_value=1, evidence=None):
        self.llm_analysis = llm_analysis
        self.results_csv = results_csv  # This may be sampled for large datasets
        self.full_results_csv = results_csv  # Store original full CSV for deep-dive
        self.flag_intel = flag_intel
        self.kql_query = kql_query
        self.session = session
        self.model_name = LLM_ROUTER.resolve(model_name)
        self.openai_client = openai_client
        if openai_client is not None:
            LLM_ROUTER.set_openai_client(openai_client)
        self.bot_guidance = bot_guidance  # Bot's intel interpretation from Stage 2
        self.conversation_history = []
        self.conversation_summary = []  # Store summaries of older conversations
        self.coach_level = max(1, min(3, int(coach_level_value or 1)))
        self.evidence = evidence or (llm_analysis or {}).get('_evidence')
        
        # Budgets from the model's REAL window (LLM_ROUTER), leaving room for the reply
        model_context_limit = LLM_ROUTER.context_limit(self.model_name)
        if model_context_limit >= 100000:
            self.MAX_TURNS = 15
            self.MAX_TOKENS = min(100000, int(model_context_limit * 0.8))
            self.RECENT_MESSAGES_TO_KEEP = 6
        else:
            self.MAX_TURNS = 12
            self.MAX_TOKENS = int(model_context_limit * 0.75) - 4096
            self.RECENT_MESSAGES_TO_KEEP = 4
        self.turn_count = 0
        
        # Build system context
        self.system_context = self._build_system_context()
    
    def _extract_row_range(self, start_row, end_row):
        """Extract specific row range from full CSV for deep-dive analysis"""
        lines = self.full_results_csv.split('\n')
        if len(lines) < 2:
            return None
        
        header = lines[0]
        data_lines = lines[1:]
        
        # Convert 1-based row numbers to 0-based indices
        start_idx = max(0, start_row - 1)
        end_idx = min(len(data_lines), end_row)
        
        if start_idx >= len(data_lines) or start_idx >= end_idx:
            return None
        
        # RowId = original 1-based row number, same numbering as the sampled view
        selected_rows = ["RowId," + header] + [f"{i + 1},{line}" for i, line in enumerate(data_lines) if start_idx <= i < end_idx]
        row_data = '\n'.join(selected_rows)

        budget = _ctf_log_budget_chars(self.model_name) // 2
        if len(row_data) > budget:
            kept = [selected_rows[0]]
            used = len(kept[0])
            for line in selected_rows[1:]:
                if used + len(line) + 1 > budget:
                    break
                kept.append(line)
                used += len(line) + 1
            last_row = int(kept[-1].split(",", 1)[0]) if len(kept) > 1 else start_row
            print(f"{Fore.YELLOW}[CTF_CHAT] Range too big for {self.model_name}; loaded rows {start_row}-{last_row}. Ask for the rest in a follow-up.{Fore.RESET}")
            row_data = '\n'.join(kept)
        return row_data
    
    def _build_system_context(self):
        """Build CTF-specific system context with smart sampling for large datasets"""
        # Count total rows
        lines = self.results_csv.split('\n')
        total_rows = len([l for l in lines if l.strip()]) - 1  # Exclude header
        
        # Fit the data to the model's window. The chat's system context is the FIRST thing
        # a too-small window drops, so this budget is deliberately below the analysis budget.
        max_chars = int(_ctf_log_budget_chars(self.model_name) * 0.75)
        csv_preview = self.results_csv
        if len(csv_preview) > max_chars or total_rows > 100:
            csv_preview = _smart_sample_csv_for_ctf(csv_preview, self.flag_intel.get('objective', ''),
                                                    max_chars=max_chars, flag_intel=self.flag_intel)
        
        previous_flags = self.session.get_llm_context(current_flag_config=self.flag_intel, context_type="compact")

        # Coach level decides what the model may say and what it is even told
        lvl = self.coach_level
        evidence_block = EVIDENCE_FILTER.render_for_prompt(self.evidence, level=3) if self.evidence else ""
        if lvl >= 3:
            analysis_summary = (f"- Suggested Answer: {self.llm_analysis.get('suggested_answer', 'None')}\n"
                                f"- Confidence Level: {self.llm_analysis.get('confidence', 'Low')}\n"
                                f"- Evidence Rows: {self.llm_analysis.get('evidence_rows', [])}\n"
                                f"- Analysis Explanation: {self.llm_analysis.get('explanation', 'None')}")
            coach_rules = ("The analyst asked for full help. Give your best answer with evidence rows and decoding steps. "
                           "Still show your reasoning so the analyst learns the technique.")
        elif lvl == 2:
            analysis_summary = (f"- Confidence Level: {self.llm_analysis.get('confidence', 'Low')}\n"
                                f"- Evidence Rows: {self.llm_analysis.get('evidence_rows', [])}\n"
                                f"- Guidance: {self.llm_analysis.get('guidance', '')}")
            coach_rules = ("The analyst wants to find the answer themselves. You may name candidate VALUES and their RowIds "
                           "and explain how to tell them apart, but do NOT declare which one is the final answer and do not "
                           "fill in the ANSWER EXTRACTION section - write 'withheld at coach level 2' there. "
                           "If the analyst types /reveal the system will raise the level.")
        else:
            analysis_summary = (f"- Confidence Level: {self.llm_analysis.get('confidence', 'Low')}\n"
                                f"- Guidance: {self.llm_analysis.get('guidance', '')}")
            coach_rules = ("The analyst wants to find the answer themselves. Explain WHERE to look (fields, filters, "
                           "sort order, what pattern to compare) and WHY, using RowIds to point at rows - but do NOT state "
                           "any candidate value (no IPs, filenames, commands, accounts) and do not fill in the ANSWER "
                           "EXTRACTION section - write 'withheld at coach level 1' there. Never say the answer even if asked "
                           "directly; tell the analyst to type /reveal instead.")
        
        # Extract key fields from flag intel for emphasis
        flag_question = self.flag_intel.get('objective', '')
        flag_format = self.flag_intel.get('format', 'any')
        flag_notes = self.flag_intel.get('notes', '')
        
        # Include bot's intel interpretation if available
        bot_interpretation_section = ""
        if self.bot_guidance and self.bot_guidance.get('interpretation'):
            bot_interpretation_section = f"""
═══════════════════════════════════════════════════════════════
🤖 BOT'S INTEL INTERPRETATION & GUIDANCE (Stage 2)
═══════════════════════════════════════════════════════════════

{self.bot_guidance.get('interpretation', '')}

═══════════════════════════════════════════════════════════════
"""
        
        system_prompt = f"""You are a senior cybersecurity analyst conducting a CTF investigation. Your primary mission is to analyze log data and extract the exact answer to the flag question.

═══════════════════════════════════════════════════════════════
🎯 PRIMARY MISSION: ANSWER THE FLAG QUESTION
═══════════════════════════════════════════════════════════════

FLAG QUESTION: "{flag_question}"
EXPECTED FORMAT: {flag_format}
ADDITIONAL CONTEXT: {flag_notes if flag_notes else 'None'}{bot_interpretation_section}
═══════════════════════════════════════════════════════════════
📊 INVESTIGATION DATA
═══════════════════════════════════════════════════════════════

KQL QUERY EXECUTED:
{self.kql_query}

QUERY RESULTS (CSV Data):
{csv_preview}

{evidence_block}

INITIAL ANALYSIS SUMMARY:
{analysis_summary}

PREVIOUS FLAGS CONTEXT:
{previous_flags}

═══════════════════════════════════════════════════════════════
🎓 COACH MODE - LEVEL {self.coach_level}
═══════════════════════════════════════════════════════════════
{coach_rules}

═══════════════════════════════════════════════════════════════
🔍 YOUR ANALYTICAL CAPABILITIES
═══════════════════════════════════════════════════════════════

1. DEEP FIELD INVESTIGATION:
   ✓ Decode base64/hex/URL encoding in ProcessCommandLine
   ✓ Parse obfuscated PowerShell commands (caret insertion, string reversal)
   ✓ Extract encoded data from RegistryKey values
   ✓ Analyze complex FolderPath patterns
   ✓ Decode filename encodings and GUIDs
   ✓ Parse concatenated commands and multi-layer encodings

2. PATTERN RECOGNITION & CORRELATION:
   ✓ Find patterns across multiple fields (AccountName + ProcessCommandLine + FolderPath)
   ✓ Identify sequences of events (chronological analysis)
   ✓ Detect data exfiltration patterns
   ✓ Correlate timestamps with process execution
   ✓ Map process trees and relationships

3. OBFUSCATION DETECTION & DECODING:
   ✓ Recognize caret insertion (p^o^w^e^r^s^h^e^l^l)
   ✓ Detect string reversal techniques
   ✓ Identify encoding layers (base64 → hex → ASCII)
   ✓ Parse PowerShell encoded commands
   ✓ Extract hidden data from encoded fields

═══════════════════════════════════════════════════════════════
📝 YOUR RESPONSE FORMAT (CRITICAL)
═══════════════════════════════════════════════════════════════

When responding, ALWAYS provide analytical reports structured as:

**ANALYSIS:**
[Your detailed analysis of the data, focusing on fields relevant to the flag question]

**EVIDENCE:**
- Row X: [Specific field/value that supports your finding]
- Row Y: [Another piece of evidence]
- Field Analysis: [Deep dive into ProcessCommandLine/FolderPath/etc.]

**DECODING STEPS (if applicable):**
1. [Step 1: e.g., "Detected base64 encoding in ProcessCommandLine"]
2. [Step 2: e.g., "Decoded to: ..."]
3. [Step 3: e.g., "Extracted: ..."]

**ANSWER EXTRACTION:**
[Direct answer to the flag question: "{flag_question}"]
[Format: {flag_format}]

**CONFIDENCE:**
[High/Medium/Low] - [Reasoning]

═══════════════════════════════════════════════════════════════
🎯 YOUR PRIMARY OBJECTIVE
═══════════════════════════════════════════════════════════════

Every response should:
1. Analyze the log data with focus on answering: "{flag_question}"
2. Investigate hidden information in fields like ProcessCommandLine, FolderPath, RegistryKey
3. Provide evidence-based answers with specific row references
4. Show your decoding/parsing process when extracting encoded data
5. Extract the exact answer matching format: {flag_format}
6. Act as a cybersecurity analyst providing analytical reports, not casual conversation

Remember: You are analyzing logs to solve a CTF challenge. Be thorough, analytical, and evidence-based.

═══════════════════════════════════════════════════════════════
🔍 DEEP-DIVE CAPABILITY
═══════════════════════════════════════════════════════════════

If the user requests analysis of specific row ranges (e.g., "analyze rows 150-200"),
you can request those rows to be loaded. The system will provide the full data for
those specific rows for detailed analysis.
"""
        return system_prompt
    
    def _estimate_tokens(self, messages):
        """CSV-aware token estimate (same one the router enforces)"""
        return LLM_ROUTER.estimate_tokens(messages, self.model_name)
    
    def _summarize_conversation_history(self, messages_to_summarize):
        """Summarize older conversation history to preserve context"""
        if not messages_to_summarize:
            return ""
        
        # Build conversation text for summarization
        conversation_text = ""
        for msg in messages_to_summarize:
            role = msg.get("role", "unknown")
            content = msg.get("content", "")
            if role == "user":
                conversation_text += f"User: {content}\n\n"
            elif role == "assistant":
                conversation_text += f"Assistant: {content}\n\n"
        
        # Create summarization prompt
        summary_prompt = f"""Summarize the following conversation about a CTF flag investigation. 
Focus on:
- Key findings and evidence discovered
- Answers or partial answers identified
- Important patterns or insights
- Decoding steps performed
- Any specific row numbers or fields analyzed

Keep it concise (2-3 sentences max) but preserve critical information.

Conversation to summarize:
{conversation_text}

Summary:"""
        
        # Use the same model for summarization
        try:
            summary_messages = [
                {
                    "role": "system",
                    "content": "You are a helpful assistant that summarizes conversation history while preserving key information."
                },
                {
                    "role": "user",
                    "content": summary_prompt
                }
            ]
            
            summary_text = LLM_ROUTER.chat(summary_messages, self.model_name, json_mode=False,
                                           temperature=0.3, think=False, max_tokens=400,
                                           timeout=120, purpose="ctf_chat_summary")
            return summary_text.strip()
        except Exception as e:
            print(f"{Fore.YELLOW}⚠️  Summarization failed: {e}. Using fallback.{Fore.RESET}")
            # Fallback: simple extraction of key points
            fallback_summary = "Previous conversation covered: "
            key_points = []
            for msg in messages_to_summarize[-4:]:  # Last 2 exchanges
                content = msg.get("content", "")[:100]  # First 100 chars
                if content:
                    key_points.append(content[:50] + "...")
            return fallback_summary + "; ".join(key_points[:3])
    
    def _truncate_history_if_needed(self):
        """Keep conversation within token budget using smart summarization"""
        import TIME_ESTIMATOR
        
        # Check if we need to truncate
        if len(self.conversation_history) <= self.RECENT_MESSAGES_TO_KEEP:
            return  # No truncation needed
        
        # Calculate how many messages to keep vs summarize
        messages_to_keep = self.conversation_history[-self.RECENT_MESSAGES_TO_KEEP:]
        messages_to_summarize = self.conversation_history[:-self.RECENT_MESSAGES_TO_KEEP]
        
        # Summarize older messages
        print(f"{Fore.YELLOW}📝 Summarizing {len(messages_to_summarize)} older messages to preserve context...{Fore.RESET}")
        summary = self._summarize_conversation_history(messages_to_summarize)
        
        if summary:
            # Add summary as a system-like message at the start of kept history
            summary_message = {
                "role": "assistant",
                "content": f"[Previous conversation summary]: {summary}"
            }
            # Insert summary before recent messages
            self.conversation_history = [summary_message] + messages_to_keep
            self.conversation_summary.append({
                "original_count": len(messages_to_summarize),
                "summary": summary,
                "timestamp": len(self.conversation_summary) + 1
            })
            print(f"{Fore.LIGHTGREEN_EX}✓ Summarized {len(messages_to_summarize)} messages into summary, kept {len(messages_to_keep)} recent messages{Fore.RESET}")
        else:
            # Fallback: simple truncation if summarization fails
            self.conversation_history = messages_to_keep
            print(f"{Fore.YELLOW}⚠️  Summarization unavailable, truncated to last {len(messages_to_keep)} exchanges{Fore.RESET}")
    
    def _detect_row_range_request(self, user_input):
        """Detect if user is requesting specific row range analysis"""
        import re
        
        # Patterns: "rows 150-200", "row 100 to 150", "analyze rows 50-100", etc.
        patterns = [
            r'/rows?\s+(\d+)\s*[-–—]\s*(\d+)',
            r'rows?\s+(\d+)\s*(?:[-–—]|to)\s*(\d+)',
            r'rows?\s+(\d+)\s+through\s+(\d+)',
            r'analyze\s+rows?\s+(\d+)\s*(?:[-–—]|to)\s*(\d+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, user_input.lower())
            if match:
                start = int(match.group(1))
                end = int(match.group(2))
                return start, end
        
        return None, None
    
    def chat_loop(self):
        """Interactive chat loop"""
        print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
        print(f"{Fore.LIGHTCYAN_EX}💬 INTERACTIVE LLM CONVERSATION")
        print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
        
        row_count = len(self.results_csv.split('\n'))
        print(f"{Fore.WHITE}🎯 Flag Objective: {Fore.LIGHTYELLOW_EX}{self.flag_intel.get('objective', 'N/A')}{Fore.RESET}")
        print(f"{Fore.WHITE}📊 Analyzing {row_count} rows from KQL query results{Fore.RESET}\n")
        
        # Count total rows in full dataset
        full_lines = self.full_results_csv.split('\n')
        total_rows = len([l for l in full_lines if l.strip()]) - 1
        
        print(f"{Fore.WHITE}You can ask the analyst to:")
        print(f"  • Analyze specific rows or patterns")
        print(f"  • Decode obfuscated fields (ProcessCommandLine, FolderPath, etc.)")
        print(f"  • Investigate hidden information in the logs")
        print(f"  • Refine the answer to the flag question")
        print(f"  • Provide deeper analysis of specific fields")
        if total_rows > 200:
            print(f"  • Request specific row ranges (e.g., 'analyze rows 150-200')")
            print(f"    Total dataset: {total_rows} rows (sampled data shown, full data available)")
        print(f"\n{Fore.WHITE}Coach commands: {Fore.LIGHTYELLOW_EX}/hint{Fore.WHITE} (one level more help)  "
              f"{Fore.LIGHTYELLOW_EX}/reveal{Fore.WHITE} (show the AI's answer)  {Fore.LIGHTYELLOW_EX}/candidates{Fore.WHITE} (code-found values)  "
              f"{Fore.LIGHTYELLOW_EX}/level N{Fore.WHITE}  {Fore.LIGHTYELLOW_EX}/rows A-B{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}Current coach level: {self.coach_level}. Type 'exit' or 'done' to finish conversation{Fore.RESET}\n")
        
        # Add initial prompt to guide first analysis
        initial_prompt = f"""As a cybersecurity analyst, analyze the query results and provide an analytical report focusing on answering the flag question: "{self.flag_intel.get('objective', '')}".

Please investigate:
1. Hidden information in ProcessCommandLine, FolderPath, RegistryKey fields
2. Encoded or obfuscated data that might contain the answer
3. Patterns across multiple rows that relate to the flag question
4. Specific evidence rows that support your findings

Provide your analysis in the structured format with evidence, decoding steps (if any), and a direct answer."""
        
        # Start with initial analysis prompt
        print(f"{Fore.LIGHTGREEN_EX}You: {Fore.RESET}{initial_prompt}\n")
        
        # Add initial prompt to conversation
        self.conversation_history.append({
            "role": "user",
            "content": initial_prompt
        })

        while self.turn_count < self.MAX_TURNS:
            try:
                user_input = input(f"{Fore.LIGHTGREEN_EX}You: {Fore.RESET}").strip()
            except (KeyboardInterrupt, EOFError):
                print(f"\n{Fore.YELLOW}Exiting conversation...{Fore.RESET}")
                break
            
            if user_input.lower() in ['exit', 'quit', 'done', 'bye', 'q']:
                print(f"{Fore.LIGHTCYAN_EX}Ending conversation...{Fore.RESET}")
                break
            
            if not user_input:
                continue

            # ── coach commands (handled locally, no model call) ──
            cmd = user_input.lower().split()
            if cmd[0] in ('/reveal', '/hint', '/level', '/candidates', '/help', '/evidence'):
                if cmd[0] == '/help':
                    print(f"{Fore.WHITE}/hint = one level more help, /reveal = show the AI's answer, /candidates = values found by code, "
                          f"/level N = set coach level, /rows A-B = load rows A..B, exit = finish{Fore.RESET}\n")
                    continue
                if cmd[0] in ('/candidates', '/evidence'):
                    if self.evidence:
                        print(f"{Fore.WHITE}{EVIDENCE_FILTER.render_for_human(self.evidence, max(2, self.coach_level))}{Fore.RESET}\n")
                    else:
                        print(f"{Fore.YELLOW}No evidence scan available for this flag.{Fore.RESET}\n")
                    continue
                new_level = self.coach_level
                if cmd[0] == '/reveal':
                    new_level = 3
                elif cmd[0] == '/hint':
                    new_level = min(3, self.coach_level + 1)
                elif cmd[0] == '/level' and len(cmd) > 1 and cmd[1] in ('1', '2', '3'):
                    new_level = int(cmd[1])
                if new_level != self.coach_level:
                    self.coach_level = new_level
                    self.system_context = self._build_system_context()
                    print(f"{Fore.LIGHTGREEN_EX}✓ Coach level {self.coach_level}{Fore.RESET}")
                if self.coach_level >= 3:
                    self.llm_analysis['revealed'] = True
                    display_llm_analysis(self.llm_analysis, level=3, evidence=self.evidence)
                else:
                    display_llm_analysis(self.llm_analysis, level=self.coach_level, evidence=self.evidence)
                continue
            
            # Check for row range requests
            start_row, end_row = self._detect_row_range_request(user_input)
            if start_row and end_row:
                # Extract and analyze specific row range
                row_data = self._extract_row_range(start_row, end_row)
                if row_data:
                    print(f"{Fore.LIGHTCYAN_EX}📊 Loading rows {start_row}-{end_row} for analysis...{Fore.RESET}\n")
                    # Add row data to user message
                    user_input = f"{user_input}\n\nHere are rows {start_row}-{end_row}:\n{row_data}"
                else:
                    print(f"{Fore.YELLOW}⚠️  Could not extract rows {start_row}-{end_row}. Check row numbers.{Fore.RESET}\n")
            
            # Add user message to history
            self.conversation_history.append({
                "role": "user",
                "content": user_input
            })
            
            # Build messages
            messages = [
                {"role": "system", "content": self.system_context}
            ] + self.conversation_history
            
            # Check token budget
            estimated_tokens = self._estimate_tokens(messages)
            if estimated_tokens > self.MAX_TOKENS:
                print(f"{Fore.YELLOW}⚠️  Approaching token limit ({estimated_tokens:,} > {self.MAX_TOKENS:,}). Summarizing history...{Fore.RESET}")
                self._truncate_history_if_needed()
                # Rebuild messages after summarization
                messages = [
                    {"role": "system", "content": self.system_context}
                ] + self.conversation_history
                # Re-check tokens after summarization
                new_estimated_tokens = self._estimate_tokens(messages)
                print(f"{Fore.LIGHTGREEN_EX}✓ After summarization: {new_estimated_tokens:,} tokens (saved {estimated_tokens - new_estimated_tokens:,} tokens){Fore.RESET}")
            
            # Get response
            try:
                print(f"{Fore.YELLOW}🤔 {self.model_name} is analyzing...{Fore.RESET}\n")
                accum = ""
                try:
                    for piece in LLM_ROUTER.chat_stream(messages, self.model_name, temperature=0.3,
                                                        think=True, purpose="ctf_chat"):
                        accum += piece
                        print(piece, end="", flush=True)
                    print("\n")
                except KeyboardInterrupt:
                    print(f"\n{Fore.YELLOW}Cancelled. Showing partial response.{Fore.RESET}")
                except LLM_ROUTER.PromptTooLargeError as e:
                    print(f"\n{Fore.LIGHTRED_EX}Too much data for {self.model_name}: {e}{Fore.RESET}")
                    print(f"{Fore.YELLOW}Ask about a smaller row range (e.g. 'analyze rows 1-40').{Fore.RESET}")
                    raise
                
                response = accum
                
                # Add to history
                self.conversation_history.append({
                    "role": "assistant",
                    "content": response
                })
                
                print(f"\n{Fore.LIGHTCYAN_EX}Assistant (complete):{Fore.RESET}\n")
                
                self.turn_count += 1
                
                if self.turn_count >= self.MAX_TURNS - 2:
                    print(f"{Fore.YELLOW}⚠️  {self.MAX_TURNS - self.turn_count} turns remaining{Fore.RESET}\n")
                
            except Exception as e:
                print(f"{Fore.RED}Error getting response: {e}{Fore.RESET}")
                print(f"{Fore.YELLOW}Try rephrasing your question or exit and restart.{Fore.RESET}\n")
                self.conversation_history.pop()
                continue
        
        if self.turn_count >= self.MAX_TURNS:
            print(f"\n{Fore.YELLOW}⚠️  Maximum turns ({self.MAX_TURNS}) reached. Ending conversation.{Fore.RESET}")
        
        # Extract refined analysis from conversation
        refined_analysis = self._extract_refined_analysis()
        
        print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
        print(f"{Fore.LIGHTCYAN_EX}CONVERSATION SUMMARY")
        print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}")
        print(f"{Fore.WHITE}Total turns: {self.turn_count}")
        if refined_analysis.get("suggested_answer"):
            print(f"{Fore.WHITE}Refined Answer: {Fore.LIGHTYELLOW_EX}{refined_analysis.get('suggested_answer')}{Fore.RESET}")
            print(f"{Fore.WHITE}Confidence: {Fore.LIGHTYELLOW_EX}{refined_analysis.get('confidence', 'Low')}{Fore.RESET}")
        print(f"{Fore.LIGHTCYAN_EX}{'='*70}\n")
        
        return refined_analysis
    
    def _extract_refined_analysis(self):
        """
        Pick up an answer ONLY when the assistant stated one explicitly in its
        ANSWER EXTRACTION section. No more grabbing the first IP in the text - that
        invented wrong flags. The human decides what to submit.
        """
        import re
        refined = (self.llm_analysis or {}).copy()
        refined['revealed'] = bool(refined.get('revealed')) or self.coach_level >= 3
        for msg in reversed(self.conversation_history):
            if msg.get("role") != "assistant":
                continue
            content = msg.get("content", "")
            m = re.search(r"\*\*ANSWER EXTRACTION:\*\*\s*\n(.+?)(?:\n\s*\n|\*\*CONFIDENCE)", content, re.S)
            if m:
                answer = m.group(1).strip().strip("`*[] ")
                answer = re.sub(r"^\[?(?:Direct answer.*?:)?\s*", "", answer).strip()
                if answer and "format:" not in answer.lower():
                    refined["suggested_answer"] = answer.split("\n")[0].strip()
                    c = re.search(r"\*\*CONFIDENCE:\*\*\s*\n?\s*\[?(Very High|High|Medium|Low)", content, re.I)
                    if c:
                        refined["confidence"] = c.group(1).title()
                    break
        if self.conversation_history:
            refined["conversation_insights"] = [
                f"User asked: {m.get('content', '')[:50]}..." for m in self.conversation_history if m.get("role") == "user"
            ]
        return refined


def interactive_llm_conversation_stage(llm_analysis, results_csv, flag_intel, kql_query,
                                      session, openai_client, model, bot_guidance=None):
    """Interactive conversation with LLM about results
    
    Args:
        bot_guidance: Optional dict containing bot's intel interpretation from Stage 2.
                     If provided, includes 'interpretation' key with guidance text.
    """
    
    # Check if model is available
    if model is None:
        print(f"{Fore.YELLOW}No model selected. Cannot start interactive conversation.{Fore.RESET}\n")
        return llm_analysis
    
    model_name = LLM_ROUTER.resolve(model)
    
    # The chat session samples the data to the model's budget itself; keep the full CSV for deep-dives
    full_csv = results_csv
    
    # Initialize chat session (will store full_csv internally)
    chat_session = CtfChatSession(
        llm_analysis=llm_analysis,
        results_csv=results_csv,
        flag_intel=flag_intel,
        kql_query=kql_query,
        session=session,
        model_name=model_name,
        openai_client=openai_client,
        bot_guidance=bot_guidance,
        coach_level_value=coach_level(session),
        evidence=(llm_analysis or {}).get('_evidence'),
    )
    
    # Update to store full CSV for deep-dive
    chat_session.full_results_csv = full_csv
    
    # Run conversation loop
    refined_analysis = chat_session.chat_loop()
    
    return refined_analysis or llm_analysis  # Return refined or original


# ═══════════════════════════════════════════════════════════════
# STAGE 6: RESULT DOCUMENTATION MENU
# ═══════════════════════════════════════════════════════════════

def result_documentation_menu(llm_analysis=None):
    """Menu for result documentation"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}📝 RESULT DOCUMENTATION")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    print(f"  {Fore.LIGHTYELLOW_EX}[1]{Fore.RESET} ↩️  Rewrite KQL query (back to query entry)")
    print(f"  {Fore.LIGHTGREEN_EX}[2]{Fore.RESET} ✍️  Document result (capture KQL + output)")
    if llm_analysis and llm_analysis.get("suggested_answer"):
        print(f"  {Fore.LIGHTCYAN_EX}[3]{Fore.RESET} 🤖 Use LLM's suggested answer ({llm_analysis.get('suggested_answer')})")
        max_choice = 3
    else:
        max_choice = 2
    
    choice = input(f"{Fore.LIGHTGREEN_EX}Select [1-{max_choice}]: {Fore.RESET}").strip()
    
    if choice == '1':
        return 'rewrite_kql'
    elif choice == '3' and max_choice == 3:
        return 'use_llm_answer'
    else:
        return 'document'


def document_result_stage(flag_intel, session, kql_query, results_csv, llm_analysis=None):
    """Document the KQL and output for JSON memory"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}📋 DOCUMENT FLAG RESULT")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    print(f"{Fore.WHITE}Document your findings for this flag.{Fore.RESET}\n")
    
    # Show current KQL
    print(f"{Fore.LIGHTCYAN_EX}Your KQL Query (saved):{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}{'─'*70}")
    print(f"{Fore.WHITE}{kql_query}{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}{'─'*70}{Fore.RESET}\n")
    
    # Pre-fill with LLM analysis if available
    prefill_answer = ""
    prefill_output = ""
    prefill_notes = ""
    
    if llm_analysis and llm_analysis.get("suggested_answer") and llm_analysis.get("revealed"):
        prefill_answer = llm_analysis.get("suggested_answer", "")
        confidence = llm_analysis.get("confidence", "Low")
        explanation = llm_analysis.get("explanation", "")
        evidence_rows = llm_analysis.get("evidence_rows", [])
        
        print(f"{Fore.LIGHTCYAN_EX}🤖 LLM SUGGESTED ANSWER: {Fore.LIGHTYELLOW_EX}{prefill_answer} {Fore.WHITE}({confidence} confidence){Fore.RESET}\n")
        
        # Try to extract evidence rows from CSV
        if evidence_rows:
            import io
            try:
                df = pd.read_csv(io.StringIO(results_csv))
                evidence_lines = []
                for row_idx in evidence_rows:
                    if 0 <= row_idx < len(df):
                        evidence_lines.append(df.iloc[row_idx].to_string())
                if evidence_lines:
                    prefill_output = '\n'.join(evidence_lines)
            except:
                pass
        
        # Pre-fill notes with LLM explanation
        prefill_notes = f"LLM Analysis:\n{explanation}"
        if llm_analysis.get("conversation_insights"):
            prefill_notes += f"\n\nConversation Insights:\n" + '\n'.join(llm_analysis.get("conversation_insights", []))
    
    # Get the answer from human (pre-filled if LLM analysis available)
    print(f"{Fore.LIGHTGREEN_EX}From the results you reviewed, enter the answer:{Fore.RESET}")
    try:
        if prefill_answer:
            user_input = input(f"{Fore.WHITE}Answer [{Fore.LIGHTYELLOW_EX}{prefill_answer}{Fore.WHITE}]: {Fore.RESET}").strip()
            answer = user_input if user_input else prefill_answer
        else:
            answer = input(f"{Fore.WHITE}Answer: {Fore.RESET}").strip()
        
        if not answer:
            print(f"{Fore.YELLOW}No answer provided.{Fore.RESET}")
            return False
        
        # Get relevant output rows (pre-filled if LLM analysis available)
        print(f"\n{Fore.LIGHTCYAN_EX}Paste the specific row(s) that contain this answer:{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}Copy relevant rows from the query results above.{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}You can paste 1 row or multiple rows.{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}Type 'DONE' on a new line when finished.{Fore.RESET}\n")
        
        if prefill_output:
            print(f"{Fore.LIGHTGREEN_EX}LLM Evidence (pre-filled):{Fore.RESET}")
            print(f"{Fore.LIGHTBLACK_EX}{prefill_output}{Fore.RESET}\n")
            print(f"{Fore.LIGHTBLACK_EX}Press Enter to use LLM evidence, or paste your own rows:{Fore.RESET}\n")
        
        output_lines = []
        if prefill_output:
            # Show pre-filled and let user edit
            first_line = input()
            if first_line.strip().upper() == 'DONE' or not first_line.strip():
                # User accepted pre-filled
                output_lines = prefill_output.split('\n')
            else:
                # User is pasting their own
                output_lines.append(first_line)
                while True:
                    line = input()
                    if line.strip().upper() == 'DONE':
                        break
                    output_lines.append(line)
        else:
            # No pre-fill, normal input
            while True:
                line = input()
                if line.strip().upper() == 'DONE':
                    break
                output_lines.append(line)
        
        query_output = '\n'.join(output_lines) if output_lines else "No output captured"
        
        # Finding notes (pre-filled if LLM analysis available)
        print(f"\n{Fore.LIGHTCYAN_EX}Finding notes (how you found the answer):{Fore.RESET}")
        if prefill_notes:
            print(f"{Fore.LIGHTGREEN_EX}LLM Notes (pre-filled):{Fore.RESET}")
            print(f"{Fore.LIGHTBLACK_EX}{prefill_notes[:200]}...{Fore.RESET}\n")
            user_notes = input(f"{Fore.WHITE}Notes [{Fore.LIGHTBLACK_EX}Press Enter to use LLM notes or type your own{Fore.WHITE}]: {Fore.RESET}").strip()
            finding_notes = user_notes if user_notes else prefill_notes
        else:
            finding_notes = input(f"{Fore.WHITE}Notes: {Fore.RESET}").strip()
        
    except (KeyboardInterrupt, EOFError):
        print(f"\n{Fore.YELLOW}Cancelled{Fore.RESET}")
        return False
    
    # Combine output and notes into structured format for JSON
    structured_notes = f"""QUERY OUTPUT:
{query_output}

FINDING:
{finding_notes}"""
    
    # Capture flag with documentation
    session.capture_flag(
        flag_number=flag_intel['flag_number'],
        title=flag_intel['title'],
        answer=answer,
        notes=structured_notes,
        kql_used=kql_query,
        table_queried='',
        stage=flag_intel.get('mitre', '').split('-')[0].strip() if '-' in flag_intel.get('mitre', '') else '',
        mitre=flag_intel.get('mitre', '')
    )
    
    print(f"\n{Fore.LIGHTGREEN_EX}{'='*70}")
    print(f"{Fore.LIGHTGREEN_EX}✓ FLAG {flag_intel['flag_number']} CAPTURED: {answer}")
    print(f"{Fore.LIGHTGREEN_EX}{'='*70}{Fore.RESET}\n")
    
    # Explicitly prompt to continue
    print(f"{Fore.WHITE}Flag documented and saved to JSON.{Fore.RESET}")
    print(f"{Fore.LIGHTGREEN_EX}Press Enter to continue to 'What's Next?' menu...{Fore.RESET}\n")
    
    try:
        input(f"{Fore.LIGHTCYAN_EX}→ {Fore.RESET}")
    except (KeyboardInterrupt, EOFError):
        pass
    
    return True


# ═══════════════════════════════════════════════════════════════
# STAGE 7: NEXT ACTION MENU
# ═══════════════════════════════════════════════════════════════


def writeup_stage(session, model=None, openai_client=None):
    """
    Draft the GitHub write-up in Peter's published format from the session, save it next
    to his other reports, and (only if he says so) push it as a branch + pull request.
    """
    state = session.state
    model = model or state.get('model')
    if not state.get('flags_captured'):
        print(f"{Fore.YELLOW}No captured flags yet - nothing to write up.{Fore.RESET}\n")
        return None

    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}📝 GITHUB WRITE-UP")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    n = len(state['flags_captured'])
    total = state.get('total_flags') or n
    print(f"{Fore.WHITE}{n}/{total} flags captured. The structured sections come straight from the session;")
    print(f"the narrative (overview, diamond model, remediation, lessons, conclusion) is drafted by {LLM_ROUTER.resolve(model) if model else 'no model'} and marked DRAFT.{Fore.RESET}")

    use_model = model
    if model:
        try:
            ans = input(f"{Fore.LIGHTGREEN_EX}Draft the narrative with {LLM_ROUTER.resolve(model)}? [Y/n]: {Fore.RESET}").strip().lower()
        except (KeyboardInterrupt, EOFError):
            ans = "n"
        if ans == "n":
            use_model = None

    if use_model:
        print(f"{Fore.LIGHTBLACK_EX}Drafting narrative sections... (local model: 2-4 minutes){Fore.RESET}")
    markdown = REPORT_GENERATOR.build_report(state, model=use_model, openai_client=openai_client)
    filename = REPORT_GENERATOR.default_filename(state)
    try:
        path = PUBLISH.write_report_file(markdown, filename)
    except Exception as e:
        path = os.path.join(session.session_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(markdown)
        print(f"{Fore.YELLOW}Could not write into the repo folder ({e}); saved to the session folder instead.{Fore.RESET}")
    print(f"\n{Fore.LIGHTGREEN_EX}✓ Write-up drafted: {path}{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  Sections marked DRAFT need your edit; screenshots are placeholders.{Fore.RESET}\n")
    state['writeup_path'] = path
    session.save_state()

    # Publish? (branch + commit + push + PR, guarded by the secret-scan hooks)
    try:
        root = PUBLISH.repo_root()
        info = PUBLISH.preflight(root)
    except Exception as e:
        print(f"{Fore.YELLOW}Not a git repo here ({e}) - publish skipped. The file is ready to add by hand.{Fore.RESET}\n")
        return path
    print(f"{Fore.WHITE}Publish to GitHub as a pull request?{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  remote: {info['remote']}   from branch: {info['branch']}   secret-scan hooks: {info['hooks']}   gh login: {'yes' if info['gh'] else 'NO'}{Fore.RESET}")
    if info['hooks'] == '(none)':
        print(f"{Fore.RED}  No secret-scan hooks are wired in this repo - refusing to push. Run: git config core.hooksPath scripts/git-hooks{Fore.RESET}\n")
        return path
    try:
        ans = input(f"{Fore.LIGHTGREEN_EX}Push and open the PR now? [y/N]: {Fore.RESET}").strip().lower()
    except (KeyboardInterrupt, EOFError):
        ans = "n"
    if ans != "y":
        print(f"{Fore.LIGHTBLACK_EX}Not published. You can publish later from the WHAT'S NEXT menu.{Fore.RESET}\n")
        return path
    try:
        url = PUBLISH.publish(path, title=state.get('project_name') or filename, root=root)
        state['writeup_pr'] = url
        session.save_state()
        print(f"\n{Fore.LIGHTGREEN_EX}✓ Pull request: {url}{Fore.RESET}\n")
    except PUBLISH.PublishError as e:
        print(f"\n{Fore.RED}Publish failed:{Fore.RESET}\n{e}\n")
    return path


def prompt_next_action(session):
    """Ask what user wants to do next"""
    
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}WHAT'S NEXT?")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    print(f"  {Fore.LIGHTGREEN_EX}[1]{Fore.RESET} ➡️  Work on next flag")
    print(f"      → Start investigating the next flag\n")
    
    print(f"  {Fore.LIGHTMAGENTA_EX}[2]{Fore.RESET} 💾 Save and exit")
    print(f"      → Pause investigation, resume later\n")
    
    print(f"  {Fore.LIGHTCYAN_EX}[3]{Fore.RESET} 🏁 Finish hunt")
    print(f"      → Add detailed logic notes and complete investigation\n")
    
    # Only show delete option if there are flags to delete
    if session.state['flags_completed'] > 0:
        print(f"  {Fore.LIGHTRED_EX}[4]{Fore.RESET} 🗑️  Delete last flag and redo")
        print(f"      → Remove Flag {session.state['flags_completed']} and start over on it\n")
        max_choice = 4
    else:
        max_choice = 3
    print(f"  {Fore.LIGHTBLUE_EX}[F]{Fore.RESET} 📥 {'Re-import' if session.state.get('flags_planned') else 'Import'} the hunt's flags from a Google Form link")
    print(f"  {Fore.LIGHTBLUE_EX}[R]{Fore.RESET} 📝 Draft the GitHub write-up now (and optionally open a pull request)\n")
    
    try:
        choice = input(f"{Fore.LIGHTGREEN_EX}Select [1-{max_choice}/F/R]: {Fore.RESET}").strip()
        
        if choice.upper() == 'F':
            import_hunt_form_into_session(session)
            return prompt_next_action(session)
        if choice.upper() == 'R':
            return 'writeup'
        if choice == '1' or not choice:
            return 'new_flag'
        elif choice == '2':
            return 'pause'
        elif choice == '3':
            return 'finish'
        elif choice == '4' and max_choice == 4:
            # Confirm deletion
            flag_num = session.state['flags_completed']
            print(f"\n{Fore.LIGHTYELLOW_EX}⚠️  WARNING: Delete Flag {flag_num}?{Fore.RESET}")
            print(f"{Fore.LIGHTBLACK_EX}  • All data for Flag {flag_num} will be permanently removed{Fore.RESET}")
            print(f"{Fore.LIGHTBLACK_EX}  • You'll return to Flag {flag_num} intel capture stage{Fore.RESET}")
            print(f"{Fore.LIGHTBLACK_EX}  • This action cannot be undone{Fore.RESET}\n")
            
            confirm = input(f"{Fore.LIGHTYELLOW_EX}Continue? [y/N]: {Fore.RESET}").strip().lower()
            
            if confirm == 'y':
                success, deleted_num = session.delete_last_flag()
                if success:
                    print(f"\n{Fore.LIGHTGREEN_EX}✓ Flag {deleted_num} deleted successfully{Fore.RESET}")
                    print(f"{Fore.LIGHTCYAN_EX}↩️  Returning to Flag {deleted_num} hunt...{Fore.RESET}\n")
                    return 'delete_and_redo'
                else:
                    print(f"\n{Fore.RED}✗ Failed to delete flag{Fore.RESET}\n")
                    return 'new_flag'
            else:
                print(f"\n{Fore.LIGHTBLACK_EX}Deletion cancelled{Fore.RESET}\n")
                return prompt_next_action(session)  # Ask again
        else:
            return 'new_flag'
            
    except (KeyboardInterrupt, EOFError):
        return 'pause'


# ═══════════════════════════════════════════════════════════════
# STAGE 8: FLAG LOGIC FLOW (Only on Finish)
# ═══════════════════════════════════════════════════════════════

def flag_logic_flow_stage(session):
    """Capture detailed threat hunt logic flow notes"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}📖 DETAILED THREAT HUNT LOGIC FLOW")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    print(f"{Fore.WHITE}Add your detailed notes about the complete threat hunt.{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}This helps document the full investigation logic and approach.{Fore.RESET}\n")
    
    print(f"{Fore.LIGHTBLACK_EX}Type your notes (multi-line), then type 'DONE' when finished:{Fore.RESET}\n")
    
    logic_notes = []
    
    try:
        while True:
            line = input()
            if line.strip().upper() == 'DONE':
                break
            logic_notes.append(line)
    except (KeyboardInterrupt, EOFError):
        pass
    
    if logic_notes:
        logic_text = '\n'.join(logic_notes)
        session.state['logic_flow_notes'] = logic_text
        session.save_state()
        
        print(f"\n{Fore.LIGHTGREEN_EX}✓ Logic flow notes saved{Fore.RESET}\n")
    else:
        print(f"\n{Fore.LIGHTBLACK_EX}No notes added{Fore.RESET}\n")


# ═══════════════════════════════════════════════════════════════
# SESSION MANAGEMENT
# ═══════════════════════════════════════════════════════════════

def display_session_context(session):
    """Display accumulated flags and IOCs"""
    
    state = session.state
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}📚 SESSION MEMORY")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    print(f"{Fore.WHITE}Flags Captured: {Fore.LIGHTGREEN_EX}{state['flags_completed']}{Fore.RESET}\n")
    
    # Show flags
    for flag in state['flags_captured']:
        print(f"  {Fore.LIGHTGREEN_EX}✓{Fore.RESET} {flag['title']}: {Fore.LIGHTYELLOW_EX}{flag['answer']}{Fore.RESET}")
    
    # Show IOCs
    iocs = state['accumulated_iocs']
    has_iocs = any(values for values in iocs.values())
    
    if has_iocs:
        print(f"\n{Fore.LIGHTCYAN_EX}Accumulated IOCs:{Fore.RESET}")
        for ioc_type, values in iocs.items():
            if values:
                print(f"  • {ioc_type.replace('_', ' ').title()}: {Fore.LIGHTYELLOW_EX}{', '.join(map(str, values[:5]))}{Fore.RESET}")
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")


def show_final_summary(session):
    """Show final investigation summary"""
    
    state = session.state
    
    print(f"\n{Fore.LIGHTGREEN_EX}{'='*70}")
    print(f"{Fore.LIGHTGREEN_EX}🎯 INVESTIGATION COMPLETE")
    print(f"{Fore.LIGHTGREEN_EX}{'='*70}{Fore.RESET}\n")
    
    print(f"{Fore.WHITE}Project: {Fore.LIGHTYELLOW_EX}{state.get('project_name', 'N/A')}{Fore.RESET}")
    print(f"{Fore.WHITE}Flags Captured: {Fore.LIGHTGREEN_EX}{state['flags_completed']}{Fore.RESET}\n")
    
    for flag in state['flags_captured']:
        print(f"  {Fore.LIGHTGREEN_EX}✓{Fore.RESET} {flag['title']}: {Fore.LIGHTYELLOW_EX}{flag['answer']}{Fore.RESET}")
    
    print(f"\n{Fore.LIGHTGREEN_EX}{'='*70}{Fore.RESET}\n")


def create_new_session():
    """Create a new CTF session with user-provided project name"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}🎯 CTF INVESTIGATION - NEW SESSION")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    print(f"{Fore.LIGHTCYAN_EX}Enter a name for this CTF investigation:{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}Examples:{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  • Hide Your RDP: Password Spray Leads to Full Compromise{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  • Operation Lurker - APT Investigation{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  • BlueTeam CTF Challenge Oct 2025{Fore.RESET}\n")
    
    try:
        project_name = input(f"{Fore.LIGHTGREEN_EX}Project Name: {Fore.RESET}").strip()
        if not project_name:
            project_name = "CTF Hunt"
        print(f"\n{Fore.LIGHTGREEN_EX}✓ Project: {project_name}{Fore.RESET}\n")
    except (KeyboardInterrupt, EOFError):
        project_name = "CTF Hunt"
    
    # Create session (JSON file created here with project name)
    session = CTF_SESSION_MANAGER.SessionMemory(
        scenario_name="dynamic_ctf",
        project_name=project_name
    )
    session.state['project_name'] = project_name
    session.state['total_flags'] = None
    session.save_state()

    print(f"{Fore.LIGHTCYAN_EX}Import the hunt from its Google Form link? Every flag, hint and format comes in at once.{Fore.RESET}")
    if not import_hunt_form_into_session(session):
        session.state['hunt_form_declined'] = True
        session.save_state()
    prompt_coach_level(session)
    return session


def find_existing_sessions():
    """Find all sessions (including completed and interrupted)"""
    
    session_dir = "ctf_sessions/"
    if not os.path.exists(session_dir):
        return []
    
    pattern = f"{session_dir}*_summary.json"
    summary_files = glob.glob(pattern)
    
    existing = []
    for summary_file in summary_files:
        try:
            with open(summary_file, 'r') as f:
                state = json.load(f)
            
            # Include all sessions regardless of status
            existing.append({
                'file': summary_file,
                'state': state,
                'project_name': state.get('project_name', 'Unknown'),
                'flags_completed': state.get('flags_completed', 0),
                'status': state.get('status', 'unknown')
            })
        except:
            continue
    
    return existing


def rename_project(session_data, existing_sessions):
    """Rename a project and update all associated files (including JSON)"""
    
    old_name = session_data['project_name']
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}📝 RENAME PROJECT")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    print(f"{Fore.WHITE}Current name: {Fore.LIGHTYELLOW_EX}{old_name}{Fore.RESET}\n")
    
    try:
        new_name = input(f"{Fore.LIGHTGREEN_EX}New project name: {Fore.RESET}").strip()
        if not new_name or new_name == old_name:
            print(f"{Fore.YELLOW}No change made.{Fore.RESET}\n")
            return session_data
    except (KeyboardInterrupt, EOFError):
        print(f"\n{Fore.YELLOW}Rename cancelled.{Fore.RESET}\n")
        return session_data
    
    # Get old file paths
    old_state_file = session_data['file']
    old_base = os.path.basename(old_state_file).replace('_summary.json', '')
    session_dir = "ctf_sessions/"
    
    old_event_log = f"{session_dir}{old_base}.jsonl"
    old_report = f"{session_dir}{old_base}_report.md"
    
    # Create new file paths
    import re
    def sanitize(name):
        return re.sub(r'[^\w\s-]', '', name).strip().replace(' ', '_')
    
    new_base = sanitize(new_name)
    timestamp = old_base.split('_')[-1] if '_' in old_base and old_base.split('_')[-1].isdigit() else None
    
    if timestamp:
        new_base = f"{new_base}_{timestamp}"
    
    new_state_file = f"{session_dir}{new_base}_summary.json"
    new_event_log = f"{session_dir}{new_base}.jsonl"
    new_report = f"{session_dir}{new_base}_report.md"
    
    # Update state data
    session_data['state']['project_name'] = new_name
    
    # Save updated state to new file
    with open(new_state_file, 'w') as f:
        json.dump(session_data['state'], f, indent=2)
    
    # Rename files
    try:
        if os.path.exists(old_state_file):
            os.remove(old_state_file)
        if os.path.exists(old_event_log) and old_event_log != new_event_log:
            os.rename(old_event_log, new_event_log)
        if os.path.exists(old_report) and old_report != new_report:
            os.rename(old_report, new_report)
    except Exception as e:
        print(f"{Fore.RED}Error renaming files: {e}{Fore.RESET}")
    
    print(f"\n{Fore.LIGHTGREEN_EX}✓ Project renamed to: {new_name}{Fore.RESET}")
    print(f"{Fore.LIGHTGREEN_EX}✓ All files updated (including JSON){Fore.RESET}\n")
    
    session_data['project_name'] = new_name
    session_data['file'] = new_state_file
    
    return session_data


def delete_project(session_data):
    """Delete a project and all associated files"""
    
    project_name = session_data['project_name']
    flags_count = session_data['flags_completed']
    
    print(f"\n{Fore.RED}{'='*70}")
    print(f"{Fore.RED}⚠️  DANGER: DELETE PROJECT")
    print(f"{Fore.RED}{'='*70}{Fore.RESET}\n")
    print(f"{Fore.YELLOW}Project: {Fore.LIGHTYELLOW_EX}{project_name}{Fore.RESET}")
    print(f"{Fore.YELLOW}Flags captured: {Fore.LIGHTYELLOW_EX}{flags_count}{Fore.RESET}\n")
    print(f"{Fore.RED}This will PERMANENTLY delete:{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  • Session state file (.json){Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  • Event log file (.jsonl){Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  • Report file (.md){Fore.RESET}")
    print(f"{Fore.RED}  • All {flags_count} captured flag(s){Fore.RESET}\n")
    print(f"{Fore.RED}This action CANNOT be undone!{Fore.RESET}\n")
    
    # Double confirmation
    confirm1 = input(f"{Fore.LIGHTYELLOW_EX}Type '{project_name}' to confirm deletion: {Fore.RESET}").strip()
    
    if confirm1 != project_name:
        print(f"{Fore.LIGHTBLACK_EX}Deletion cancelled. Names don't match.{Fore.RESET}\n")
        return 'cancelled'
    
    confirm2 = input(f"{Fore.RED}Are you absolutely sure? [yes/N]: {Fore.RESET}").strip().lower()
    
    if confirm2 != 'yes':
        print(f"{Fore.LIGHTBLACK_EX}Deletion cancelled.{Fore.RESET}\n")
        return 'cancelled'
    
    # Get file paths
    session_dir = "ctf_sessions/"
    state_file = session_data['file']
    base_name = os.path.basename(state_file).replace('_summary.json', '')
    
    # Find all matching files (could have multiple .jsonl files with timestamps)
    event_log_pattern = f"{session_dir}{base_name}*.jsonl"
    report_file = f"{session_dir}{base_name}_report.md"
    
    deleted_files = []
    errors = []
    
    # Delete state file
    try:
        if os.path.exists(state_file):
            os.remove(state_file)
            deleted_files.append(state_file)
    except Exception as e:
        errors.append(f"State file: {e}")
    
    # Delete event log files (could be multiple)
    try:
        event_logs = glob.glob(event_log_pattern)
        for event_log in event_logs:
            if os.path.exists(event_log):
                os.remove(event_log)
                deleted_files.append(event_log)
    except Exception as e:
        errors.append(f"Event log: {e}")
    
    # Delete report file
    try:
        if os.path.exists(report_file):
            os.remove(report_file)
            deleted_files.append(report_file)
    except Exception as e:
        errors.append(f"Report file: {e}")
    
    # Show results
    if errors:
        print(f"\n{Fore.RED}⚠️  Some files could not be deleted:{Fore.RESET}")
        for error in errors:
            print(f"{Fore.RED}  • {error}{Fore.RESET}")
    
    if deleted_files:
        print(f"\n{Fore.LIGHTGREEN_EX}✓ Project deleted successfully{Fore.RESET}")
        print(f"{Fore.LIGHTGREEN_EX}✓ Deleted {len(deleted_files)} file(s):{Fore.RESET}")
        for file in deleted_files:
            print(f"{Fore.LIGHTBLACK_EX}  • {os.path.basename(file)}{Fore.RESET}")
        print()
        return 'deleted'
    else:
        print(f"\n{Fore.RED}✗ No files were deleted.{Fore.RESET}\n")
        return 'failed'


def view_project_progress(session_data):
    """Display comprehensive project progress view"""
    
    state = session_data['state']
    project_name = state.get('project_name', 'Unknown')
    status = state.get('status', 'unknown')
    flags_completed = state.get('flags_completed', 0)
    total_flags = state.get('total_flags')
    
    # Status formatting
    status_color = Fore.LIGHTGREEN_EX if status == 'in_progress' else (Fore.LIGHTYELLOW_EX if status == 'completed' else Fore.LIGHTRED_EX)
    status_icon = "🟢" if status == 'in_progress' else ("✅" if status == 'completed' else "⚠️")
    status_text = status.replace('_', ' ').title()
    
    # Calculate duration
    try:
        start = datetime.fromisoformat(state['started_at'])
        last = datetime.fromisoformat(state['last_updated'])
        duration = last - start
        hours = duration.seconds // 3600
        minutes = (duration.seconds % 3600) // 60
        days = duration.days
        if days > 0:
            duration_str = f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            duration_str = f"{hours}h {minutes}m"
        else:
            duration_str = f"{minutes}m"
    except:
        duration_str = "N/A"
    
    # Header
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}📊 PROJECT PROGRESS VIEW")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    # Project Info
    print(f"{Fore.WHITE}Project Name:{Fore.RESET} {Fore.LIGHTYELLOW_EX}{project_name}{Fore.RESET}")
    print(f"{Fore.WHITE}Status:{Fore.RESET} {status_icon} {status_color}{status_text}{Fore.RESET}")
    print(f"{Fore.WHITE}Started:{Fore.RESET} {Fore.LIGHTBLACK_EX}{state['started_at'][:19].replace('T', ' ')}{Fore.RESET}")
    print(f"{Fore.WHITE}Last Updated:{Fore.RESET} {Fore.LIGHTBLACK_EX}{state['last_updated'][:19].replace('T', ' ')}{Fore.RESET}")
    print(f"{Fore.WHITE}Duration:{Fore.RESET} {Fore.LIGHTBLACK_EX}{duration_str}{Fore.RESET}")
    
    # Progress
    print(f"\n{Fore.LIGHTCYAN_EX}{'─'*70}{Fore.RESET}")
    if total_flags is not None and total_flags > 0:
        progress_pct = int((flags_completed / total_flags) * 100)
        progress_bar = "█" * (progress_pct // 5) + "░" * (20 - (progress_pct // 5))
        print(f"{Fore.WHITE}Progress:{Fore.RESET} {Fore.LIGHTGREEN_EX}{flags_completed}/{total_flags}{Fore.RESET} Flags ({progress_pct}%)")
        print(f"{Fore.LIGHTBLACK_EX}  [{progress_bar}]{Fore.RESET}")
    else:
        print(f"{Fore.WHITE}Progress:{Fore.RESET} {Fore.LIGHTGREEN_EX}{flags_completed}{Fore.RESET} Flags Captured")
    
    # Flags Details
    if state['flags_captured']:
        print(f"\n{Fore.LIGHTCYAN_EX}{'─'*70}{Fore.RESET}")
        print(f"{Fore.LIGHTCYAN_EX}🚩 FLAGS CAPTURED:{Fore.RESET}\n")
        
        for idx, flag in enumerate(state['flags_captured'], 1):
            print(f"{Fore.LIGHTGREEN_EX}[Flag {flag['flag_number']}]{Fore.RESET} {Fore.LIGHTYELLOW_EX}{flag.get('title', 'N/A')}{Fore.RESET}")
            print(f"  {Fore.WHITE}Answer:{Fore.RESET} {Fore.LIGHTCYAN_EX}{flag['answer']}{Fore.RESET}")
            
            if flag.get('mitre'):
                print(f"  {Fore.WHITE}MITRE:{Fore.RESET} {Fore.LIGHTMAGENTA_EX}{flag['mitre']}{Fore.RESET}")
            
            if flag.get('stage'):
                print(f"  {Fore.WHITE}Stage:{Fore.RESET} {Fore.LIGHTBLACK_EX}{flag['stage']}{Fore.RESET}")
            
            if flag.get('captured_at'):
                captured_time = flag['captured_at'][:19].replace('T', ' ')
                print(f"  {Fore.WHITE}Captured:{Fore.RESET} {Fore.LIGHTBLACK_EX}{captured_time}{Fore.RESET}")
            
            if flag.get('notes'):
                # Show full notes, preserving newlines
                print(f"  {Fore.WHITE}Notes:{Fore.RESET}")
                for line in flag['notes'].split('\n'):
                    print(f"    {Fore.LIGHTBLACK_EX}{line}{Fore.RESET}")
            
            if flag.get('kql_used'):
                # Show full KQL query, preserving newlines
                print(f"  {Fore.WHITE}KQL:{Fore.RESET}")
                for line in flag['kql_used'].split('\n'):
                    print(f"    {Fore.LIGHTBLACK_EX}{line}{Fore.RESET}")
            
            if flag.get('correlation'):
                print(f"  {Fore.WHITE}Correlation:{Fore.RESET} {Fore.LIGHTBLACK_EX}{flag['correlation']}{Fore.RESET}")
            
            if idx < len(state['flags_captured']):
                print()  # Space between flags
    
    # IOCs
    iocs = state.get('accumulated_iocs', {})
    has_iocs = any(values for values in iocs.values())
    
    if has_iocs:
        print(f"\n{Fore.LIGHTCYAN_EX}{'─'*70}{Fore.RESET}")
        print(f"{Fore.LIGHTCYAN_EX}🔍 ACCUMULATED IOCs:{Fore.RESET}\n")
        
        for ioc_type, values in iocs.items():
            if values:
                print(f"  {Fore.WHITE}{ioc_type.replace('_', ' ').title()}:{Fore.RESET} {Fore.LIGHTYELLOW_EX}{', '.join(map(str, values))}{Fore.RESET}")
    else:
        print(f"\n{Fore.LIGHTCYAN_EX}{'─'*70}{Fore.RESET}")
        print(f"{Fore.LIGHTCYAN_EX}🔍 ACCUMULATED IOCs:{Fore.RESET}\n")
        print(f"  {Fore.LIGHTBLACK_EX}(No IOCs captured yet){Fore.RESET}")
    
    # Attack Chain
    attack_chain = state.get('attack_chain', [])
    if attack_chain:
        print(f"\n{Fore.LIGHTCYAN_EX}{'─'*70}{Fore.RESET}")
        print(f"{Fore.LIGHTCYAN_EX}🔗 ATTACK CHAIN:{Fore.RESET}\n")
        for step in attack_chain:
            print(f"  {Fore.LIGHTBLACK_EX}• {step}{Fore.RESET}")
    
    # Logic Flow Notes (if completed)
    if state.get('logic_flow_notes'):
        print(f"\n{Fore.LIGHTCYAN_EX}{'─'*70}{Fore.RESET}")
        print(f"{Fore.LIGHTCYAN_EX}📝 INVESTIGATION NOTES:{Fore.RESET}\n")
        print(f"{Fore.LIGHTBLACK_EX}{state['logic_flow_notes']}{Fore.RESET}")
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    input(f"{Fore.LIGHTBLACK_EX}Press Enter to continue...{Fore.RESET}")


def prompt_project_action(session_data):
    """Submenu for selected project: Continue, Rename, View Progress, or Delete"""
    
    while True:
        status = session_data.get('status', 'unknown')
        status_color = Fore.LIGHTGREEN_EX if status == 'in_progress' else (Fore.LIGHTYELLOW_EX if status == 'completed' else Fore.LIGHTRED_EX)
        status_icon = "🟢" if status == 'in_progress' else ("✅" if status == 'completed' else "⚠️")
        status_text = status.replace('_', ' ').title()
        
        print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
        print(f"{Fore.LIGHTCYAN_EX}📂 SELECTED: {Fore.LIGHTYELLOW_EX}{session_data['project_name']}{Fore.RESET}")
        print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
        print(f"{Fore.WHITE}Flags completed: {session_data['flags_completed']}{Fore.RESET}")
        print(f"{Fore.WHITE}Status: {status_icon} {status_color}{status_text}{Fore.RESET}\n")
        
        # Show warning for completed/interrupted sessions
        if status in ['completed', 'interrupted']:
            print(f"{Fore.YELLOW}{'='*70}")
            print(f"{Fore.YELLOW}⚠️  WARNING: This session is marked as '{status_text}'{Fore.RESET}")
            print(f"{Fore.YELLOW}  Resuming will change status to 'in_progress' and allow editing.{Fore.RESET}")
            print(f"{Fore.YELLOW}{'='*70}{Fore.RESET}\n")
        
        print(f"{Fore.LIGHTGREEN_EX}[1]{Fore.RESET} Continue hunt")
        print(f"{Fore.LIGHTYELLOW_EX}[2]{Fore.RESET} Rename project")
        print(f"{Fore.LIGHTCYAN_EX}[3]{Fore.RESET} 📊 View project progress")
        print(f"{Fore.LIGHTRED_EX}[4]{Fore.RESET} 🗑️  Delete project")
        print(f"{Fore.LIGHTBLACK_EX}[B]{Fore.RESET} Back to session list\n")
        
        choice = input(f"{Fore.LIGHTGREEN_EX}Select [1-4/B]: {Fore.RESET}").strip().upper()
        
        if choice == '1':
            # Confirm if resuming completed/interrupted session
            if status in ['completed', 'interrupted']:
                confirm = input(f"{Fore.LIGHTYELLOW_EX}Resume this {status_text.lower()} session? [y/N]: {Fore.RESET}").strip().lower()
                if confirm != 'y':
                    print(f"{Fore.LIGHTBLACK_EX}Cancelled.{Fore.RESET}\n")
                    continue
            
            # Load and return session
            session = CTF_SESSION_MANAGER.SessionMemory(
                scenario_name="dynamic_ctf",
                project_name=session_data['project_name']
            )
            session.state = session_data['state']
            session.state_file = session_data['file']
            
            # Change status back to 'in_progress' if it was completed/interrupted
            if status in ['completed', 'interrupted']:
                session.state['status'] = 'in_progress'
                session.save_state()
                print(f"\n{Fore.LIGHTGREEN_EX}✓ Session status changed to 'in_progress'{Fore.RESET}\n")
            
            base_name = os.path.basename(session_data['file']).replace('_summary.json', '')
            session.event_log = f"{session.session_dir}{base_name}.jsonl"
            session.report_file = f"{session.session_dir}{base_name}_report.md"
            
            return session
            
        elif choice == '2':
            # Rename project (updates JSON filename too)
            session_data = rename_project(session_data, None)
            # Loop back to show updated name
            
        elif choice == '3':
            # View project progress
            view_project_progress(session_data)
            # Loop back to menu after viewing
            
        elif choice == '4':
            # Delete project
            result = delete_project(session_data)
            if result == 'deleted':
                return 'deleted'
            # If cancelled, loop back to menu
            
        elif choice == 'B':
            return 'back'
        
        else:
            print(f"{Fore.RED}Invalid choice. Please select 1, 2, 3, 4, or B.{Fore.RESET}")


def prompt_resume_or_new(existing_sessions):
    """Enhanced menu: Resume existing hunt or start new"""
    
    while True:
        # Refresh session list at start of each iteration
        existing_sessions = find_existing_sessions()
        
        if not existing_sessions:
            # No sessions left, return None to start fresh
            return None
        
        print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
        print(f"{Fore.LIGHTCYAN_EX}🔄 EXISTING SESSIONS FOUND")
        print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
        
        print(f"{Fore.LIGHTCYAN_EX}You have {len(existing_sessions)} investigation(s):{Fore.RESET}\n")
        
        for i, sess in enumerate(existing_sessions, 1):
            status = sess.get('status', 'unknown')
            status_color = Fore.LIGHTGREEN_EX if status == 'in_progress' else (Fore.LIGHTYELLOW_EX if status == 'completed' else Fore.LIGHTRED_EX)
            status_icon = "🟢" if status == 'in_progress' else ("✅" if status == 'completed' else "⚠️")
            status_text = status.replace('_', ' ').title()
            print(f"  {Fore.LIGHTBLACK_EX}•{Fore.RESET} {status_icon} {Fore.LIGHTYELLOW_EX}{sess['project_name']}{Fore.RESET} ({sess['flags_completed']} flags) {status_color}[{status_text}]{Fore.RESET}")
        
        print(f"\n{Fore.LIGHTGREEN_EX}[C]{Fore.RESET} Continue with existing hunts")
        print(f"{Fore.LIGHTGREEN_EX}[N]{Fore.RESET} Start new investigation\n")
        
        choice = input(f"{Fore.LIGHTGREEN_EX}Select [C/N]: {Fore.RESET}").strip().upper()
        
        if choice == 'N' or not choice:
            return None
        
        elif choice == 'C':
            # Show detailed project list
            while True:
                # Refresh list again before showing detailed view
                existing_sessions = find_existing_sessions()
                if not existing_sessions:
                    print(f"\n{Fore.LIGHTGREEN_EX}✓ All sessions deleted. Starting fresh...{Fore.RESET}\n")
                    return None
                
                print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
                print(f"{Fore.LIGHTCYAN_EX}📋 SELECT INVESTIGATION TO RESUME")
                print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
                
                for i, sess in enumerate(existing_sessions, 1):
                    status = sess.get('status', 'unknown')
                    status_color = Fore.LIGHTGREEN_EX if status == 'in_progress' else (Fore.LIGHTYELLOW_EX if status == 'completed' else Fore.LIGHTRED_EX)
                    status_icon = "🟢" if status == 'in_progress' else ("✅" if status == 'completed' else "⚠️")
                    status_text = status.replace('_', ' ').title()
                    print(f"{Fore.LIGHTCYAN_EX}[{i}]{Fore.RESET} {status_icon} {Fore.LIGHTYELLOW_EX}{sess['project_name']}{Fore.RESET}")
                    print(f"    Flags: {sess['flags_completed']} | Status: {status_color}{status_text}{Fore.RESET}")
                    print()
                
                print(f"{Fore.LIGHTBLACK_EX}[B]{Fore.RESET} Back\n")
                
                project_choice = input(f"{Fore.LIGHTGREEN_EX}Select [1-{len(existing_sessions)}/B]: {Fore.RESET}").strip().upper()
                
                if project_choice == 'B':
                    break
                
                try:
                    idx = int(project_choice) - 1
                    if 0 <= idx < len(existing_sessions):
                        result = prompt_project_action(existing_sessions[idx])
                        
                        if result == 'back':
                            continue
                        elif result == 'deleted':
                            # Project was deleted, refresh will happen on next loop iteration
                            print(f"\n{Fore.LIGHTGREEN_EX}✓ Project deleted. Refreshing list...{Fore.RESET}\n")
                            break  # Break inner loop, outer loop will refresh
                        elif result:
                            return result
                except:
                    print(f"{Fore.RED}Invalid choice.{Fore.RESET}")
        
        else:
            print(f"{Fore.RED}Invalid choice. Please select C or N.{Fore.RESET}")

