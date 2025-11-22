"""
CTF Hunt Mode V3 - Human-Driven with LLM Advisory
Major redesign: Human writes KQL, LLM provides guidance

Canonical implementation: This module is the single active CTF Hunt Mode.
Legacy variants have been archived under `archive/` and are no longer
imported or maintained.
"""

import json
import os
import glob
from datetime import timedelta, datetime
from color_support import Fore
import CTF_SESSION_MANAGER
import GUARDRAILS
import OLLAMA_CLIENT
import AZURE_SCHEMA_REFERENCE
import pandas as pd


def is_local_model(model_name):
    """Determine if a model is local/Ollama or cloud/OpenAI"""
    if model_name is None:
        return False
    
    # Check direct match first
    if model_name in GUARDRAILS.ALLOWED_MODELS:
        model_info = GUARDRAILS.ALLOWED_MODELS[model_name]
        return (model_info.get("cost_per_million_input", 0) == 0.00 and 
                model_info.get("cost_per_million_output", 0) == 0.00)
    
    # Check if it's an Ollama model name that maps to an allowed model
    # (e.g., "qwen3:8b" maps to "qwen", "gpt-oss:20b" maps to itself)
    ollama_to_allowed_mapping = {
        "qwen3:8b": "qwen",
        "gpt-oss:20b": "gpt-oss:20b"
    }
    
    if model_name in ollama_to_allowed_mapping:
        mapped_name = ollama_to_allowed_mapping[model_name]
        if mapped_name in GUARDRAILS.ALLOWED_MODELS:
            model_info = GUARDRAILS.ALLOWED_MODELS[mapped_name]
            return (model_info.get("cost_per_million_input", 0) == 0.00 and 
                    model_info.get("cost_per_million_output", 0) == 0.00)
    
    return False


def get_ollama_model_name(model_name):
    """Map friendly model names to Ollama model names"""
    if model_name is None:
        return None
    # local-mix is handled by HYBRID_ENGINE, not Ollama directly
    if model_name == "local-mix":
        return "local-mix"  # Special case - handled by hybrid engine
    ollama_mapping = {
        "qwen": "qwen3:8b",
        "gpt-oss:20b": "gpt-oss:20b"
    }
    return ollama_mapping.get(model_name, model_name)


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
                    model, timerange_hours, start_date, end_date, severity_config
                )
                
                if not flag_captured:
                    continue
            
            elif action == 'pause':
                print(f"\n{Fore.LIGHTCYAN_EX}💾 Pausing investigation...{Fore.RESET}\n")
                session.state['status'] = 'in_progress'
                session.save_state()
                print(f"{Fore.LIGHTGREEN_EX}✓ Session paused. You can resume later.{Fore.RESET}\n")
                break
            
            elif action == 'finish':
                # Flag logic flow stage
                flag_logic_flow_stage(session)
                session.state['status'] = 'completed'
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

def capture_flag_intel_stage(session):
    """Capture flag objective and intel from user"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}📋 FLAG {session.state['flags_completed'] + 1} INTEL CAPTURE")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    print(f"{Fore.WHITE}Paste the flag objective and any hints/intel you have.{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}Include:{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  • Flag title/question{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  • Objective (what you're looking for){Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  • Hints, guidance, MITRE techniques{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  • Expected format{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}Type 'DONE' on a new line when finished{Fore.RESET}\n")
    
    print(f"{Fore.LIGHTCYAN_EX}Example:{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}{'─'*70}")
    print(f"{Fore.LIGHTBLACK_EX}🚩 Flag 1: Attacker IP Address")
    print(f"{Fore.LIGHTBLACK_EX}MITRE: T1110.001 - Brute Force")
    print(f"{Fore.LIGHTBLACK_EX}Objective: Find external IP that logged in after brute-force")
    print(f"{Fore.LIGHTBLACK_EX}Hint: Look for failed logins followed by success")
    print(f"{Fore.LIGHTBLACK_EX}Format: xxx.xxx.xxx.xxx")
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
    print(f"{Fore.WHITE}Title: {Fore.LIGHTYELLOW_EX}{flag_intel.get('title', 'Unnamed Flag')}{Fore.RESET}\n")
    
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
        
        # Extract objective
        if 'objective:' in line_lower:
            intel['objective'] = line.split(':', 1)[1].strip()
        elif 'find' in line_lower or 'identify' in line_lower or 'determine' in line_lower:
            if not intel['objective']:
                intel['objective'] = line.strip()
        
        # Extract MITRE
        if 'mitre' in line_lower or 't1' in line_lower:
            intel['mitre'] = line.strip()
        
        # Extract hints
        if 'hint:' in line_lower or 'guidance:' in line_lower:
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
    
    # Build interpretation prompt
    interpretation_prompt = f"""You are a cybersecurity analyst advisor helping with a CTF investigation.

{llm_context}

CURRENT FLAG INTEL:
{flag_intel['raw_intel']}

Your role is ADVISORY ONLY. Do NOT generate KQL queries. Instead:

1. EXPLAIN what this flag is asking for in plain English
2. SUGGEST which Azure log table to query (DeviceLogonEvents, DeviceProcessEvents, etc.)
3. RECOMMEND which fields should be projected in the query
4. IDENTIFY what patterns or conditions to look for
5. MENTION any previous flag answers that could be used as filters

Provide concise, practical guidance to help the human write their own KQL query.

Format your response as:
INTERPRETATION: [What the flag is asking]
RECOMMENDED TABLE: [Table name]
KEY FIELDS: [List of fields to include]
SEARCH CRITERIA: [What to filter/look for]
CORRELATION: [How to use previous flags, if applicable]
"""
    
    # Check if model is available
    if model is None:
        print(f"{Fore.YELLOW}No model selected. Skipping bot interpretation.{Fore.RESET}\n")
        return {
            'interpretation': "No interpretation available (model not selected)",
            'flag_intel': flag_intel
        }
    
    print(f"{Fore.LIGHTBLACK_EX}LLM analyzing flag intel...{Fore.RESET}\n")
    
    try:
        # Get LLM interpretation - use selected model directly
        if is_local_model(model):
            model_name = get_ollama_model_name(model)
            # For local-mix, HYBRID_ENGINE handles it, but for simple interpretation use first model
            if model == "local-mix":
                # local-mix uses hybrid engine, but for simple text interpretation, use qwen (faster)
                # This is acceptable as it's just guidance, not final analysis
                model_name = "qwen3:8b"
            interpretation = OLLAMA_CLIENT.chat(
                messages=[{"role": "user", "content": interpretation_prompt}],
                model_name=model_name,
                json_mode=False,
                temperature=0.3
            )
        else:
            response = openai_client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": interpretation_prompt}],
                temperature=0.3
            )
            interpretation = response.choices[0].message.content
        
        print(f"{Fore.LIGHTCYAN_EX}BOT'S GUIDANCE:{Fore.RESET}\n")
        print(f"{Fore.WHITE}{interpretation.strip()}{Fore.RESET}\n")
        print(f"{Fore.LIGHTCYAN_EX}{'─'*70}{Fore.RESET}\n")
        
    except Exception as e:
        print(f"{Fore.RED}Error getting bot interpretation: {e}{Fore.RESET}\n")
        interpretation = "No interpretation available"
    
    return {
        'interpretation': interpretation,
        'flag_intel': flag_intel
    }


# ═══════════════════════════════════════════════════════════════
# STAGE 3: HUMAN WRITES KQL (NEW)
# ═══════════════════════════════════════════════════════════════

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
    
    if not query_lines:
        print(f"{Fore.YELLOW}No query entered.{Fore.RESET}")
        return None
    
    kql_query = '\n'.join(query_lines)
    
    print(f"\n{Fore.LIGHTBLACK_EX}Processing query...{Fore.RESET}\n")
    
    return kql_query


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
    
    # For large datasets, use smart sampling
    original_csv = results_csv
    if row_count > 100:
        print(f"{Fore.YELLOW}⚠️  Large dataset detected ({row_count} rows). Using intelligent sampling...{Fore.RESET}")
        print(f"{Fore.WHITE}   Strategy: Prioritizing rows with relevant fields (ProcessCommandLine, FolderPath, RegistryKey, encoded data){Fore.RESET}\n")
        
        results_csv = _smart_sample_csv_for_ctf(
            results_csv, 
            flag_intel.get('objective', ''),
            max_chars=50000  # ~500-1000 rows depending on row length
        )
        
        sampled_lines = len(results_csv.split('\n')) - 1
        print(f"{Fore.LIGHTGREEN_EX}✓ Sampled {sampled_lines} rows for analysis (from {row_count} total){Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}  Note: If answer not found, use interactive conversation to analyze specific row ranges{Fore.RESET}\n")
    
    # Detect table from CSV
    table_name = _detect_table_from_csv(results_csv)
    
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

Return the answer with:
- The exact value/string that is the flag answer
- Row numbers where evidence appears
- Brief explanation of why this is the answer
- Any decoding/parsing steps performed
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
        'table_name': table_name
    }
    
    # Estimate tokens and get confirmation
    try:
        import CONFIRMATION_MANAGER
        import TIME_ESTIMATOR
        messages = [ctf_system_prompt, threat_hunt_user_message]
        approx_tokens = TIME_ESTIMATOR.estimate_tokens(messages, model)
        cost_info = CONFIRMATION_MANAGER.get_cost_info(model)
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
    
    # Display LLM analysis
    display_llm_analysis(llm_analysis)
    
    return llm_analysis


def _smart_sample_csv_for_ctf(csv_data, flag_objective, max_chars=50000):
    """
    Intelligently sample CSV data for CTF analysis:
    1. Prioritize rows with relevant fields (ProcessCommandLine, FolderPath, RegistryKey)
    2. Include rows with encoded/obfuscated data
    3. Ensure header + representative sample
    4. Add summary statistics
    
    Args:
        csv_data: Full CSV string
        flag_objective: The CTF flag objective/question
        max_chars: Maximum characters to include in sampled CSV
    
    Returns:
        Sampled CSV string with summary header
    """
    lines = csv_data.split('\n')
    if len(lines) < 2:
        return csv_data
    
    header = lines[0]
    data_lines = lines[1:]
    total_rows = len([l for l in data_lines if l.strip()])
    
    if total_rows == 0:
        return csv_data
    
    # Keywords that indicate relevant data for CTF
    relevant_keywords = [
        'base64', 'encoded', 'powershell', 'cmd', 'reg', 'registry',
        'temp', 'public', 'downloads', 'appdata', 'obfuscated',
        'executionpolicy', 'bypass', 'hidden', 'encodedcommand',
        'invoke', 'downloadstring', 'webrequest', 'iex', 'frombase64string',
        'decode', 'hex', 'url', 'percent', 'unicode'
    ]
    
    # Priority rows: rows with relevant fields or keywords
    priority_rows = []
    normal_rows = []
    
    for idx, line in enumerate(data_lines):
        if not line.strip():
            continue
        
        line_lower = line.lower()
        # Check if row contains relevant keywords
        is_priority = any(keyword in line_lower for keyword in relevant_keywords)
        
        # Check for encoded data patterns
        has_encoding = any([
            ' -enc ' in line_lower,
            ' -encodedcommand ' in line_lower,
            'base64' in line_lower,
            'frombase64string' in line_lower,
            len([c for c in line if c.isalnum() and len(c) > 30]) > 0  # Long encoded strings
        ])
        
        # Check for suspicious paths
        has_suspicious_path = any([
            'temp' in line_lower,
            'public' in line_lower,
            'downloads' in line_lower,
            'appdata' in line_lower,
            '\\users\\' in line_lower and 'public' in line_lower
        ])
        
        if is_priority or has_encoding or has_suspicious_path:
            priority_rows.append((idx, line))
        else:
            normal_rows.append((idx, line))
    
    # Build sampled CSV
    sampled_lines = [header]
    char_count = len(header)
    
    # Add ALL priority rows (up to char limit)
    priority_added = 0
    for idx, line in priority_rows:
        if char_count + len(line) + 1 > max_chars:  # +1 for newline
            break
        sampled_lines.append(line)
        char_count += len(line) + 1
        priority_added += 1
    
    # Add representative sample of normal rows
    remaining_chars = max_chars - char_count
    sample_size = min(len(normal_rows), max(10, remaining_chars // 200))  # ~10-50 normal rows
    
    import random
    if normal_rows and sample_size > 0:
        sampled_normal = random.sample(normal_rows, min(sample_size, len(normal_rows)))
        for idx, line in sampled_normal:
            if char_count + len(line) + 1 > max_chars:
                break
            sampled_lines.append(line)
            char_count += len(line) + 1
    
    sampled_csv = '\n'.join(sampled_lines)
    sampled_row_count = len(sampled_lines) - 1  # Exclude header
    
    # Add summary header
    summary = f"""# CSV DATA SUMMARY
# Total Rows in Dataset: {total_rows}
# Priority Rows (with relevant fields/encoding): {len(priority_rows)}
# Normal Rows: {len(normal_rows)}
# Sampled Rows: {sampled_row_count} (Priority: {priority_added}, Normal: {sampled_row_count - priority_added})
# Sampling Strategy: Prioritized rows with ProcessCommandLine/FolderPath/RegistryKey/encoded data
# 
# IMPORTANT: Analyze ALL rows systematically. If answer not in sampled data, 
# request specific row ranges for deeper analysis (e.g., "analyze rows 150-200").
#
"""
    
    return summary + sampled_csv


def _detect_table_from_csv(csv_text):
    """Detect which table the CSV data came from based on column headers"""
    lines = csv_text.strip().split('\n')
    if len(lines) < 2:
        return "Unknown"
    
    headers = lines[0].lower()
    
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
    
    # Find best match
    for table_name, signature_fields in table_signatures.items():
        matches = sum(1 for field in signature_fields if field in headers)
        if matches >= len(signature_fields) - 1:  # Allow 1 missing field
            return table_name
    
    return "Unknown"


def display_llm_analysis(llm_analysis):
    """Display LLM analysis results"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}🤖 LLM ANALYSIS RESULTS")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    suggested_answer = llm_analysis.get("suggested_answer", "")
    confidence = llm_analysis.get("confidence", "Low")
    evidence_rows = llm_analysis.get("evidence_rows", [])
    evidence_fields = llm_analysis.get("evidence_fields", [])
    explanation = llm_analysis.get("explanation", "")
    correlation = llm_analysis.get("correlation", "")
    
    if suggested_answer:
        print(f"{Fore.LIGHTGREEN_EX}SUGGESTED ANSWER: {Fore.LIGHTYELLOW_EX}{suggested_answer}{Fore.RESET}")
        print(f"{Fore.WHITE}CONFIDENCE: {Fore.LIGHTYELLOW_EX}{confidence}{Fore.RESET}\n")
    else:
        print(f"{Fore.YELLOW}SUGGESTED ANSWER: {Fore.RED}None found{Fore.RESET}")
        print(f"{Fore.WHITE}CONFIDENCE: {Fore.LIGHTYELLOW_EX}{confidence}{Fore.RESET}\n")
    
    if evidence_rows:
        print(f"{Fore.LIGHTCYAN_EX}EVIDENCE:{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}{'─'*70}{Fore.RESET}")
        print(f"{Fore.WHITE}Evidence Rows: {Fore.LIGHTYELLOW_EX}{evidence_rows}{Fore.RESET}")
        if evidence_fields:
            print(f"{Fore.WHITE}Evidence Fields: {Fore.LIGHTYELLOW_EX}{', '.join(evidence_fields)}{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}{'─'*70}{Fore.RESET}\n")
    
    if explanation:
        print(f"{Fore.LIGHTCYAN_EX}EXPLANATION:{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}{'─'*70}{Fore.RESET}")
        # Print explanation with word wrap
        import textwrap
        wrapped_explanation = textwrap.fill(explanation, width=70)
        print(f"{Fore.WHITE}{wrapped_explanation}{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}{'─'*70}{Fore.RESET}\n")
    
    if correlation:
        print(f"{Fore.LIGHTCYAN_EX}CORRELATION:{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}{'─'*70}{Fore.RESET}")
        print(f"{Fore.WHITE}{correlation}{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}{'─'*70}{Fore.RESET}\n")


# ═══════════════════════════════════════════════════════════════
# STAGE 5.6: INTERACTIVE LLM CONVERSATION (NEW)
# ═══════════════════════════════════════════════════════════════

class CtfChatSession:
    """CTF-specific chat session for interactive investigation"""
    
    def __init__(self, llm_analysis, results_csv, flag_intel, kql_query, session, model_name, openai_client=None, bot_guidance=None):
        self.llm_analysis = llm_analysis
        self.results_csv = results_csv  # This may be sampled for large datasets
        self.full_results_csv = results_csv  # Store original full CSV for deep-dive
        self.flag_intel = flag_intel
        self.kql_query = kql_query
        self.session = session
        self.model_name = model_name
        self.openai_client = openai_client
        self.bot_guidance = bot_guidance  # Bot's intel interpretation from Stage 2
        self.conversation_history = []
        
        # Safety limits - dynamic based on model capabilities
        import TIME_ESTIMATOR
        model_context_limit = TIME_ESTIMATOR.get_model_context_limit(model_name)
        # Set limits based on model context window (larger models get more turns/tokens)
        if model_context_limit >= 100000:
            self.MAX_TURNS = 15  # Large context models (Qwen, GPT-4o, etc.)
            self.MAX_TOKENS = min(100000, int(model_context_limit * 0.8))
        else:
            self.MAX_TURNS = 5   # Smaller context models (GPT-OSS, etc.)
            self.MAX_TOKENS = min(25000, int(model_context_limit * 0.8))
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
        
        selected_rows = [header] + data_lines[start_idx:end_idx]
        return '\n'.join(selected_rows)
    
    def _build_system_context(self):
        """Build CTF-specific system context with smart sampling for large datasets"""
        # Count total rows
        lines = self.results_csv.split('\n')
        total_rows = len([l for l in lines if l.strip()]) - 1  # Exclude header
        
        # For large datasets, use smart sampling instead of simple truncation
        if total_rows > 200:
            csv_preview = _smart_sample_csv_for_ctf(
                self.results_csv,
                self.flag_intel.get('objective', ''),
                max_chars=50000  # Increased from 15K to 50K for better coverage
            )
        else:
            # Small dataset: include all data (up to 50K chars)
            csv_preview = self.results_csv[:50000]
            if len(self.results_csv) > 50000:
                csv_preview += f"\n... (truncated, {len(self.results_csv)} total chars, {total_rows} total rows)"
        
        previous_flags = self.session.get_llm_context(current_flag_config=self.flag_intel, context_type="compact")
        
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

INITIAL ANALYSIS SUMMARY:
- Suggested Answer: {self.llm_analysis.get('suggested_answer', 'None')}
- Confidence Level: {self.llm_analysis.get('confidence', 'Low')}
- Evidence Rows: {self.llm_analysis.get('evidence_rows', [])}
- Analysis Explanation: {self.llm_analysis.get('explanation', 'None')}

PREVIOUS FLAGS CONTEXT:
{previous_flags}

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
        """Rough token estimate"""
        try:
            import tiktoken
            enc = tiktoken.get_encoding("cl100k_base")
            text = ""
            for m in messages:
                text += m.get("role", "") + " " + m.get("content", "") + "\n"
            return len(enc.encode(text))
        except:
            # Fallback: rough character-based estimate
            total_chars = sum(len(m.get("content", "")) for m in messages)
            return total_chars // 4  # ~4 chars per token
    
    def _truncate_history_if_needed(self):
        """Keep conversation within token budget"""
        # Dynamic history limit based on model context window
        import TIME_ESTIMATOR
        model_context_limit = TIME_ESTIMATOR.get_model_context_limit(self.model_name)
        max_history = 8 if model_context_limit >= 100000 else 3
        
        if len(self.conversation_history) > max_history:
            self.conversation_history = self.conversation_history[-max_history:]
            print(f"{Fore.YELLOW}📝 Truncated conversation history to last {max_history} exchanges{Fore.RESET}")
    
    def _detect_row_range_request(self, user_input):
        """Detect if user is requesting specific row range analysis"""
        import re
        
        # Patterns: "rows 150-200", "row 100 to 150", "analyze rows 50-100", etc.
        patterns = [
            r'rows?\s+(\d+)\s*[-–—to]\s*(\d+)',
            r'rows?\s+(\d+)\s+through\s+(\d+)',
            r'analyze\s+rows?\s+(\d+)\s*[-–—to]\s*(\d+)',
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
        print(f"\n{Fore.LIGHTBLACK_EX}Type 'exit' or 'done' to finish conversation{Fore.RESET}\n")
        
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
                print(f"{Fore.YELLOW}⚠️  Approaching token limit. Truncating history...{Fore.RESET}")
                self._truncate_history_if_needed()
                messages = [
                    {"role": "system", "content": self.system_context}
                ] + self.conversation_history
            
            # Get response
            try:
                print(f"{Fore.YELLOW}🤔 {self.model_name} is analyzing... (streaming){Fore.RESET}\n")
                accum = ""
                
                # Check if model is OpenAI or Ollama
                is_offline = is_local_model(self.model_name)
                
                if is_offline:
                    # Use Ollama for local models
                    try:
                        for chunk in OLLAMA_CLIENT.chat_stream(messages=messages, model_name=self.model_name, json_mode=False):
                            try:
                                # Parse JSON chunk from Ollama streaming response
                                obj = json.loads(chunk)
                                # Extract content from message.content or response field
                                # Skip "thinking" field (internal reasoning, not user-facing)
                                content = ""
                                if "message" in obj and isinstance(obj["message"], dict):
                                    content = obj["message"].get("content", "")
                                elif "response" in obj:
                                    content = obj["response"]
                                
                                # Only print actual content, not thinking/internal reasoning or JSON structure
                                if content:
                                    accum += content
                                    print(content, end="", flush=True)
                            except json.JSONDecodeError:
                                # If it's not JSON, treat as plain text (shouldn't happen but handle gracefully)
                                text = chunk if isinstance(chunk, str) else chunk.decode("utf-8", errors="ignore")
                                accum += text
                                print(text, end="", flush=True)
                            except Exception:
                                # Skip malformed chunks silently
                                continue
                        print("\n")  # Newline after streaming completes
                    except KeyboardInterrupt:
                        print(f"\n{Fore.YELLOW}Cancelled. Showing partial response.{Fore.RESET}")
                else:
                    # Use OpenAI API for cloud models
                    if not self.openai_client:
                        print(f"{Fore.RED}Error: OpenAI client not available for model {self.model_name}{Fore.RESET}")
                        raise Exception("OpenAI client required for cloud models")
                    
                    from openai import OpenAIError
                    try:
                        stream = self.openai_client.chat.completions.create(
                            model=self.model_name,
                            messages=messages,
                            stream=True
                        )
                        for chunk in stream:
                            if chunk.choices[0].delta.content:
                                content = chunk.choices[0].delta.content
                                accum += content
                                print(content, end="", flush=True)
                        print("\n")
                    except KeyboardInterrupt:
                        print(f"\n{Fore.YELLOW}Cancelled. Showing partial response.{Fore.RESET}")
                    except OpenAIError as e:
                        raise Exception(f"OpenAI API error: {e}")
                
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
        """Extract refined analysis from conversation"""
        # Start with original analysis
        refined = self.llm_analysis.copy()
        
        # Look for answer updates in conversation
        for msg in reversed(self.conversation_history):
            if msg.get("role") == "assistant":
                content = msg.get("content", "").lower()
                # Try to extract answer patterns
                import re
                # IP address
                ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', msg.get("content", ""))
                if ip_match and not refined.get("suggested_answer"):
                    refined["suggested_answer"] = ip_match.group(0)
                
                # Filename
                if not refined.get("suggested_answer"):
                    filename_match = re.search(r'[\w\-_]+\.(txt|exe|dll|bat|ps1|sh)', msg.get("content", ""), re.IGNORECASE)
                    if filename_match:
                        refined["suggested_answer"] = filename_match.group(0)
                
                # Confidence updates
                if "very high" in content or "high confidence" in content:
                    refined["confidence"] = "Very High"
                elif "high" in content and refined.get("confidence") == "Low":
                    refined["confidence"] = "High"
        
        # Add conversation insights
        if self.conversation_history:
            insights = []
            for msg in self.conversation_history:
                if msg.get("role") == "user":
                    insights.append(f"User asked: {msg.get('content', '')[:50]}...")
            refined["conversation_insights"] = insights
        
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
    
    # Use selected model directly - no overrides
    # Convert model name for Ollama if needed, but respect user's choice
    if is_local_model(model):
        model_name = get_ollama_model_name(model)
        # For local-mix, use Qwen for chat loop (faster, better for real-time conversation)
        # HYBRID_ENGINE is for batch analysis, not streaming chat
        if model == "local-mix":
            model_name = "qwen3:8b"  # Use Qwen for efficient interactive conversation
    else:
        model_name = model
    
    # For large datasets, use smart sampling for initial context
    # Store full CSV for deep-dive capability
    full_csv = results_csv
    lines = results_csv.split('\n')
    row_count = len([l for l in lines if l.strip()]) - 1
    
    if row_count > 200:
        # Use smart sampling for initial context
        sampled_csv = _smart_sample_csv_for_ctf(
            results_csv,
            flag_intel.get('objective', ''),
            max_chars=50000
        )
        results_csv = sampled_csv  # Use sampled for initial context
    
    # Initialize chat session (will store full_csv internally)
    chat_session = CtfChatSession(
        llm_analysis=llm_analysis,
        results_csv=results_csv,  # Sampled CSV for initial context
        flag_intel=flag_intel,
        kql_query=kql_query,
        session=session,
        model_name=model_name,
        openai_client=openai_client,
        bot_guidance=bot_guidance  # Pass bot's intel interpretation
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
    
    if llm_analysis and llm_analysis.get("suggested_answer"):
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
    
    try:
        choice = input(f"{Fore.LIGHTGREEN_EX}Select [1-{max_choice}]: {Fore.RESET}").strip()
        
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

