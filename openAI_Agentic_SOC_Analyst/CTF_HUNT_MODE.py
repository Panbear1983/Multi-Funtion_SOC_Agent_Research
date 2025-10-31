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
    if model_name not in GUARDRAILS.ALLOWED_MODELS:
        return False
    model_info = GUARDRAILS.ALLOWED_MODELS[model_name]
    return (model_info.get("cost_per_million_input", 0) == 0.00 and 
            model_info.get("cost_per_million_output", 0) == 0.00)


def get_ollama_model_name(model_name):
    """Map friendly model names to Ollama model names"""
    ollama_mapping = {
        "qwen": "qwen3:8b",
        "gpt-oss:20b": "gpt-oss:20b"
    }
    return ollama_mapping.get(model_name, model_name)


def run_ctf_hunt(openai_client, law_client, workspace_id, model, severity_config,
                 timerange_hours, start_date, end_date, data_source='MDE'):
    """
    Human-driven CTF hunting with LLM advisory
    - Human writes all KQL queries
    - Supports both MDE and Azure Sentinel data sources
    - LLM provides interpretation and guidance
    - Complete documentation of hunt process
    """
    
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
                    model, timerange_hours, start_date, end_date
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
                    model, timerange_hours, start_date, end_date
                )
                
                if not flag_captured:
                    continue
            
            elif action == 'delete_and_redo':
                # Flag already deleted, just continue to hunt it again
                flag_captured = hunt_single_flag(
                    session, openai_client, law_client, workspace_id,
                    model, timerange_hours, start_date, end_date
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
                     model, timerange_hours, start_date, end_date):
    """
    Hunt a single flag - human-driven with LLM advisory
    """
    
    # ═══════════════════════════════════════════════════════════════
    # STAGE 1: FLAG INTEL CAPTURE (Keep as is)
    # ═══════════════════════════════════════════════════════════════
    
    flag_intel = capture_flag_intel_stage(session)
    
    if flag_intel is None:
        return False
    
    # ═══════════════════════════════════════════════════════════════
    # STAGE 2: BOT'S INTEL INTERPRETATION (NEW)
    # ═══════════════════════════════════════════════════════════════
    
    bot_guidance = bot_interpretation_stage(flag_intel, session, openai_client, model)
    
    if bot_guidance is None:
        return False
    
    # ═══════════════════════════════════════════════════════════════
    # STAGES 3-6: KQL ENTRY → EXECUTION → RESULTS → DOCUMENTATION
    # Loop allows rewriting KQL without redoing intel capture
    # ═══════════════════════════════════════════════════════════════
    
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
        
        # STAGE 6: RESULT DOCUMENTATION MENU
        doc_action = result_documentation_menu()
        
        if doc_action == 'rewrite_kql':
            # Loop back to Stage 3 (HUMAN KQL ENTRY)
            print(f"\n{Fore.LIGHTCYAN_EX}Returning to KQL entry...{Fore.RESET}\n")
            continue  # Back to Stage 3
        
        elif doc_action == 'document':
            # Document the result for JSON
            documented = document_result_stage(flag_intel, session, kql_query, results)
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
    
    print(f"{Fore.LIGHTBLACK_EX}LLM analyzing flag intel...{Fore.RESET}\n")
    
    try:
        # Get LLM interpretation
        if is_local_model(model):
            model_name = get_ollama_model_name(model)
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
    """Execute KQL query against MDE or Azure Sentinel"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}⚡ EXECUTING QUERY")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    try:
        # Check if using MDE or Azure Sentinel client
        if hasattr(law_client, 'query_advanced_hunting'):
            # MDE client
            print(f"{Fore.LIGHTBLACK_EX}[Querying MDE Advanced Hunting]{Fore.RESET}\n")
            response = law_client.query_advanced_hunting(kql_query)
        else:
            # Azure Sentinel / Log Analytics client
            print(f"{Fore.LIGHTBLACK_EX}[Querying Azure Log Analytics]{Fore.RESET}\n")
            response = law_client.query_workspace(
                workspace_id=workspace_id,
                query=kql_query,
                timespan=timedelta(hours=timerange_hours)
            )
        
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
# STAGE 6: RESULT DOCUMENTATION MENU
# ═══════════════════════════════════════════════════════════════

def result_documentation_menu():
    """Menu for result documentation"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}📝 RESULT DOCUMENTATION")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    print(f"  {Fore.LIGHTYELLOW_EX}[1]{Fore.RESET} ↩️  Rewrite KQL query (back to query entry)")
    print(f"  {Fore.LIGHTGREEN_EX}[2]{Fore.RESET} ✍️  Document result (capture KQL + output)\n")
    
    choice = input(f"{Fore.LIGHTGREEN_EX}Select [1-2]: {Fore.RESET}").strip()
    
    if choice == '1':
        return 'rewrite_kql'
    else:
        return 'document'


def document_result_stage(flag_intel, session, kql_query, results_csv):
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
    
    # Get the answer from human
    print(f"{Fore.LIGHTGREEN_EX}From the results you reviewed, enter the answer:{Fore.RESET}")
    try:
        answer = input(f"{Fore.WHITE}Answer: {Fore.RESET}").strip()
        if not answer:
            print(f"{Fore.YELLOW}No answer provided.{Fore.RESET}")
            return False
        
        # Get relevant output rows (manual paste)
        print(f"\n{Fore.LIGHTCYAN_EX}Paste the specific row(s) that contain this answer:{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}Copy relevant rows from the query results above.{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}You can paste 1 row or multiple rows.{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}Type 'DONE' on a new line when finished.{Fore.RESET}\n")
        
        print(f"{Fore.LIGHTCYAN_EX}Example:{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}{'─'*70}")
        print(f"{Fore.LIGHTBLACK_EX}2025-09-14 03:45:12, slflarewinsysmo, slflare, 159.26.106.84, LogonSuccess")
        print(f"{Fore.LIGHTBLACK_EX}DONE")
        print(f"{Fore.LIGHTBLACK_EX}{'─'*70}{Fore.RESET}\n")
        
        output_lines = []
        while True:
            line = input()
            if line.strip().upper() == 'DONE':
                break
            output_lines.append(line)
        
        query_output = '\n'.join(output_lines) if output_lines else "No output captured"
        
        # Finding notes
        print(f"\n{Fore.LIGHTCYAN_EX}Finding notes (how you found the answer):{Fore.RESET}")
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
    """Find all incomplete sessions"""
    
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
            
            if state.get('status') == 'in_progress':
                existing.append({
                    'file': summary_file,
                    'state': state,
                    'project_name': state.get('project_name', 'Unknown'),
                    'flags_completed': state.get('flags_completed', 0)
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


def prompt_project_action(session_data):
    """Submenu for selected project: Continue or Rename"""
    
    while True:
        print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
        print(f"{Fore.LIGHTCYAN_EX}📂 SELECTED: {Fore.LIGHTYELLOW_EX}{session_data['project_name']}{Fore.RESET}")
        print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
        print(f"{Fore.WHITE}Flags completed: {session_data['flags_completed']}{Fore.RESET}\n")
        
        print(f"{Fore.LIGHTGREEN_EX}[1]{Fore.RESET} Continue hunt")
        print(f"{Fore.LIGHTYELLOW_EX}[2]{Fore.RESET} Rename project")
        print(f"{Fore.LIGHTBLACK_EX}[B]{Fore.RESET} Back to session list\n")
        
        choice = input(f"{Fore.LIGHTGREEN_EX}Select [1-2/B]: {Fore.RESET}").strip().upper()
        
        if choice == '1':
            # Load and return session
            session = CTF_SESSION_MANAGER.SessionMemory(
                scenario_name="dynamic_ctf",
                project_name=session_data['project_name']
            )
            session.state = session_data['state']
            session.state_file = session_data['file']
            
            base_name = os.path.basename(session_data['file']).replace('_summary.json', '')
            session.event_log = f"{session.session_dir}{base_name}.jsonl"
            session.report_file = f"{session.session_dir}{base_name}_report.md"
            
            return session
            
        elif choice == '2':
            # Rename project (updates JSON filename too)
            session_data = rename_project(session_data, None)
            # Loop back to show updated name
            
        elif choice == 'B':
            return 'back'
        
        else:
            print(f"{Fore.RED}Invalid choice. Please select 1, 2, or B.{Fore.RESET}")


def prompt_resume_or_new(existing_sessions):
    """Enhanced menu: Resume existing hunt or start new"""
    
    while True:
        print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
        print(f"{Fore.LIGHTCYAN_EX}🔄 EXISTING SESSIONS FOUND")
        print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
        
        print(f"{Fore.LIGHTCYAN_EX}You have {len(existing_sessions)} unfinished investigation(s):{Fore.RESET}\n")
        
        for i, sess in enumerate(existing_sessions, 1):
            print(f"  {Fore.LIGHTBLACK_EX}•{Fore.RESET} {Fore.LIGHTYELLOW_EX}{sess['project_name']}{Fore.RESET} ({sess['flags_completed']} flags)")
        
        print(f"\n{Fore.LIGHTGREEN_EX}[C]{Fore.RESET} Continue with existing hunts")
        print(f"{Fore.LIGHTGREEN_EX}[N]{Fore.RESET} Start new investigation\n")
        
        choice = input(f"{Fore.LIGHTGREEN_EX}Select [C/N]: {Fore.RESET}").strip().upper()
        
        if choice == 'N' or not choice:
            return None
        
        elif choice == 'C':
            # Show detailed project list
            while True:
                print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
                print(f"{Fore.LIGHTCYAN_EX}📋 SELECT INVESTIGATION TO RESUME")
                print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
                
                for i, sess in enumerate(existing_sessions, 1):
                    print(f"{Fore.LIGHTCYAN_EX}[{i}]{Fore.RESET} {Fore.LIGHTYELLOW_EX}{sess['project_name']}{Fore.RESET}")
                    print(f"    Flags: {sess['flags_completed']}")
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
                        elif result:
                            return result
                except:
                    print(f"{Fore.RED}Invalid choice.{Fore.RESET}")
        
        else:
            print(f"{Fore.RED}Invalid choice. Please select C or N.{Fore.RESET}")

