"""
CTF Hunt Mode - Dynamic Flag-by-Flag Assistant
Helps with CTF investigations without predefined scenarios
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
    """
    Determine if a model is local/Ollama or cloud/OpenAI
    Local models have zero cost in GUARDRAILS.ALLOWED_MODELS
    """
    if model_name not in GUARDRAILS.ALLOWED_MODELS:
        return False
    
    model_info = GUARDRAILS.ALLOWED_MODELS[model_name]
    # Local models have zero cost
    is_free = (model_info.get("cost_per_million_input", 0) == 0.00 and 
               model_info.get("cost_per_million_output", 0) == 0.00)
    
    return is_free


def get_ollama_model_name(model_name):
    """
    Map friendly model names to Ollama model names
    """
    ollama_mapping = {
        "qwen": "qwen3:8b",
        "gpt-oss:20b": "gpt-oss:20b"
    }
    return ollama_mapping.get(model_name, model_name)


def run_ctf_hunt(openai_client, law_client, workspace_id, model, severity_config,
                 timerange_hours, start_date, end_date):
    """
    Dynamic CTF hunting assistant
    - No predefined scenarios
    - Flag-by-flag assistance
    - User pastes objectives as they encounter flags
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
    # MAIN FLAG HUNTING LOOP (Dynamic)
    # ═══════════════════════════════════════════════════════════════
    
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}🏆 DYNAMIC CTF ASSISTANT")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    print(f"{Fore.WHITE}Work through CTF flags one at a time.{Fore.RESET}")
    print(f"{Fore.WHITE}Paste flag objectives, get query help, analyze results.{Fore.RESET}\n")
    
    try:
        while True:
            # For the very first flag, skip menu and start hunting directly
            if session.state['flags_completed'] == 0:
                # Go straight to Stage 1 (Flag Intel Capture)
                flag_captured = hunt_single_flag(
                    session, openai_client, law_client, workspace_id,
                    model, timerange_hours, start_date, end_date
                )
                
                if not flag_captured:
                    # User cancelled - exit
                    print(f"{Fore.YELLOW}Hunt cancelled.{Fore.RESET}")
                    break
                
                # After first flag, continue to menu
                continue
            
            # Show session context if flags already captured
            if session.state['flags_completed'] > 0:
                display_session_context(session)
            
            # Ask what to do next (only after first flag)
            action = prompt_next_action(session)
            
            if action == 'new_flag':
                # Work on new flag
                flag_captured = hunt_single_flag(
                    session, openai_client, law_client, workspace_id,
                    model, timerange_hours, start_date, end_date
                )
                
                if not flag_captured:
                    # User cancelled this flag
                    continue
            
            elif action == 'rework':
                # Rework last captured flag
                if session.state['flags_completed'] > 0:
                    last_flag_num = session.state['flags_captured'][-1]['flag_number']
                    print(f"\n{Fore.LIGHTCYAN_EX}🔄 Reworking Flag {last_flag_num}...{Fore.RESET}\n")
                    
                    # Remove last flag from state (will be re-captured)
                    session.state['flags_captured'].pop()
                    session.state['flags_completed'] -= 1
                    session.save_state()
                    
                    # Re-hunt it
                    flag_captured = hunt_single_flag(
                        session, openai_client, law_client, workspace_id,
                        model, timerange_hours, start_date, end_date
                    )
                else:
                    print(f"{Fore.YELLOW}No flags to rework yet.{Fore.RESET}")
                    continue
                    
            elif action == 'pause':
                # Pause and exit (keep in_progress status)
                print(f"\n{Fore.LIGHTCYAN_EX}💾 Pausing investigation...{Fore.RESET}\n")
                session.state['status'] = 'in_progress'  # Keep as in_progress
                session.save_state()
                print(f"{Fore.LIGHTGREEN_EX}✓ Session paused. You can resume later.{Fore.RESET}\n")
                break
            
            elif action == 'finish':
                # Finish hunt completely
                session.state['status'] = 'completed'
                break
    
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}{'='*70}")
        print(f"{Fore.YELLOW}Hunt interrupted (Ctrl+C)")
        print(f"{Fore.YELLOW}{'='*70}{Fore.RESET}\n")
        session.state['status'] = 'interrupted'
    
    # ═══════════════════════════════════════════════════════════════
    # WRAP UP
    # ═══════════════════════════════════════════════════════════════
    
    # Final save (status already set above)
    session.save_state()
    
    print(f"{Fore.LIGHTCYAN_EX}💾 Session saved{Fore.RESET}")
    print(f"{Fore.LIGHTGREEN_EX}✓ State: {session.state_file}{Fore.RESET}")
    print(f"{Fore.LIGHTGREEN_EX}✓ Event log: {session.event_log}{Fore.RESET}\n")
    
    # Only show completion if actually finished
    if session.state.get('status') == 'completed':
        # Show final summary
        show_final_summary(session)
        
        # Generate report
        generate_report_prompt(session)
        
        # Optional: Flag logic review
        flag_logic_review_stage(session)
    else:
        # Just paused/interrupted
        print(f"{Fore.LIGHTCYAN_EX}Session paused. Resume anytime by selecting CTF mode again.{Fore.RESET}\n")
    
    return session.state, session.report_file


def hunt_single_flag(session, openai_client, law_client, workspace_id, 
                     model, timerange_hours, start_date, end_date):
    """
    Hunt a single flag dynamically
    User provides objective, system assists
    """
    
    # ═══════════════════════════════════════════════════════════════
    # STAGE 1: Capture Flag Intel (User Input)
    # ═══════════════════════════════════════════════════════════════
    
    flag_intel = capture_flag_intel_stage(session)
    
    if flag_intel is None:
        return False  # User cancelled
    
    # ═══════════════════════════════════════════════════════════════
    # STAGE 2: Build Query with LLM
    # ═══════════════════════════════════════════════════════════════
    
    kql_query = query_building_stage(flag_intel, session, openai_client, model)
    
    if kql_query is None:
        return False  # User cancelled
    
    # ═══════════════════════════════════════════════════════════════
    # STAGE 3: Execute Query
    # ═══════════════════════════════════════════════════════════════
    
    results = execution_stage(kql_query, law_client, workspace_id, timerange_hours, 
                              start_date, end_date, flag_intel)
    
    if results is None:
        # Query failed, ask to retry
        retry = input(f"\n{Fore.YELLOW}Query failed. Retry this flag? [Y/n]: {Fore.RESET}").strip().lower()
        if retry not in ['n', 'no']:
            return hunt_single_flag(session, openai_client, law_client, workspace_id,
                                  model, timerange_hours, start_date, end_date)
        return False
    
    # ═══════════════════════════════════════════════════════════════
    # STAGE 4: Analyze Results with LLM
    # ═══════════════════════════════════════════════════════════════
    
    llm_answer = analysis_stage(results, flag_intel, session, openai_client, model)
    
    # ═══════════════════════════════════════════════════════════════
    # STAGE 5: Capture Flag (with rejection recovery)
    # ═══════════════════════════════════════════════════════════════
    
    while True:
        captured = capture_flag_stage(llm_answer, flag_intel, session, kql_query, results)
        
        if captured:
            return True  # Flag captured successfully
        
        # Flag rejected - offer recovery options
        recovery_action = rejection_recovery_menu()
        
        if recovery_action == 'new_query':
            # Rebuild query from Stage 2
            kql_query = query_building_stage(flag_intel, session, openai_client, model)
            if kql_query is None:
                return False
            results = execution_stage(kql_query, law_client, workspace_id, timerange_hours,
                                     start_date, end_date, flag_intel)
            if results is None:
                return False
            llm_answer = analysis_stage(results, flag_intel, session, openai_client, model)
            continue  # Try capture again
            
        elif recovery_action == 're_analyze':
            # Interactive re-analysis with human guidance
            llm_answer = interactive_analysis_stage(results, flag_intel, session, openai_client, model)
            if llm_answer:
                continue  # Try capture again
            else:
                return False  # User cancelled
            
        elif recovery_action == 'manual':
            # Manual entry
            llm_answer = input(f"\n{Fore.LIGHTCYAN_EX}Enter answer manually: {Fore.RESET}").strip()
            if llm_answer:
                continue  # Try capture again with manual answer
            else:
                return False
                
        elif recovery_action == 'view_raw':
            # Show full raw results with pagination
            print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
            print(f"{Fore.LIGHTCYAN_EX}RAW QUERY RESULTS (FULL)")
            print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
            
            # Parse CSV and display with pagination
            import io
            df_raw = pd.read_csv(io.StringIO(results))
            
            total_rows = len(df_raw)
            page_size = 100
            current_page = 0
            
            while True:
                start_idx = current_page * page_size
                end_idx = min(start_idx + page_size, total_rows)
                
                if start_idx >= total_rows:
                    break
                
                print(f"{Fore.LIGHTCYAN_EX}RESULTS (rows {start_idx + 1}-{end_idx} of {total_rows}):{Fore.RESET}\n")
                page_df = df_raw.iloc[start_idx:end_idx]
                print(page_df.to_string(index=False, max_colwidth=150))
                print(f"\n{Fore.LIGHTCYAN_EX}{'─'*70}{Fore.RESET}\n")
                
                remaining_rows = total_rows - end_idx
                
                if remaining_rows > 0:
                    print(f"{Fore.LIGHTGREEN_EX}[SPACE]{Fore.RESET} Show next {min(page_size, remaining_rows)} rows")
                    print(f"{Fore.LIGHTGREEN_EX}[ENTER]{Fore.RESET} Back to recovery menu\n")
                    
                    try:
                        user_input = input(f"{Fore.LIGHTCYAN_EX}→ {Fore.RESET}")
                        if user_input.strip() == '':
                            break
                        elif user_input.strip().lower() in [' ', 'space', 's']:
                            current_page += 1
                            print()
                            continue
                        else:
                            break
                    except (KeyboardInterrupt, EOFError):
                        break
                else:
                    input(f"{Fore.LIGHTBLACK_EX}Press Enter to return to recovery menu...{Fore.RESET}")
                    break
            
            continue  # Back to recovery menu
            
        elif recovery_action == 'exit':
            # Exit hunt
            return False


def capture_flag_intel_stage(session):
    """Capture flag objective and intel from user"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}📋 FLAG INTEL CAPTURE")
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
    
    # Parse intel to extract structured info
    flag_intel = parse_flag_intel(intel_text, session)
    
    print(f"\n{Fore.LIGHTGREEN_EX}✓ Flag intel captured{Fore.RESET}")
    print(f"{Fore.WHITE}Title: {Fore.LIGHTYELLOW_EX}{flag_intel.get('title', 'Unnamed Flag')}{Fore.RESET}")
    print(f"{Fore.WHITE}Objective: {Fore.LIGHTBLACK_EX}{flag_intel.get('objective', 'N/A')[:80]}...{Fore.RESET}\n")
    
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
        'table_suggestion': '',
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
        
        # Suggest table based on keywords
        if 'login' in line_lower or 'logon' in line_lower or 'rdp' in line_lower or 'auth' in line_lower:
            intel['table_suggestion'] = 'DeviceLogonEvents'
        elif 'process' in line_lower or 'command' in line_lower or 'execution' in line_lower or 'binary' in line_lower:
            intel['table_suggestion'] = 'DeviceProcessEvents'
        elif 'network' in line_lower or 'connection' in line_lower or 'traffic' in line_lower:
            intel['table_suggestion'] = 'DeviceNetworkEvents'
        elif 'file' in line_lower or 'archive' in line_lower or 'zip' in line_lower:
            intel['table_suggestion'] = 'DeviceFileEvents'
        elif 'registry' in line_lower or 'scheduled task' in line_lower or 'persistence' in line_lower:
            intel['table_suggestion'] = 'DeviceRegistryEvents'
    
    return intel


def query_building_stage(flag_intel, session, openai_client, model):
    """Build KQL query with LLM assistance"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}🔨 BUILDING QUERY")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    # Get session context for correlation
    llm_context = session.get_llm_context(current_flag_config=flag_intel, context_type="compact")
    
    # Get comprehensive schema from AZURE_SCHEMA_REFERENCE
    suggested_table = flag_intel.get('table_suggestion', 'DeviceLogonEvents')
    
    # Display available fields to user
    field_list = AZURE_SCHEMA_REFERENCE.get_field_list(suggested_table)
    print(f"{Fore.LIGHTBLACK_EX}Suggested Table: {Fore.WHITE}{suggested_table}{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}Available Fields: {Fore.WHITE}{', '.join(field_list)}{Fore.RESET}\n")
    
    # Generate comprehensive schema prompt for LLM
    schema_prompt = AZURE_SCHEMA_REFERENCE.generate_schema_prompt(suggested_table)
    kql_rules_prompt = AZURE_SCHEMA_REFERENCE.generate_kql_rules_prompt()
    
    # Build comprehensive prompt
    query_prompt = f"""You are a cybersecurity analyst helping with a CTF investigation.
You MUST generate a syntactically correct KQL query using ONLY the exact field names provided.

{llm_context}

CURRENT FLAG:
{flag_intel['raw_intel']}

{schema_prompt}

{kql_rules_prompt}

**CRITICAL RULES:**
1. Use ONLY the field names listed in the schema above
2. Field names are CASE-SENSITIVE - use exact spelling
3. For DeviceLogonEvents, ActionType values are: "LogonSuccess" or "LogonFailed"
4. Do NOT invent field names like Computer, IPAddress, LogonType, LogonSuccess
5. Always use TimeGenerated for time filtering (not Timestamp)
6. If you need to correlate events, be explicit about which table's fields you're using
7. After joins or aggregations, only projected/aggregated fields are available
8. Keep queries simple - avoid complex joins if possible

Use previous flag answers as filters where relevant.

Return ONLY the KQL query, no markdown formatting, no explanations."""
    
    # Validate model before using
    try:
        GUARDRAILS.validate_model(model)
    except Exception as e:
        print(f"{Fore.RED}Model validation failed: {e}{Fore.RESET}")
        print(f"{Fore.YELLOW}Using gpt-4o-mini as fallback{Fore.RESET}")
        model = "gpt-4o-mini"
    
    print(f"{Fore.LIGHTCYAN_EX}🤖 Generating KQL query with {model}...{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}Processing...{Fore.RESET}\n")
    
    try:
        # Route to appropriate client based on model type (dynamic detection)
        if is_local_model(model):
            # Local Ollama model - auto-detected
            model_name = get_ollama_model_name(model)
            kql_query = OLLAMA_CLIENT.chat(
                messages=[{"role": "user", "content": query_prompt}],
                model_name=model_name,
                json_mode=False,  # KQL queries are plain text
                temperature=0.3
            )
            kql_query = kql_query.strip()
        else:
            # OpenAI cloud model - auto-detected
            response = openai_client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": query_prompt}],
                temperature=0.3
            )
            kql_query = response.choices[0].message.content.strip()
        
        # Clean up markdown if present
        if "```" in kql_query:
            kql_query = kql_query.split("```")[1]
            if kql_query.startswith("kql") or kql_query.startswith("sql"):
                kql_query = kql_query[3:]
            kql_query = kql_query.strip()
        
        print(f"{Fore.LIGHTCYAN_EX}SUGGESTED QUERY:{Fore.RESET}\n")
        print(f"{Fore.LIGHTYELLOW_EX}{kql_query}{Fore.RESET}\n")
        print(f"{Fore.LIGHTCYAN_EX}{'─'*70}{Fore.RESET}\n")
        
        # Options
        print(f"  {Fore.LIGHTGREEN_EX}[1]{Fore.RESET} Execute this query")
        print(f"  {Fore.LIGHTYELLOW_EX}[2]{Fore.RESET} Edit query")
        print(f"  {Fore.LIGHTRED_EX}[3]{Fore.RESET} Cancel\n")
        
        choice = input(f"Select [1-3]: ").strip()
        
        if choice == '2':
            # Custom query entry with instructions
            print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
            print(f"{Fore.LIGHTCYAN_EX}✍️  CUSTOM KQL ENTRY")
            print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
            
            print(f"{Fore.WHITE}Enter your KQL query line by line.{Fore.RESET}")
            print(f"{Fore.LIGHTBLACK_EX}Instructions:{Fore.RESET}")
            print(f"{Fore.LIGHTBLACK_EX}  • Type each line of your query{Fore.RESET}")
            print(f"{Fore.LIGHTBLACK_EX}  • Press Enter after each line{Fore.RESET}")
            print(f"{Fore.LIGHTBLACK_EX}  • Type 'DONE' on a new line when finished{Fore.RESET}")
            print(f"{Fore.LIGHTBLACK_EX}  • Press Enter after DONE to submit{Fore.RESET}\n")
            
            print(f"{Fore.LIGHTCYAN_EX}Example:{Fore.RESET}")
            print(f"{Fore.LIGHTBLACK_EX}{'─'*70}")
            print(f"{Fore.LIGHTBLACK_EX}KQL > DeviceLogonEvents")
            print(f"{Fore.LIGHTBLACK_EX}KQL > | where ActionType == \"LogonSuccess\"")
            print(f"{Fore.LIGHTBLACK_EX}KQL > | where DeviceName contains \"flare\"")
            print(f"{Fore.LIGHTBLACK_EX}KQL > | project TimeGenerated, RemoteIP, AccountName")
            print(f"{Fore.LIGHTBLACK_EX}KQL > DONE")
            print(f"{Fore.LIGHTBLACK_EX}{'─'*70}{Fore.RESET}\n")
            
            print(f"{Fore.LIGHTGREEN_EX}Available fields: {Fore.WHITE}{', '.join(field_list)}{Fore.RESET}\n")
            
            custom_lines = []
            while True:
                line = input(f"{Fore.WHITE}KQL > {Fore.RESET}")
                if line.strip().upper() == 'DONE':
                    break
                custom_lines.append(line)
            
            if not custom_lines:
                print(f"{Fore.YELLOW}No query entered. Using LLM-generated query.{Fore.RESET}\n")
            else:
                print(f"\n{Fore.LIGHTBLACK_EX}Processing custom query...{Fore.RESET}\n")
                kql_query = '\n'.join(custom_lines)
        
        elif choice == '3':
            return None
        
        return kql_query
        
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Fore.RESET}")
        return None


def execution_stage(kql_query, law_client, workspace_id, timerange_hours, 
                    start_date, end_date, flag_intel):
    """Execute KQL query and display results"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}⚡ EXECUTING QUERY")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    try:
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
        
        # Paginated results display
        total_rows = len(df)
        page_size = 100
        current_page = 0
        
        while True:
            start_idx = current_page * page_size
            end_idx = min(start_idx + page_size, total_rows)
            
            if start_idx >= total_rows:
                break
            
            # Display current page
            print(f"{Fore.LIGHTCYAN_EX}RESULTS (rows {start_idx + 1}-{end_idx} of {total_rows}):{Fore.RESET}\n")
            page_df = df.iloc[start_idx:end_idx]
            print(page_df.to_string(index=False, max_colwidth=150))
            print(f"\n{Fore.LIGHTCYAN_EX}{'─'*70}{Fore.RESET}\n")
            
            # Show navigation instructions
            remaining_rows = total_rows - end_idx
            
            if remaining_rows > 0:
                print(f"{Fore.LIGHTGREEN_EX}[SPACE]{Fore.RESET} Show next {min(page_size, remaining_rows)} rows")
                print(f"{Fore.LIGHTGREEN_EX}[ENTER]{Fore.RESET} Continue to next stage (analysis)")
                print(f"{Fore.LIGHTBLACK_EX}Note: LLM receives all {total_rows} rows for analysis{Fore.RESET}\n")
                
                try:
                    user_input = input(f"{Fore.LIGHTCYAN_EX}→ {Fore.RESET}")
                    
                    if user_input.strip() == '':  # Enter pressed
                        break  # Move to next stage
                    elif user_input.strip().lower() in [' ', 'space', 's']:  # Space or 's'
                        current_page += 1
                        print()  # Blank line before next page
                        continue
                    else:  # Any other input
                        break  # Move to next stage
                except (KeyboardInterrupt, EOFError):
                    break
            else:
                # Last page - just show continue message
                print(f"{Fore.LIGHTGREEN_EX}[ENTER]{Fore.RESET} Continue to next stage (analysis)\n")
                input(f"{Fore.LIGHTCYAN_EX}→ {Fore.RESET}")
                break
        
        print()
        
        return df.to_csv(index=False)
        
    except Exception as e:
        print(f"{Fore.RED}Error executing query: {e}{Fore.RESET}")
        return None


def extract_answer_from_text(text):
    """Extract answer from LLM analysis text"""
    lines = text.split('\n')
    for line in lines:
        if line.strip().upper().startswith('ANSWER:'):
            return line.split(':', 1)[1].strip()
    # If no explicit ANSWER: line, return first non-empty line
    for line in lines:
        if line.strip():
            return line.strip()
    return text.strip()


def interactive_analysis_stage(results_csv, flag_intel, session, openai_client, model):
    """Interactive analysis with human-in-the-loop refinement"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}🧠 INTERACTIVE ANALYSIS MODE")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    print(f"{Fore.WHITE}Chat with the LLM to refine the analysis.{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}Guide the LLM to narrow down the answer based on the results.{Fore.RESET}\n")
    
    # Parse results for display
    import io
    df_results = pd.read_csv(io.StringIO(results_csv))
    
    # Get session context
    llm_context = session.get_llm_context(current_flag_config=flag_intel, context_type="compact")
    
    # Initialize conversation history
    conversation = []
    
    # System message with context
    system_prompt = f"""You are a cybersecurity analyst helping find the answer to a CTF flag.

{llm_context}

FLAG OBJECTIVE:
{flag_intel['raw_intel']}

QUERY RESULTS (CSV format):
{results_csv[:8000]}

Analyze the results and help find the answer. When the human provides guidance or asks questions, use that to refine your analysis.

When you're confident about the answer, state it clearly as:
ANSWER: <the answer>
"""
    
    conversation.append({"role": "system", "content": system_prompt})
    
    # Initial analysis
    print(f"{Fore.LIGHTCYAN_EX}Initial LLM analysis...{Fore.RESET}\n")
    
    initial_prompt = "Based on the flag objective and query results, what do you think the answer is? Provide your reasoning."
    conversation.append({"role": "user", "content": initial_prompt})
    
    # Get initial analysis
    if is_local_model(model):
        model_name = get_ollama_model_name(model)
        response_text = OLLAMA_CLIENT.chat(
            messages=conversation,
            model_name=model_name,
            json_mode=False,
            temperature=0.3
        )
    else:
        response = openai_client.chat.completions.create(
            model=model,
            messages=conversation,
            temperature=0.3
        )
        response_text = response.choices[0].message.content
    
    conversation.append({"role": "assistant", "content": response_text})
    
    print(f"{Fore.LIGHTCYAN_EX}LLM:{Fore.RESET}\n{Fore.WHITE}{response_text}{Fore.RESET}\n")
    print(f"{Fore.LIGHTCYAN_EX}{'─'*70}{Fore.RESET}\n")
    
    # Interactive loop
    while True:
        print(f"{Fore.LIGHTGREEN_EX}[1]{Fore.RESET} Provide guidance/ask question")
        print(f"{Fore.LIGHTGREEN_EX}[2]{Fore.RESET} View results (paginated)")
        print(f"{Fore.LIGHTGREEN_EX}[3]{Fore.RESET} Accept current answer")
        print(f"{Fore.LIGHTRED_EX}[4]{Fore.RESET} Exit interactive mode\n")
        
        choice = input(f"{Fore.LIGHTCYAN_EX}Select [1-4]: {Fore.RESET}").strip()
        
        if choice == '1':
            # Get user guidance
            print(f"\n{Fore.LIGHTCYAN_EX}Your guidance/question:{Fore.RESET}")
            print(f"{Fore.LIGHTBLACK_EX}Examples:{Fore.RESET}")
            print(f"{Fore.LIGHTBLACK_EX}  • Look for the earliest IP with failed attempts followed by success{Fore.RESET}")
            print(f"{Fore.LIGHTBLACK_EX}  • Filter by only public IPs{Fore.RESET}")
            print(f"{Fore.LIGHTBLACK_EX}  • Focus on the slflare account{Fore.RESET}")
            print(f"{Fore.LIGHTBLACK_EX}  • What's the pattern in the timestamps?{Fore.RESET}\n")
            
            guidance = input(f"{Fore.WHITE}You: {Fore.RESET}").strip()
            
            if not guidance:
                continue
            
            conversation.append({"role": "user", "content": guidance})
            
            print(f"\n{Fore.LIGHTBLACK_EX}LLM analyzing with your guidance...{Fore.RESET}\n")
            
            # Get refined analysis
            if is_local_model(model):
                model_name = get_ollama_model_name(model)
                response_text = OLLAMA_CLIENT.chat(
                    messages=conversation,
                    model_name=model_name,
                    json_mode=False,
                    temperature=0.3
                )
            else:
                response = openai_client.chat.completions.create(
                    model=model,
                    messages=conversation,
                    temperature=0.3
                )
                response_text = response.choices[0].message.content
            
            conversation.append({"role": "assistant", "content": response_text})
            
            print(f"{Fore.LIGHTCYAN_EX}LLM:{Fore.RESET}\n{Fore.WHITE}{response_text}{Fore.RESET}\n")
            print(f"{Fore.LIGHTCYAN_EX}{'─'*70}{Fore.RESET}\n")
            
        elif choice == '2':
            # View results with pagination
            print()
            current_page = 0
            while True:
                start_idx = current_page * 100
                end_idx = min(start_idx + 100, len(df_results))
                
                if start_idx >= len(df_results):
                    break
                
                print(f"{Fore.LIGHTCYAN_EX}RESULTS (rows {start_idx + 1}-{end_idx} of {len(df_results)}):{Fore.RESET}\n")
                pd.set_option('display.max_columns', None)
                pd.set_option('display.width', None)
                pd.set_option('display.max_colwidth', 150)
                print(df_results.iloc[start_idx:end_idx].to_string(index=False))
                print(f"\n{Fore.LIGHTCYAN_EX}{'─'*70}{Fore.RESET}\n")
                
                if end_idx < len(df_results):
                    print(f"{Fore.LIGHTGREEN_EX}[SPACE]{Fore.RESET} Next page | {Fore.LIGHTGREEN_EX}[ENTER]{Fore.RESET} Back to analysis\n")
                    user_input = input(f"{Fore.LIGHTCYAN_EX}→ {Fore.RESET}")
                    if user_input.strip() == '' or user_input.strip().lower() not in [' ', 'space', 's']:
                        break
                    current_page += 1
                    print()
                else:
                    input(f"{Fore.LIGHTBLACK_EX}Press Enter to return...{Fore.RESET}")
                    break
            print()
            
        elif choice == '3':
            # Extract answer from last LLM response
            answer = extract_answer_from_text(conversation[-1]['content'])
            return answer
            
        elif choice == '4':
            # Exit
            print(f"{Fore.YELLOW}Interactive analysis cancelled.{Fore.RESET}")
            return None
        
        else:
            continue


def analysis_stage(results_csv, flag_intel, session, openai_client, model):
    """Analyze results with LLM - with results review"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}🧠 ANALYZING RESULTS")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    # Parse and display results with pagination for review
    import io
    df_results = pd.read_csv(io.StringIO(results_csv))
    
    total_rows = len(df_results)
    page_size = 100
    current_page = 0
    
    print(f"{Fore.WHITE}Review query results before LLM analysis.{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}Total records: {total_rows}{Fore.RESET}\n")
    
    # Paginated display
    while True:
        start_idx = current_page * page_size
        end_idx = min(start_idx + page_size, total_rows)
        
        if start_idx >= total_rows:
            break
        
        print(f"{Fore.LIGHTCYAN_EX}RESULTS (rows {start_idx + 1}-{end_idx} of {total_rows}):{Fore.RESET}\n")
        page_df = df_results.iloc[start_idx:end_idx]
        
        # Display with all columns visible (wide format)
        pd.set_option('display.max_columns', None)
        pd.set_option('display.width', None)
        pd.set_option('display.max_colwidth', 150)
        
        print(page_df.to_string(index=False))
        print(f"\n{Fore.LIGHTCYAN_EX}{'─'*70}{Fore.RESET}\n")
        
        remaining_rows = total_rows - end_idx
        
        if remaining_rows > 0:
            print(f"{Fore.LIGHTGREEN_EX}[SPACE]{Fore.RESET} Show next {min(page_size, remaining_rows)} rows")
            print(f"{Fore.LIGHTGREEN_EX}[ENTER]{Fore.RESET} Continue to LLM analysis\n")
            
            try:
                user_input = input(f"{Fore.LIGHTCYAN_EX}→ {Fore.RESET}")
                if user_input.strip() == '':
                    break  # Continue to analysis
                elif user_input.strip().lower() in [' ', 'space', 's']:
                    current_page += 1
                    print()
                    continue
                else:
                    break
            except (KeyboardInterrupt, EOFError):
                break
        else:
            print(f"{Fore.LIGHTGREEN_EX}[ENTER]{Fore.RESET} Continue to LLM analysis\n")
            input(f"{Fore.LIGHTCYAN_EX}→ {Fore.RESET}")
            break
    
    print(f"\n{Fore.LIGHTBLACK_EX}Starting LLM analysis...{Fore.RESET}\n")
    
    # Get session context
    llm_context = session.get_llm_context(current_flag_config=flag_intel, context_type="full")
    
    analysis_prompt = f"""You are analyzing threat hunting results for a CTF flag.

{llm_context}

FLAG OBJECTIVE:
{flag_intel['raw_intel']}

QUERY RESULTS:
{results_csv[:4000]}

Based on the objective, what is the answer?

Provide:
1. ANSWER: <the actual answer in correct format>
2. EVIDENCE: Key supporting data points
3. REASONING: Why this is the answer

Keep it concise."""
    
    print(f"{Fore.LIGHTCYAN_EX}Analyzing with {model}...{Fore.RESET}\n")
    
    try:
        # Route to appropriate client based on model type (dynamic detection)
        if is_local_model(model):
            # Local Ollama model - auto-detected
            model_name = get_ollama_model_name(model)
            analysis = OLLAMA_CLIENT.chat(
                messages=[{"role": "user", "content": analysis_prompt}],
                model_name=model_name,
                json_mode=False,
                temperature=0.3
            )
            analysis = analysis.strip()
        else:
            # OpenAI cloud model - auto-detected
            response = openai_client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": analysis_prompt}],
                temperature=0.3
            )
            analysis = response.choices[0].message.content.strip()
        
        print(f"{Fore.LIGHTCYAN_EX}FINDING:{Fore.RESET}\n")
        print(f"{Fore.WHITE}{analysis}{Fore.RESET}\n")
        print(f"{Fore.LIGHTCYAN_EX}{'─'*70}{Fore.RESET}\n")
        
        # Extract answer
        llm_answer = extract_answer(analysis)
        
        return llm_answer
        
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Fore.RESET}")
        return None


def extract_answer(analysis):
    """Extract answer from LLM analysis"""
    for line in analysis.split('\n'):
        if line.strip().upper().startswith('ANSWER:'):
            return line.split(':', 1)[1].strip()
    return analysis.split('\n')[0].strip()


def rejection_recovery_menu():
    """Show options when flag answer is rejected"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}⚠️  ANSWER REJECTED - RECOVERY OPTIONS")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    print(f"  {Fore.LIGHTGREEN_EX}[1]{Fore.RESET} 🔨 Build new query (start from Stage 2)")
    print(f"  {Fore.LIGHTYELLOW_EX}[2]{Fore.RESET} 🧠 Re-analyze same results (new LLM analysis)")
    print(f"  {Fore.LIGHTCYAN_EX}[3]{Fore.RESET} ✍️  Enter answer manually")
    print(f"  {Fore.LIGHTBLACK_EX}[4]{Fore.RESET} 👁️  View raw results")
    print(f"  {Fore.LIGHTRED_EX}[5]{Fore.RESET} 🚪 Exit hunt\n")
    
    try:
        choice = input(f"{Fore.LIGHTGREEN_EX}Select [1-5]: {Fore.RESET}").strip()
        
        if choice == '1':
            return 'new_query'
        elif choice == '2':
            return 're_analyze'
        elif choice == '3':
            return 'manual'
        elif choice == '4':
            return 'view_raw'
        elif choice == '5':
            return 'exit'
        else:
            return 'exit'  # Default to exit
            
    except (KeyboardInterrupt, EOFError):
        return 'exit'


def capture_flag_stage(llm_answer, flag_intel, session, kql_query, results):
    """Capture flag answer - simplified"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}🎯 FLAG ANSWER")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    print(f"{Fore.LIGHTCYAN_EX}SUGGESTED:{Fore.RESET} {Fore.LIGHTYELLOW_EX}{llm_answer}{Fore.RESET}\n")
    
    # Simple choice
    print(f"  {Fore.LIGHTGREEN_EX}[1]{Fore.RESET} ✓ Accept this answer")
    print(f"  {Fore.LIGHTRED_EX}[2]{Fore.RESET} ✗ Reject (show recovery options)\n")
    
    choice = input(f"{Fore.LIGHTGREEN_EX}Select [1-2]: {Fore.RESET}").strip()
    
    if choice == '2' or choice.lower() in ['n', 'no', 'reject']:
        # Reject - will trigger recovery menu
        return False
    
    # Accept - capture the flag
    notes = input(f"\n{Fore.LIGHTCYAN_EX}Notes (optional): {Fore.RESET}").strip()
    
    session.capture_flag(
        flag_number=flag_intel['flag_number'],
        title=flag_intel['title'],
        answer=llm_answer,
        notes=notes,
        kql_used=kql_query,
        table_queried=flag_intel.get('table_suggestion', ''),
        stage=flag_intel.get('mitre', '').split('-')[0].strip() if '-' in flag_intel.get('mitre', '') else '',
        mitre=flag_intel.get('mitre', '')
    )
    
    print(f"\n{Fore.LIGHTGREEN_EX}{'='*70}")
    print(f"{Fore.LIGHTGREEN_EX}✓ FLAG {flag_intel['flag_number']} CAPTURED: {llm_answer}")
    print(f"{Fore.LIGHTGREEN_EX}{'='*70}{Fore.RESET}\n")
    
    return True


def prompt_next_action(session):
    """Ask what user wants to do next"""
    
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}WHAT'S NEXT?")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    print(f"  {Fore.LIGHTYELLOW_EX}[1]{Fore.RESET} 🔄 Rework current flag (different query/approach)")
    print(f"      → Build new query for same flag, overwrite if different answer\n")
    
    print(f"  {Fore.LIGHTGREEN_EX}[2]{Fore.RESET} ➡️  Work on next flag")
    print(f"      → Start a new flag investigation\n")
    
    print(f"  {Fore.LIGHTMAGENTA_EX}[3]{Fore.RESET} 💾 Pause and exit")
    print(f"      → Save progress and exit cleanly (resume anytime)\n")
    
    print(f"  {Fore.LIGHTCYAN_EX}[4]{Fore.RESET} 🏁 Finish hunt (complete investigation)")
    print(f"      → Generate reports, add detailed notes, mark as done\n")
    
    try:
        choice = input(f"{Fore.LIGHTGREEN_EX}Select [1-4]: {Fore.RESET}").strip()
        
        if choice == '1':
            return 'rework'
        elif choice == '2' or not choice:
            return 'new_flag'
        elif choice == '3':
            return 'pause'
        elif choice == '4':
            return 'finish'
        else:
            return 'new_flag'  # Default
            
    except (KeyboardInterrupt, EOFError):
        return 'pause'  # Default to pause on interrupt


def display_session_context(session):
    """Display accumulated flags and IOCs"""
    
    state = session.state
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}📚 SESSION MEMORY")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    print(f"{Fore.WHITE}Flags Captured: {Fore.LIGHTGREEN_EX}{state['flags_completed']}{Fore.RESET}\n")
    
    # Show recent flags
    for flag in state['flags_captured'][-5:]:  # Last 5
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
    print(f"{Fore.LIGHTGREEN_EX}🎯 INVESTIGATION SUMMARY")
    print(f"{Fore.LIGHTGREEN_EX}{'='*70}{Fore.RESET}\n")
    
    print(f"{Fore.WHITE}Project: {Fore.LIGHTYELLOW_EX}{state.get('project_name', 'N/A')}{Fore.RESET}")
    print(f"{Fore.WHITE}Flags Captured: {Fore.LIGHTGREEN_EX}{state['flags_completed']}{Fore.RESET}")
    print(f"{Fore.WHITE}Duration: {Fore.LIGHTYELLOW_EX}{session._calculate_duration()}{Fore.RESET}\n")
    
    # All flags
    print(f"{Fore.LIGHTCYAN_EX}ALL FLAGS:{Fore.RESET}")
    for flag in state['flags_captured']:
        print(f"  {Fore.LIGHTGREEN_EX}✓{Fore.RESET} {flag['title']}: {Fore.LIGHTYELLOW_EX}{flag['answer']}{Fore.RESET}")
    
    print()


def generate_report_prompt(session):
    """Prompt to generate report"""
    
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}💾 GENERATE REPORT")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    gen = input(f"Generate investigation report? [Y/n]: ").strip().lower()
    
    if gen not in ['n', 'no']:
        session.generate_report()
        print(f"\n{Fore.LIGHTGREEN_EX}✓ Report saved: {session.report_file}{Fore.RESET}\n")


def flag_logic_review_stage(session):
    """Optional: Capture detailed investigation notes"""
    
    add = input(f"Add detailed investigation notes? [y/N]: ").strip().lower()
    
    if add not in ['y', 'yes']:
        return
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}📝 DETAILED NOTES CAPTURE")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    print(f"{Fore.WHITE}Paste your complete investigation writeup (all flags).{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}Type 'DONE' when finished{Fore.RESET}\n")
    
    notes_lines = []
    while True:
        try:
            line = input()
            if line.strip().upper() == 'DONE':
                break
            notes_lines.append(line)
        except (KeyboardInterrupt, EOFError):
            break
    
    detailed_notes = '\n'.join(notes_lines)
    
    logic_file = session.session_dir + "flag_investigation_logic.json"
    
    logic_data = {
        "project_name": session.state.get('project_name'),
        "flags_captured": session.state['flags_captured'],
        "detailed_writeup": detailed_notes
    }
    
    with open(logic_file, 'w', encoding='utf-8') as f:
        json.dump(logic_data, f, indent=2, ensure_ascii=False)
    
    print(f"\n{Fore.LIGHTGREEN_EX}✓ Detailed notes saved: {logic_file}{Fore.RESET}\n")


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
    
    # Create new session
    session = CTF_SESSION_MANAGER.SessionMemory(
        scenario_name="dynamic_ctf",
        project_name=project_name
    )
    session.state['project_name'] = project_name
    session.state['total_flags'] = None  # Unknown total
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
    """Rename a project and update all associated files"""
    
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
    print(f"{Fore.LIGHTGREEN_EX}✓ Files updated:{Fore.RESET}")
    print(f"  {Fore.WHITE}• {new_state_file}{Fore.RESET}")
    print(f"  {Fore.WHITE}• {new_event_log}{Fore.RESET}")
    if os.path.exists(new_report):
        print(f"  {Fore.WHITE}• {new_report}{Fore.RESET}")
    print()
    
    # Update session data
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
            # Rename project
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
            return None  # Will create new
        
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
                    break  # Return to main menu
                
                try:
                    idx = int(project_choice) - 1
                    if 0 <= idx < len(existing_sessions):
                        # Show project submenu
                        result = prompt_project_action(existing_sessions[idx])
                        
                        if result == 'back':
                            continue  # Stay in project list
                        elif result:
                            return result  # Session loaded, continue
                except:
                    print(f"{Fore.RED}Invalid choice.{Fore.RESET}")
        
        else:
            print(f"{Fore.RED}Invalid choice. Please select C or N.{Fore.RESET}")

