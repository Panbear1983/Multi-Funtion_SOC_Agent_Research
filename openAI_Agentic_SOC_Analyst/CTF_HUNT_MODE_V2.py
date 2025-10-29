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
import EXECUTOR
import PROMPT_MANAGEMENT
import MODEL_SELECTOR
import pandas as pd


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
        if session is None:
            return None, None
        
        project_name = session.state.get('project_name', 'CTF Hunt')
        print(f"\n{Fore.LIGHTGREEN_EX}✓ Resumed: {project_name}{Fore.RESET}")
        print(f"{Fore.WHITE}Flags captured so far: {session.state['flags_completed']}{Fore.RESET}\n")
    else:
        # ═══════════════════════════════════════════════════════════════
        # NEW SESSION: PROMPT FOR PROJECT NAME
        # ═══════════════════════════════════════════════════════════════
        
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
            # Show session context if flags already captured
            if session.state['flags_completed'] > 0:
                display_session_context(session)
            
            # Ask if user wants to work on a flag
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
                    
            elif action == 'finish':
                # Finish hunt
                break
            
            elif action == 'exit':
                # Exit without finishing
                break
    
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Hunt interrupted{Fore.RESET}\n")
    
    # ═══════════════════════════════════════════════════════════════
    # WRAP UP
    # ═══════════════════════════════════════════════════════════════
    
    # Final save
    session.state['status'] = 'completed'
    session.save_state()
    
    print(f"{Fore.LIGHTCYAN_EX}💾 Saving session...{Fore.RESET}")
    print(f"{Fore.LIGHTGREEN_EX}✓ State saved to: {session.state_file}{Fore.RESET}\n")
    
    # Show final summary
    show_final_summary(session)
    
    # Generate report
    generate_report_prompt(session)
    
    # Optional: Flag logic review
    flag_logic_review_stage(session)
    
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
    # STAGE 5: Capture Flag
    # ═══════════════════════════════════════════════════════════════
    
    captured = capture_flag_stage(llm_answer, flag_intel, session, kql_query)
    
    return captured


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
    
    # Build prompt
    query_prompt = f"""You are a cybersecurity analyst helping with a CTF investigation.

{llm_context}

CURRENT FLAG:
{flag_intel['raw_intel']}

Generate a KQL query to find the answer to this flag.
Use previous flag answers as filters where relevant.
Suggested table: {flag_intel.get('table_suggestion', 'DeviceLogonEvents')}

Return ONLY the KQL query, no explanations."""
    
    print(f"{Fore.LIGHTCYAN_EX}🤖 Generating KQL query...{Fore.RESET}\n")
    
    try:
        response = openai_client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": query_prompt}],
            temperature=0.3
        )
        
        kql = response.choices[0].message.content.strip()
        
        # Clean up markdown if present
        if "```" in kql:
            kql = kql.split("```")[1]
            if kql.startswith("kql") or kql.startswith("sql"):
                kql = kql[3:]
            kql = kql.strip()
        
        print(f"{Fore.LIGHTCYAN_EX}SUGGESTED QUERY:{Fore.RESET}\n")
        print(f"{Fore.LIGHTYELLOW_EX}{kql}{Fore.RESET}\n")
        print(f"{Fore.LIGHTCYAN_EX}{'─'*70}{Fore.RESET}\n")
        
        # Options
        print(f"  {Fore.LIGHTGREEN_EX}[1]{Fore.RESET} Execute this query")
        print(f"  {Fore.LIGHTYELLOW_EX}[2]{Fore.RESET} Edit query")
        print(f"  {Fore.LIGHTRED_EX}[3]{Fore.RESET} Cancel\n")
        
        choice = input(f"Select [1-3]: ").strip()
        
        if choice == '2':
            print(f"\n{Fore.LIGHTCYAN_EX}Enter your KQL (type DONE when finished):{Fore.RESET}\n")
            custom_lines = []
            while True:
                line = input(f"{Fore.WHITE}KQL > {Fore.RESET}")
                if line.strip().upper() == 'DONE':
                    break
                custom_lines.append(line)
            kql = '\n'.join(custom_lines)
        
        elif choice == '3':
            return None
        
        return kql
        
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
        df = pandas.DataFrame(table.rows, columns=table.columns)
        
        print(f"{Fore.LIGHTGREEN_EX}✓ Query completed{Fore.RESET}")
        print(f"{Fore.WHITE}Records: {Fore.LIGHTYELLOW_EX}{len(table.rows)}{Fore.RESET}\n")
        
        # Show first 15 rows
        print(f"{Fore.LIGHTCYAN_EX}RESULTS (first 15 rows):{Fore.RESET}\n")
        print(df.head(15).to_string(index=False))
        print(f"\n{Fore.LIGHTCYAN_EX}{'─'*70}{Fore.RESET}\n")
        
        return df.to_csv(index=False)
        
    except Exception as e:
        print(f"{Fore.RED}Error executing query: {e}{Fore.RESET}")
        return None


def analysis_stage(results_csv, flag_intel, session, openai_client, model):
    """Analyze results with LLM"""
    
    input(f"Press {Fore.LIGHTGREEN_EX}[Enter]{Fore.RESET} for LLM analysis... ")
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}🧠 ANALYZING RESULTS")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
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


def capture_flag_stage(llm_answer, flag_intel, session, kql_query):
    """Capture flag answer"""
    
    print(f"{Fore.LIGHTCYAN_EX}SUGGESTED ANSWER:{Fore.RESET} {Fore.LIGHTYELLOW_EX}{llm_answer}{Fore.RESET}\n")
    
    # Options
    print(f"  {Fore.LIGHTGREEN_EX}[1]{Fore.RESET} Accept answer")
    print(f"  {Fore.LIGHTYELLOW_EX}[2]{Fore.RESET} Enter different answer manually")
    print(f"  {Fore.LIGHTRED_EX}[3]{Fore.RESET} Reject and retry flag\n")
    
    choice = input(f"Select [1-3]: ").strip()
    
    if choice == '2':
        # Manual entry
        llm_answer = input(f"\n{Fore.LIGHTCYAN_EX}Enter answer: {Fore.RESET}").strip()
        if not llm_answer:
            return False
    
    elif choice == '3':
        # Reject
        return False
    
    # Capture
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
    
    print(f"{Fore.LIGHTCYAN_EX}WHAT'S NEXT?{Fore.RESET}\n")
    print(f"  {Fore.LIGHTGREEN_EX}[1]{Fore.RESET} Work on another flag")
    print(f"  {Fore.LIGHTYELLOW_EX}[2]{Fore.RESET} Finish hunt and generate report")
    print(f"  {Fore.LIGHTRED_EX}[3]{Fore.RESET} Exit\n")
    
    choice = input(f"Select [1-3]: ").strip()
    
    if choice == '2':
        return 'finish'
    elif choice == '3':
        return 'exit'
    else:
        return 'new_flag'


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


def prompt_resume_or_new(existing_sessions):
    """Prompt to resume or start new"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}🔄 EXISTING SESSIONS FOUND")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    for i, sess in enumerate(existing_sessions, 1):
        print(f"{Fore.LIGHTCYAN_EX}[{i}]{Fore.RESET} {Fore.LIGHTYELLOW_EX}{sess['project_name']}{Fore.RESET}")
        print(f"    Flags: {sess['flags_completed']}")
        print()
    
    print(f"{Fore.LIGHTGREEN_EX}[N]{Fore.RESET} Start new investigation\n")
    
    choice = input(f"Resume or start new [1-{len(existing_sessions)}/N]: ").strip().upper()
    
    if choice == 'N' or not choice:
        return None  # Will create new
    
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(existing_sessions):
            # Load session
            session = CTF_SESSION_MANAGER.SessionMemory(
                scenario_name="dynamic_ctf",
                project_name=existing_sessions[idx]['project_name']
            )
            session.state = existing_sessions[idx]['state']
            session.state_file = existing_sessions[idx]['file']
            
            base_name = os.path.basename(existing_sessions[idx]['file']).replace('_summary.json', '')
            session.event_log = f"{session.session_dir}{base_name}.jsonl"
            session.report_file = f"{session.session_dir}{base_name}_report.md"
            
            return session
    except:
        pass
    
    return None  # Will create new

