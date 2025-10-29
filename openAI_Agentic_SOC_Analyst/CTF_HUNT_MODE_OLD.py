"""
CTF Hunt Mode - Interactive Flag Hunting Pipeline
Step-by-step flag capture with session memory and correlation
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
                 timerange_hours, start_date, end_date, 
                 ctf_scenario_file="ctf_scenarios/rdp_password_spray.json"):
    """
    Main CTF hunting pipeline with interactive flag progression
    """
    
    # Load CTF scenario configuration
    if not os.path.exists(ctf_scenario_file):
        print(f"{Fore.RED}CTF scenario file not found: {ctf_scenario_file}{Fore.RESET}")
        print(f"{Fore.YELLOW}Please create the scenario file first.{Fore.RESET}")
        return None, None
    
    with open(ctf_scenario_file, 'r') as f:
        ctf_scenario = json.load(f)
    
    # ═══════════════════════════════════════════════════════════════
    # CHECK FOR EXISTING SESSIONS (Resume Support)
    # ═══════════════════════════════════════════════════════════════
    
    existing_sessions = find_existing_sessions(ctf_scenario['scenario_id'])
    
    if existing_sessions:
        session = prompt_resume_or_new(existing_sessions, ctf_scenario)
        if session is None:
            # User cancelled
            return None, None
        
        # Load project name from resumed session
        project_name = session.state.get('project_name', ctf_scenario['scenario_name'])
        
        print(f"\n{Fore.LIGHTGREEN_EX}✓ Resumed: {project_name}{Fore.RESET}")
        print(f"{Fore.WHITE}Continuing from Flag {session.state['current_flag']}{Fore.RESET}\n")
        
    else:
        # ═══════════════════════════════════════════════════════════════
        # NEW SESSION: PROMPT FOR PROJECT NAME
        # ═══════════════════════════════════════════════════════════════
        
        print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
        print(f"{Fore.LIGHTCYAN_EX}🎯 CTF INVESTIGATION SETUP")
        print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
        
        print(f"{Fore.WHITE}Scenario: {Fore.LIGHTYELLOW_EX}{ctf_scenario['scenario_name']}{Fore.RESET}\n")
        print(f"{Fore.LIGHTCYAN_EX}Enter a name for this investigation (for file naming):{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}Examples:{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}  • Hide Your RDP: Password Spray Leads to Full Compromise{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}  • Operation Lurker - Advanced Persistence Hunt{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}  • Papertrail Investigation - Log Analysis{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}Or press Enter to use default: '{ctf_scenario['scenario_name']}'{Fore.RESET}\n")
        
        try:
            project_name = input(f"{Fore.LIGHTGREEN_EX}Project Name: {Fore.RESET}").strip()
            
            if not project_name:
                project_name = ctf_scenario['scenario_name']
            
            print(f"\n{Fore.LIGHTGREEN_EX}✓ Project: {project_name}{Fore.RESET}\n")
            
        except (KeyboardInterrupt, EOFError):
            project_name = ctf_scenario['scenario_name']
            print(f"\n{Fore.LIGHTBLACK_EX}Using default: {project_name}{Fore.RESET}\n")
        
        # Initialize new session with project name
        session = CTF_SESSION_MANAGER.SessionMemory(
            scenario_name=ctf_scenario['scenario_id'],
            project_name=project_name
        )
        session.state['total_flags'] = ctf_scenario['total_flags']
        session.state['project_name'] = project_name
        session.save_state()
    
    # Display scenario intro
    display_scenario_intro(ctf_scenario, project_name)
    
    # Main hunting loop
    try:
        while True:
            current_flag_num = session.state['current_flag']
            
            # Check if all flags completed
            if current_flag_num > ctf_scenario['total_flags']:
                # Completion stage
                completion_stage(session, ctf_scenario)
                break
            
            # Get current flag configuration
            current_flag = ctf_scenario['flags'].get(str(current_flag_num))
            if not current_flag:
                print(f"{Fore.RED}Flag {current_flag_num} not found in scenario{Fore.RESET}")
                break
            
            current_flag['flag_number'] = current_flag_num
            
            # ═══════════════════════════════════════════════════════════════
            # STAGE 0: Session Context
            # ═══════════════════════════════════════════════════════════════
            display_session_context(session)
            
            # ═══════════════════════════════════════════════════════════════
            # STAGE 1: Intel Briefing
            # ═══════════════════════════════════════════════════════════════
            intel_briefing_stage(current_flag, session, ctf_scenario)
            
            # ═══════════════════════════════════════════════════════════════
            # STAGE 2: Query Building
            # ═══════════════════════════════════════════════════════════════
            kql_query = query_building_stage(current_flag, session, openai_client, model)
            
            if kql_query is None:
                # User cancelled
                break
            
            # ═══════════════════════════════════════════════════════════════
            # STAGE 3: Execution
            # ═══════════════════════════════════════════════════════════════
            results = execution_stage(kql_query, law_client, workspace_id, timerange_hours, 
                                      start_date, end_date, session, current_flag)
            
            if results is None:
                # Query failed or returned no results, loop back to query building
                print(f"\n{Fore.YELLOW}Query returned no results. Try different approach.{Fore.RESET}")
                session.state['current_flag'] = current_flag_num  # Stay on same flag
                continue
            
            # ═══════════════════════════════════════════════════════════════
            # STAGE 4: Analysis
            # ═══════════════════════════════════════════════════════════════
            llm_answer = analysis_stage(results, current_flag, session, openai_client, model)
            
            # ═══════════════════════════════════════════════════════════════
            # STAGE 5: Flag Capture
            # ═══════════════════════════════════════════════════════════════
            captured = capture_stage(llm_answer, current_flag, session, kql_query)
            
            if not captured:
                # User rejected, loop back
                continue
            
            # ═══════════════════════════════════════════════════════════════
            # STAGE 6: Continue Decision
            # ═══════════════════════════════════════════════════════════════
            action = continue_decision_stage(session, ctf_scenario)
            
            if action == 'exit':
                break
            elif action == 'retry':
                session.state['current_flag'] = current_flag_num  # Stay on same flag
                continue
            # else: action == 'next', loop continues to next flag
    
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        print(f"\n\n{Fore.YELLOW}{'='*70}")
        print(f"{Fore.YELLOW}Hunt interrupted by user")
        print(f"{Fore.YELLOW}{'='*70}{Fore.RESET}\n")
    
    # ═══════════════════════════════════════════════════════════════
    # FINAL STATE SAVE (on any exit path)
    # ═══════════════════════════════════════════════════════════════
    
    # Mark session as completed/interrupted
    if session.state['flags_completed'] >= ctf_scenario['total_flags']:
        session.state['status'] = 'completed'
    else:
        session.state['status'] = 'interrupted'
    
    # Final save to ensure everything is persisted
    session.save_state()
    
    print(f"{Fore.LIGHTCYAN_EX}💾 Saving final session state...{Fore.RESET}")
    print(f"{Fore.LIGHTGREEN_EX}✓ State saved to: {session.state_file}{Fore.RESET}")
    print(f"{Fore.LIGHTGREEN_EX}✓ Event log: {session.event_log}{Fore.RESET}\n")
    
    # Generate final report
    session.generate_report()
    
    # Optional: Flag logic review stage
    flag_logic_review_stage(session, ctf_scenario)
    
    return session.state, session.report_file


def find_existing_sessions(scenario_id):
    """Find existing incomplete sessions for this scenario"""
    
    session_dir = "ctf_sessions/"
    
    if not os.path.exists(session_dir):
        return []
    
    # Find all summary files for this scenario
    pattern = f"{session_dir}*_summary.json"
    summary_files = glob.glob(pattern)
    
    existing = []
    
    for summary_file in summary_files:
        try:
            with open(summary_file, 'r') as f:
                state = json.load(f)
            
            # Check if it's for this scenario and not completed
            if state.get('scenario') == scenario_id and state.get('status') == 'in_progress':
                existing.append({
                    'file': summary_file,
                    'state': state,
                    'project_name': state.get('project_name', 'Unknown'),
                    'flags_completed': state.get('flags_completed', 0),
                    'total_flags': state.get('total_flags', 0),
                    'current_flag': state.get('current_flag', 1),
                    'started_at': state.get('started_at', 'Unknown'),
                    'last_updated': state.get('last_updated', 'Unknown')
                })
        except:
            continue
    
    return existing


def prompt_resume_or_new(existing_sessions, ctf_scenario):
    """Ask user to resume existing session or start new"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}🔄 EXISTING SESSIONS FOUND")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    print(f"{Fore.WHITE}Found {len(existing_sessions)} incomplete investigation(s):{Fore.RESET}\n")
    
    # Show each session
    for i, sess in enumerate(existing_sessions, 1):
        progress_pct = int((sess['flags_completed'] / sess['total_flags']) * 100) if sess['total_flags'] > 0 else 0
        progress_bar = "█" * (progress_pct // 10) + "░" * (10 - (progress_pct // 10))
        
        print(f"{Fore.LIGHTCYAN_EX}[{i}]{Fore.RESET} {Fore.LIGHTYELLOW_EX}{sess['project_name']}{Fore.RESET}")
        print(f"    Progress: {sess['flags_completed']}/{sess['total_flags']} ({progress_pct}%) [{progress_bar}]")
        print(f"    Started: {sess['started_at'][:19]}")
        print(f"    Last Update: {sess['last_updated'][:19]}")
        print(f"    Next Flag: {sess['current_flag']}")
        print()
    
    print(f"{Fore.LIGHTGREEN_EX}[N]{Fore.RESET} Start new investigation")
    print(f"{Fore.LIGHTRED_EX}[X]{Fore.RESET} Cancel\n")
    
    try:
        choice = input(f"{Fore.LIGHTGREEN_EX}Resume session or start new [1-{len(existing_sessions)}/N/X]: {Fore.RESET}").strip().upper()
        
        if choice == 'X':
            return None
        
        if choice == 'N' or choice == '':
            # Start new session
            return create_new_session(ctf_scenario)
        
        # Try to parse as number
        try:
            choice_num = int(choice)
            if 1 <= choice_num <= len(existing_sessions):
                # Resume selected session
                selected = existing_sessions[choice_num - 1]
                return resume_session(selected, ctf_scenario)
            else:
                print(f"{Fore.YELLOW}Invalid selection. Starting new session.{Fore.RESET}")
                return create_new_session(ctf_scenario)
        except ValueError:
            print(f"{Fore.YELLOW}Invalid input. Starting new session.{Fore.RESET}")
            return create_new_session(ctf_scenario)
            
    except (KeyboardInterrupt, EOFError):
        return None


def create_new_session(ctf_scenario):
    """Create a brand new investigation session"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}🎯 NEW INVESTIGATION")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    print(f"{Fore.LIGHTCYAN_EX}Enter a name for this investigation (for file naming):{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}Examples:{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  • Hide Your RDP: Password Spray Leads to Full Compromise{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  • Operation Lurker - Advanced Persistence Hunt{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  • Papertrail Investigation - Log Analysis{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}Or press Enter to use default: '{ctf_scenario['scenario_name']}'{Fore.RESET}\n")
    
    try:
        project_name = input(f"{Fore.LIGHTGREEN_EX}Project Name: {Fore.RESET}").strip()
        
        if not project_name:
            project_name = ctf_scenario['scenario_name']
        
        print(f"\n{Fore.LIGHTGREEN_EX}✓ Project: {project_name}{Fore.RESET}\n")
        
    except (KeyboardInterrupt, EOFError):
        project_name = ctf_scenario['scenario_name']
        print(f"\n{Fore.LIGHTBLACK_EX}Using default: {project_name}{Fore.RESET}\n")
    
    # Initialize new session
    session = CTF_SESSION_MANAGER.SessionMemory(
        scenario_name=ctf_scenario['scenario_id'],
        project_name=project_name
    )
    session.state['total_flags'] = ctf_scenario['total_flags']
    session.state['project_name'] = project_name
    session.save_state()
    
    return session


def resume_session(session_info, ctf_scenario):
    """Resume an existing investigation session"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}📂 RESUMING SESSION")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    print(f"{Fore.WHITE}Project: {Fore.LIGHTYELLOW_EX}{session_info['project_name']}{Fore.RESET}")
    print(f"{Fore.WHITE}Progress: {Fore.LIGHTGREEN_EX}{session_info['flags_completed']}/{session_info['total_flags']} flags{Fore.RESET}")
    print(f"{Fore.WHITE}Next Flag: {Fore.LIGHTYELLOW_EX}#{session_info['current_flag']}{Fore.RESET}\n")
    
    # Show captured flags
    if session_info['state'].get('flags_captured'):
        print(f"{Fore.LIGHTCYAN_EX}Previously Captured:{Fore.RESET}")
        for flag in session_info['state']['flags_captured']:
            print(f"  {Fore.LIGHTGREEN_EX}✓{Fore.RESET} Flag {flag['flag_number']}: {flag['answer']}")
        print()
    
    # Reconstruct session from state file
    session = CTF_SESSION_MANAGER.SessionMemory(
        scenario_name=ctf_scenario['scenario_id'],
        project_name=session_info['project_name']
    )
    
    # Load the existing state
    session.state = session_info['state']
    session.state_file = session_info['file']
    
    # Update file paths to match existing session
    base_name = os.path.basename(session_info['file']).replace('_summary.json', '')
    session.event_log = f"{session.session_dir}{base_name}.jsonl"
    session.report_file = f"{session.session_dir}{base_name}_report.md"
    
    return session


def display_scenario_intro(ctf_scenario, project_name):
    """Display CTF scenario introduction"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}🎯 CTF INVESTIGATION MODE")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}")
    print(f"\n{Fore.WHITE}Project: {Fore.LIGHTGREEN_EX}{project_name}{Fore.RESET}")
    print(f"{Fore.WHITE}Scenario: {Fore.LIGHTYELLOW_EX}{ctf_scenario['scenario_name']}{Fore.RESET}")
    print(f"{Fore.WHITE}{ctf_scenario['description']}{Fore.RESET}")
    print(f"\n{Fore.LIGHTBLACK_EX}Device Filter: {ctf_scenario.get('device_filter', 'N/A')}")
    print(f"Total Flags: {ctf_scenario['total_flags']}")
    print(f"Incident Date: {ctf_scenario.get('incident_date', 'N/A')}{Fore.RESET}")
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    try:
        input(f"Press {Fore.LIGHTGREEN_EX}[Enter]{Fore.RESET} to begin hunting... ")
    except (KeyboardInterrupt, EOFError):
        pass


def display_session_context(session):
    """STAGE 0: Display accumulated session context"""
    
    state = session.state
    
    if state['flags_completed'] == 0:
        return  # Skip for first flag
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}📚 SESSION MEMORY")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    # Progress
    completed = state['flags_completed']
    total = state['total_flags']
    progress_bar = "█" * completed + "░" * (total - completed)
    print(f"{Fore.WHITE}Progress: {completed}/{total} Flags [{Fore.LIGHTGREEN_EX}{progress_bar}{Fore.WHITE}]{Fore.RESET}\n")
    
    # Recent flags
    print(f"{Fore.LIGHTCYAN_EX}Flags Captured:{Fore.RESET}")
    for flag in state['flags_captured'][-3:]:  # Last 3
        print(f"  {Fore.LIGHTGREEN_EX}✓{Fore.RESET} Flag {flag['flag_number']}: {flag['answer']}")
    
    # IOCs
    iocs = state['accumulated_iocs']
    has_iocs = any(values for values in iocs.values())
    
    if has_iocs:
        print(f"\n{Fore.LIGHTCYAN_EX}Accumulated IOCs:{Fore.RESET}")
        for ioc_type, values in iocs.items():
            if values:
                print(f"  • {ioc_type.replace('_', ' ').title()}: {Fore.LIGHTYELLOW_EX}{', '.join(map(str, values))}{Fore.RESET}")
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")


def intel_briefing_stage(current_flag, session, ctf_scenario):
    """STAGE 1: Intel briefing for current flag"""
    
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}🚩 FLAG {current_flag['flag_number']}: {current_flag['title'].upper()}")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    print(f"{Fore.WHITE}Stage: {Fore.LIGHTYELLOW_EX}{current_flag.get('stage', 'N/A')}{Fore.RESET}")
    print(f"{Fore.WHITE}MITRE: {Fore.LIGHTYELLOW_EX}{current_flag.get('mitre', 'N/A')}{Fore.RESET}\n")
    
    print(f"{Fore.LIGHTCYAN_EX}OBJECTIVE:{Fore.RESET}")
    print(f"{Fore.WHITE}{current_flag.get('objective', 'N/A')}{Fore.RESET}\n")
    
    if current_flag.get('guidance'):
        print(f"{Fore.LIGHTCYAN_EX}GUIDANCE:{Fore.RESET}")
        print(f"{Fore.WHITE}{current_flag['guidance']}{Fore.RESET}\n")
    
    if current_flag.get('flag_format'):
        print(f"{Fore.LIGHTCYAN_EX}FLAG FORMAT:{Fore.RESET} {Fore.LIGHTYELLOW_EX}{current_flag['flag_format']}{Fore.RESET}\n")
    
    print(f"{Fore.LIGHTCYAN_EX}{'─'*70}{Fore.RESET}\n")
    
    try:
        input(f"Press {Fore.LIGHTGREEN_EX}[Enter]{Fore.RESET} to build query... ")
    except (KeyboardInterrupt, EOFError):
        pass


def query_building_stage(current_flag, session, openai_client, model):
    """STAGE 2: Build KQL query with LLM assistance"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}🔨 QUERY BUILDING")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    # Get LLM context
    llm_context = session.get_llm_context(current_flag, context_type="compact")
    
    # Build prompt for query generation
    query_prompt = f"""You are a cybersecurity analyst building a KQL query for threat hunting.

{llm_context}

CURRENT FLAG:
- Objective: {current_flag.get('objective', '')}
- Table to query: {current_flag.get('table', 'DeviceLogonEvents')}
- Key fields: {', '.join(current_flag.get('key_fields', []))}

Generate a KQL query to find the answer to this flag.
Use previous flag answers as filters where relevant.
Include time range filtering and sort by Timestamp.

Return ONLY the KQL query, no explanations."""
    
    print(f"{Fore.LIGHTCYAN_EX}🤖 Generating KQL query with LLM...{Fore.RESET}\n")
    
    try:
        response = openai_client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": query_prompt}],
            temperature=0.3
        )
        
        suggested_kql = response.choices[0].message.content.strip()
        
        # Remove markdown code blocks if present
        if "```" in suggested_kql:
            suggested_kql = suggested_kql.split("```")[1]
            if suggested_kql.startswith("kql"):
                suggested_kql = suggested_kql[3:]
            suggested_kql = suggested_kql.strip()
        
        print(f"{Fore.LIGHTCYAN_EX}SUGGESTED QUERY:{Fore.RESET}\n")
        print(f"{Fore.LIGHTYELLOW_EX}{suggested_kql}{Fore.RESET}\n")
        print(f"{Fore.LIGHTCYAN_EX}{'─'*70}{Fore.RESET}\n")
        
        # Options
        print(f"OPTIONS:")
        print(f"  {Fore.LIGHTGREEN_EX}[1]{Fore.RESET} Execute this query")
        print(f"  {Fore.LIGHTYELLOW_EX}[2]{Fore.RESET} Write custom KQL")
        print(f"  {Fore.LIGHTRED_EX}[3]{Fore.RESET} Cancel\n")
        
        choice = input(f"Select [1-3]: ").strip()
        
        if choice == '2':
            # Custom KQL
            print(f"\n{Fore.LIGHTCYAN_EX}Enter your KQL query (type 'DONE' when finished):{Fore.RESET}\n")
            custom_lines = []
            while True:
                line = input(f"{Fore.WHITE}KQL > {Fore.RESET}")
                if line.strip().upper() == 'DONE':
                    break
                custom_lines.append(line)
            
            suggested_kql = '\n'.join(custom_lines)
        
        elif choice == '3':
            return None
        
        # Log event
        session.append_event("query_built", {
            "flag_number": current_flag['flag_number'],
            "kql": suggested_kql,
            "method": "llm" if choice == '1' else "custom"
        })
        
        return suggested_kql
        
    except Exception as e:
        print(f"{Fore.RED}Error generating query: {e}{Fore.RESET}")
        return None


def execution_stage(kql_query, law_client, workspace_id, timerange_hours, 
                    start_date, end_date, session, current_flag):
    """STAGE 3: Execute KQL query"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}⚡ EXECUTING QUERY")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    print(f"{Fore.WHITE}Querying Azure Log Analytics...{Fore.RESET}")
    
    try:
        response = law_client.query_workspace(
            workspace_id=workspace_id,
            query=kql_query,
            timespan=timedelta(hours=timerange_hours)
        )
        
        if not response.tables or len(response.tables[0].rows) == 0:
            print(f"\n{Fore.YELLOW}✗ Query returned 0 records{Fore.RESET}")
            session.append_event("query_executed", {
                "flag_number": current_flag['flag_number'],
                "results_count": 0
            })
            return None
        
        # Convert to DataFrame
        table = response.tables[0]
        columns = table.columns
        rows = table.rows
        df = pd.DataFrame(rows, columns=columns)
        
        print(f"\n{Fore.LIGHTGREEN_EX}✓ Query completed{Fore.RESET}")
        print(f"{Fore.WHITE}Records returned: {Fore.LIGHTYELLOW_EX}{len(rows)}{Fore.RESET}\n")
        
        # Show first few rows
        print(f"{Fore.LIGHTCYAN_EX}RESULTS (first 10 rows):{Fore.RESET}\n")
        print(df.head(10).to_string(index=False))
        print(f"\n{Fore.LIGHTCYAN_EX}{'─'*70}{Fore.RESET}\n")
        
        # Convert to CSV for LLM
        results_csv = df.to_csv(index=False)
        
        # Log event
        session.append_event("query_executed", {
            "flag_number": current_flag['flag_number'],
            "results_count": len(rows)
        })
        
        return results_csv
        
    except Exception as e:
        print(f"{Fore.RED}Error executing query: {e}{Fore.RESET}")
        return None


def analysis_stage(results_csv, current_flag, session, openai_client, model):
    """STAGE 4: Analyze results with LLM"""
    
    input(f"\nPress {Fore.LIGHTGREEN_EX}[Enter]{Fore.RESET} for LLM analysis... ")
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}🧠 LLM ANALYSIS")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    # Get session context
    llm_context = session.get_llm_context(current_flag, context_type="full")
    
    # Build analysis prompt
    analysis_prompt = f"""You are analyzing threat hunting query results to answer a specific question.

{llm_context}

QUESTION TO ANSWER:
{current_flag.get('objective', '')}

FLAG FORMAT: {current_flag.get('flag_format', 'text')}

QUERY RESULTS:
{results_csv[:3000]}  

Based on the objective and results, provide:
1. The answer (just the value in the correct format)
2. Brief evidence (2-3 bullet points)
3. Reasoning (1-2 sentences)

Format your response as:
ANSWER: <the answer>
EVIDENCE:
- <point 1>
- <point 2>
REASONING: <explanation>"""
    
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
        llm_answer = extract_answer_from_analysis(analysis)
        
        # Log event
        session.append_event("analysis_complete", {
            "flag_number": current_flag['flag_number'],
            "llm_answer": llm_answer,
            "full_analysis": analysis
        })
        
        return llm_answer
        
    except Exception as e:
        print(f"{Fore.RED}Error during analysis: {e}{Fore.RESET}")
        return None


def extract_answer_from_analysis(analysis):
    """Extract the answer from LLM analysis"""
    
    # Try to find "ANSWER:" line
    for line in analysis.split('\n'):
        if line.strip().upper().startswith('ANSWER:'):
            return line.split(':', 1)[1].strip()
    
    # Fallback: return first line
    return analysis.split('\n')[0].strip()


def capture_stage(llm_answer, current_flag, session, kql_query):
    """STAGE 5: Capture flag answer"""
    
    print(f"{Fore.LIGHTCYAN_EX}SUGGESTED ANSWER:{Fore.RESET} {Fore.LIGHTYELLOW_EX}{llm_answer}{Fore.RESET}\n")
    
    try:
        accept = input(f"Accept this answer? [Y/n]: ").strip().lower()
        
        if accept in ['n', 'no']:
            # Answer rejected - show recovery options
            return rejection_recovery_stage(current_flag, session)
        
        # Optional notes
        notes = input(f"\n{Fore.LIGHTCYAN_EX}Add notes (optional):{Fore.RESET} ").strip()
        
        # Capture flag
        session.capture_flag(
            flag_number=current_flag['flag_number'],
            title=current_flag['title'],
            answer=llm_answer,
            notes=notes,
            kql_used=kql_query,
            table_queried=current_flag.get('table', ''),
            stage=current_flag.get('stage', ''),
            mitre=current_flag.get('mitre', ''),
            correlation=current_flag.get('correlation', {})
        )
        
        print(f"\n{Fore.LIGHTGREEN_EX}{'='*70}")
        print(f"{Fore.LIGHTGREEN_EX}✓ FLAG {current_flag['flag_number']} CAPTURED: {llm_answer}")
        print(f"{Fore.LIGHTGREEN_EX}{'='*70}{Fore.RESET}\n")
        
        return True
        
    except (KeyboardInterrupt, EOFError):
        print(f"\n{Fore.YELLOW}Cancelled{Fore.RESET}")
        return False


def rejection_recovery_stage(current_flag, session):
    """STAGE 5.5: Handle rejected answer - choose recovery path"""
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}❌ ANSWER REJECTED - RECOVERY OPTIONS")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    print(f"{Fore.WHITE}What would you like to do?{Fore.RESET}\n")
    
    print(f"  {Fore.LIGHTGREEN_EX}[1]{Fore.RESET} 🔄 Build new query (different approach)")
    print(f"      → Loop back to query building stage")
    print(f"      → Try different table, filters, or time range\n")
    
    print(f"  {Fore.LIGHTYELLOW_EX}[2]{Fore.RESET} 🧠 Re-analyze same results (LLM missed it)")
    print(f"      → Keep current query results")
    print(f"      → Ask LLM to focus on different fields\n")
    
    print(f"  {Fore.LIGHTMAGENTA_EX}[3]{Fore.RESET} ✏️  Enter answer manually (I found it)")
    print(f"      → You see the answer in the results")
    print(f"      → Skip LLM, input directly\n")
    
    print(f"  {Fore.LIGHTBLUE_EX}[4]{Fore.RESET} 🔍 Review raw results again")
    print(f"      → Show full query results")
    print(f"      → Examine data before deciding\n")
    
    print(f"  {Fore.LIGHTCYAN_EX}[5]{Fore.RESET} ⏭️  Skip this flag (come back later)")
    print(f"      → Move to next flag")
    print(f"      → Can return to this one later\n")
    
    print(f"  {Fore.LIGHTRED_EX}[6]{Fore.RESET} 🚪 Exit CTF hunt")
    print(f"      → Generate report and quit\n")
    
    try:
        choice = input(f"{Fore.LIGHTGREEN_EX}Select [1-6]: {Fore.RESET}").strip()
        
        if choice == '1':
            # Retry with new query
            print(f"\n{Fore.LIGHTCYAN_EX}🔄 Returning to query building...{Fore.RESET}")
            session.append_event("flag_retry", {
                "flag_number": current_flag['flag_number'],
                "reason": "new_query_needed"
            })
            return False  # Will loop back to query building
        
        elif choice == '2':
            # Re-analyze same data
            print(f"\n{Fore.LIGHTCYAN_EX}🧠 Re-analyzing current results...{Fore.RESET}")
            print(f"{Fore.WHITE}What should LLM focus on this time?{Fore.RESET}")
            focus_hint = input(f"{Fore.LIGHTCYAN_EX}Analysis hint: {Fore.RESET}").strip()
            
            session.append_event("flag_retry", {
                "flag_number": current_flag['flag_number'],
                "reason": "reanalyze",
                "hint": focus_hint
            })
            # This would need to trigger re-analysis with the hint
            # For now, just retry the flag
            return False
        
        elif choice == '3':
            # Manual entry
            print(f"\n{Fore.LIGHTCYAN_EX}✏️  MANUAL ANSWER ENTRY{Fore.RESET}\n")
            manual_answer = input(f"{Fore.LIGHTGREEN_EX}Enter flag answer: {Fore.RESET}").strip()
            
            if not manual_answer:
                print(f"{Fore.YELLOW}No answer entered. Returning to hunt.{Fore.RESET}")
                return False
            
            confirm = input(f"\nConfirm '{Fore.LIGHTYELLOW_EX}{manual_answer}{Fore.RESET}' is correct? [Y/n]: ").strip().lower()
            
            if confirm in ['n', 'no']:
                print(f"{Fore.YELLOW}Cancelled. Returning to hunt.{Fore.RESET}")
                return False
            
            # Get notes
            notes = input(f"\n{Fore.LIGHTCYAN_EX}Add notes (optional):{Fore.RESET} ").strip()
            
            # Capture with manual entry
            session.capture_flag(
                flag_number=current_flag['flag_number'],
                title=current_flag['title'],
                answer=manual_answer,
                notes=notes,
                kql_used="(Manually entered)",
                table_queried=current_flag.get('table', ''),
                stage=current_flag.get('stage', ''),
                mitre=current_flag.get('mitre', ''),
                correlation=current_flag.get('correlation', {})
            )
            
            print(f"\n{Fore.LIGHTGREEN_EX}{'='*70}")
            print(f"{Fore.LIGHTGREEN_EX}✓ FLAG {current_flag['flag_number']} CAPTURED (Manual): {manual_answer}")
            print(f"{Fore.LIGHTGREEN_EX}{'='*70}{Fore.RESET}\n")
            
            session.append_event("flag_captured", {
                "flag_number": current_flag['flag_number'],
                "method": "manual_entry",
                "answer": manual_answer
            })
            
            return True
        
        elif choice == '4':
            # Review results
            print(f"\n{Fore.YELLOW}(Review raw results feature - to be implemented){Fore.RESET}")
            print(f"{Fore.WHITE}Results are displayed in Stage 3. Scroll up to review.{Fore.RESET}\n")
            return False
        
        elif choice == '5':
            # Skip flag
            print(f"\n{Fore.LIGHTYELLOW_EX}⏭️  Skipping Flag {current_flag['flag_number']}...{Fore.RESET}")
            
            confirm = input(f"Continue to next flag? [Y/n]: ").strip().lower()
            
            if confirm in ['n', 'no']:
                return False
            
            # Advance to next flag
            session.state['current_flag'] = current_flag['flag_number'] + 1
            session.save_state()
            
            session.append_event("flag_skipped", {
                "flag_number": current_flag['flag_number'],
                "reason": "user_skip"
            })
            
            return True  # Marks as "handled" so main loop continues
        
        elif choice == '6':
            # Exit hunt
            print(f"\n{Fore.LIGHTRED_EX}Exiting CTF hunt...{Fore.RESET}")
            
            confirm = input(f"Generate partial report? [Y/n]: ").strip().lower()
            
            if confirm not in ['n', 'no']:
                session.generate_report()
                print(f"\n{Fore.LIGHTGREEN_EX}✓ Partial report generated{Fore.RESET}")
            
            raise KeyboardInterrupt  # Signal to exit main loop
        
        else:
            # Default: retry
            return False
            
    except (KeyboardInterrupt, EOFError):
        raise  # Propagate to exit main loop


def continue_decision_stage(session, ctf_scenario):
    """STAGE 6: Decide next action"""
    
    state = session.state
    next_flag_num = state['current_flag']
    
    print(f"\n{Fore.LIGHTCYAN_EX}NEXT STEPS:{Fore.RESET}\n")
    print(f"  {Fore.LIGHTGREEN_EX}[1]{Fore.RESET} Continue to Flag {next_flag_num}")
    print(f"  {Fore.LIGHTYELLOW_EX}[2]{Fore.RESET} Re-investigate current flag")
    print(f"  {Fore.LIGHTMAGENTA_EX}[3]{Fore.RESET} View progress summary")
    print(f"  {Fore.LIGHTRED_EX}[4]{Fore.RESET} Generate report and exit\n")
    
    try:
        choice = input(f"Select [1-4]: ").strip()
        
        if choice == '2':
            return 'retry'
        elif choice == '3':
            display_session_context(session)
            return 'next'
        elif choice == '4':
            return 'exit'
        else:
            return 'next'
            
    except (KeyboardInterrupt, EOFError):
        return 'exit'


def completion_stage(session, ctf_scenario):
    """Final wrap-up stage when all flags are captured"""
    
    state = session.state
    
    print(f"\n{Fore.LIGHTGREEN_EX}{'='*70}")
    print(f"{Fore.LIGHTGREEN_EX}🎉 INVESTIGATION COMPLETE - ALL FLAGS CAPTURED!")
    print(f"{Fore.LIGHTGREEN_EX}{'='*70}{Fore.RESET}\n")
    
    # ═══════════════════════════════════════════════════════════════
    # 1. FINAL STATISTICS
    # ═══════════════════════════════════════════════════════════════
    
    duration = session._calculate_duration()
    
    print(f"{Fore.LIGHTCYAN_EX}📊 INVESTIGATION STATISTICS:{Fore.RESET}\n")
    print(f"  {Fore.WHITE}Scenario: {Fore.LIGHTYELLOW_EX}{ctf_scenario['scenario_name']}{Fore.RESET}")
    print(f"  {Fore.WHITE}Duration: {Fore.LIGHTYELLOW_EX}{duration}{Fore.RESET}")
    print(f"  {Fore.WHITE}Flags Captured: {Fore.LIGHTGREEN_EX}{state['flags_completed']}/{state['total_flags']} (100%){Fore.RESET}")
    print(f"  {Fore.WHITE}Started: {Fore.LIGHTBLACK_EX}{state['started_at'][:19]}{Fore.RESET}")
    print(f"  {Fore.WHITE}Completed: {Fore.LIGHTBLACK_EX}{state['last_updated'][:19]}{Fore.RESET}\n")
    
    # ═══════════════════════════════════════════════════════════════
    # 2. ALL FLAGS SUMMARY
    # ═══════════════════════════════════════════════════════════════
    
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}🚩 ALL FLAGS CAPTURED")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    for flag in state['flags_captured']:
        print(f"{Fore.LIGHTGREEN_EX}✓ Flag {flag['flag_number']}: {flag['title']}{Fore.RESET}")
        print(f"  {Fore.WHITE}Answer: {Fore.LIGHTYELLOW_EX}{flag['answer']}{Fore.RESET}")
        print(f"  {Fore.LIGHTBLACK_EX}Stage: {flag['stage']} | MITRE: {flag['mitre']}{Fore.RESET}")
        if flag.get('notes'):
            print(f"  {Fore.LIGHTBLACK_EX}Notes: {flag['notes'][:100]}{Fore.RESET}")
        print()
    
    # ═══════════════════════════════════════════════════════════════
    # 3. ACCUMULATED IOCs
    # ═══════════════════════════════════════════════════════════════
    
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}🔑 ACCUMULATED INDICATORS OF COMPROMISE")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    iocs = state['accumulated_iocs']
    ioc_count = 0
    
    for ioc_type, values in iocs.items():
        if values:
            ioc_count += len(values)
            print(f"{Fore.WHITE}{ioc_type.replace('_', ' ').title()}:{Fore.RESET}")
            for value in values:
                print(f"  {Fore.LIGHTYELLOW_EX}• {value}{Fore.RESET}")
            print()
    
    print(f"{Fore.WHITE}Total IOCs Extracted: {Fore.LIGHTGREEN_EX}{ioc_count}{Fore.RESET}\n")
    
    # ═══════════════════════════════════════════════════════════════
    # 4. ATTACK CHAIN RECONSTRUCTION
    # ═══════════════════════════════════════════════════════════════
    
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}📈 ATTACK CHAIN TIMELINE (MITRE ATT&CK)")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    # Group flags by stage
    stages_completed = {}
    for flag in state['flags_captured']:
        stage = flag.get('stage', 'Unknown')
        if stage not in stages_completed:
            stages_completed[stage] = []
        stages_completed[stage].append(flag)
    
    # Display in MITRE ATT&CK order
    mitre_order = [
        "Initial Access", "Execution", "Persistence", "Defense Evasion",
        "Discovery", "Collection", "Command and Control", "Exfiltration"
    ]
    
    for i, stage_name in enumerate(mitre_order, 1):
        if stage_name in stages_completed:
            flags_in_stage = stages_completed[stage_name]
            
            # Show stage header
            print(f"{Fore.LIGHTYELLOW_EX}{i}. {stage_name}{Fore.RESET}")
            
            # Show flags in this stage
            for flag in flags_in_stage:
                print(f"   {Fore.WHITE}├─ Flag {flag['flag_number']}: {flag['answer']}{Fore.RESET}")
            
            # Show transition arrow if not last
            if i < len(mitre_order) and any(s in stages_completed for s in mitre_order[i:]):
                print(f"   {Fore.LIGHTBLACK_EX}↓{Fore.RESET}")
    
    print()
    
    # ═══════════════════════════════════════════════════════════════
    # 5. ATTACK NARRATIVE
    # ═══════════════════════════════════════════════════════════════
    
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}📖 ATTACK NARRATIVE (Reconstructed)")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    # Build narrative from attack chain
    if 'attack_chain' in ctf_scenario:
        for chain_item in ctf_scenario['attack_chain']:
            stage = chain_item['stage']
            description = chain_item['description']
            
            print(f"{Fore.LIGHTYELLOW_EX}▶ {stage}:{Fore.RESET}")
            print(f"  {Fore.WHITE}{description}{Fore.RESET}\n")
    
    # ═══════════════════════════════════════════════════════════════
    # 6. REPORT GENERATION OPTIONS
    # ═══════════════════════════════════════════════════════════════
    
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}💾 SAVE INVESTIGATION REPORT")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    print(f"{Fore.WHITE}Generate final investigation report?{Fore.RESET}\n")
    print(f"  {Fore.LIGHTGREEN_EX}[1]{Fore.RESET} Generate markdown report (recommended)")
    print(f"  {Fore.LIGHTYELLOW_EX}[2]{Fore.RESET} View session files only")
    print(f"  {Fore.LIGHTRED_EX}[3]{Fore.RESET} Skip\n")
    
    try:
        choice = input(f"Select [1-3]: ").strip()
        
        if choice == '1' or not choice:
            # Generate markdown report
            print(f"\n{Fore.LIGHTCYAN_EX}Generating investigation report...{Fore.RESET}\n")
            session.generate_report()
            
            print(f"{Fore.LIGHTGREEN_EX}✓ Investigation report generated!{Fore.RESET}\n")
            print(f"{Fore.WHITE}Report Location:{Fore.RESET}")
            print(f"  {Fore.LIGHTYELLOW_EX}📄 {session.report_file}{Fore.RESET}\n")
            
            # Show preview
            print(f"{Fore.LIGHTCYAN_EX}Report Preview:{Fore.RESET}")
            print(f"{Fore.LIGHTBLACK_EX}{'─'*70}")
            print(f"# {ctf_scenario['scenario_name']} - Investigation Report")
            print(f"**Date:** {state['started_at'][:10]}")
            print(f"**Flags Completed:** {state['flags_completed']}/{state['total_flags']}")
            print(f"**Status:** ✅ Complete")
            for flag in state['flags_captured'][:3]:
                print(f"\n## Flag {flag['flag_number']}: {flag['title']}")
                print(f"Answer: {flag['answer']}")
            print(f"\n[... {state['flags_completed'] - 3} more flags in full report ...]")
            print(f"{'─'*70}{Fore.RESET}\n")
            
        elif choice == '2':
            # Just show file locations
            print(f"\n{Fore.LIGHTCYAN_EX}Session files saved (no report generated):{Fore.RESET}\n")
            
    except (KeyboardInterrupt, EOFError):
        pass
    
    # ═══════════════════════════════════════════════════════════════
    # 7. FINAL FILE LOCATIONS
    # ═══════════════════════════════════════════════════════════════
    
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}📁 SESSION FILES")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}")
    print(f"{Fore.WHITE}Event Log:   {Fore.LIGHTBLACK_EX}{session.event_log}{Fore.RESET}")
    print(f"{Fore.WHITE}State File:  {Fore.LIGHTBLACK_EX}{session.state_file}{Fore.RESET}")
    
    if os.path.exists(session.report_file):
        print(f"{Fore.WHITE}Report:      {Fore.LIGHTBLACK_EX}{session.report_file}{Fore.RESET}")
    
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    # ═══════════════════════════════════════════════════════════════
    # 8. CONGRATULATIONS
    # ═══════════════════════════════════════════════════════════════
    
    print(f"{Fore.LIGHTGREEN_EX}{'='*70}")
    print(f"{Fore.LIGHTGREEN_EX}🎊 CONGRATULATIONS! INVESTIGATION COMPLETE!")
    print(f"{Fore.LIGHTGREEN_EX}{'='*70}{Fore.RESET}\n")
    print(f"{Fore.WHITE}You successfully reconstructed the complete attack chain from{Fore.RESET}")
    print(f"{Fore.WHITE}initial access through exfiltration across {Fore.LIGHTGREEN_EX}{state['flags_completed']} flags{Fore.WHITE}.{Fore.RESET}\n")
    print(f"{Fore.LIGHTYELLOW_EX}Great job completing this CTF! 🎉{Fore.RESET}\n")


def export_report(session, ctf_scenario):
    """Export report in different formats"""
    
    state = session.state
    
    print(f"\n{Fore.LIGHTCYAN_EX}EXPORT OPTIONS:{Fore.RESET}\n")
    print(f"  {Fore.LIGHTGREEN_EX}[1]{Fore.RESET} Markdown (.md) - Default")
    print(f"  {Fore.LIGHTYELLOW_EX}[2]{Fore.RESET} JSON (.json) - Machine readable")
    print(f"  {Fore.LIGHTMAGENTA_EX}[3]{Fore.RESET} Plain text (.txt)")
    print(f"  {Fore.LIGHTRED_EX}[4]{Fore.RESET} Cancel\n")
    
    choice = input(f"Select format [1-4]: ").strip()
    
    if choice == '1' or not choice:
        session.generate_report()
        print(f"\n{Fore.LIGHTGREEN_EX}✓ Markdown report saved: {session.report_file}{Fore.RESET}\n")
    
    elif choice == '2':
        # Export as JSON
        json_file = session.report_file.replace('.md', '.json')
        with open(json_file, 'w') as f:
            json.dump(state, f, indent=2)
        print(f"\n{Fore.LIGHTGREEN_EX}✓ JSON export saved: {json_file}{Fore.RESET}\n")
    
    elif choice == '3':
        # Export as plain text
        txt_file = session.report_file.replace('.md', '.txt')
        
        with open(txt_file, 'w') as f:
            f.write(f"{ctf_scenario['scenario_name']} - Investigation Report\n")
            f.write("="*70 + "\n\n")
            
            for flag in state['flags_captured']:
                f.write(f"Flag {flag['flag_number']}: {flag['title']}\n")
                f.write(f"Answer: {flag['answer']}\n")
                f.write(f"Stage: {flag['stage']}\n")
                f.write("\n")
        
        print(f"\n{Fore.LIGHTGREEN_EX}✓ Text export saved: {txt_file}{Fore.RESET}\n")


def flag_logic_review_stage(session, ctf_scenario):
    """
    Optional final stage: Paste complete flag investigation notes
    Stores detailed findings, KQL, and reasoning for future reference
    """
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}📝 FLAG LOGIC REVIEW (Optional)")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    print(f"{Fore.WHITE}Would you like to add detailed investigation notes for each flag?{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}This is useful for:{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  • Documentation and write-ups{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  • Detailed reasoning beyond automated capture{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  • Sharing investigation methodology{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  • Future reference and learning{Fore.RESET}\n")
    
    try:
        add_logic = input(f"{Fore.LIGHTGREEN_EX}Add flag investigation notes? [y/N]: {Fore.RESET}").strip().lower()
        
        if add_logic not in ['y', 'yes']:
            print(f"{Fore.LIGHTBLACK_EX}Skipping flag logic review.{Fore.RESET}\n")
            return
        
        print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
        print(f"{Fore.LIGHTCYAN_EX}FLAG INVESTIGATION NOTES CAPTURE")
        print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
        
        print(f"{Fore.WHITE}You can add detailed notes for each flag.{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}Enter notes in your preferred format (paste your writeup).{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}Type 'DONE' on a new line when finished with each flag.{Fore.RESET}\n")
        
        flag_logic_data = {
            "scenario": ctf_scenario['scenario_name'],
            "session_id": session.state['session_id'],
            "completed_at": session.state['last_updated'],
            "flags_logic": []
        }
        
        # For each captured flag
        for flag in session.state['flags_captured']:
            print(f"\n{Fore.LIGHTCYAN_EX}{'─'*70}")
            print(f"{Fore.LIGHTCYAN_EX}Flag {flag['flag_number']}: {flag['title']}")
            print(f"{Fore.LIGHTCYAN_EX}Current answer: {Fore.LIGHTYELLOW_EX}{flag['answer']}{Fore.RESET}")
            print(f"{Fore.LIGHTCYAN_EX}{'─'*70}{Fore.RESET}\n")
            
            add_notes = input(f"{Fore.LIGHTGREEN_EX}Add detailed notes for Flag {flag['flag_number']}? [y/N]: {Fore.RESET}").strip().lower()
            
            if add_notes not in ['y', 'yes']:
                # Use existing notes
                flag_logic_data['flags_logic'].append({
                    "flag_number": flag['flag_number'],
                    "title": flag['title'],
                    "answer": flag['answer'],
                    "notes": flag.get('notes', ''),
                    "kql": flag.get('kql_used', ''),
                    "stage": flag.get('stage', ''),
                    "mitre": flag.get('mitre', '')
                })
                continue
            
            print(f"\n{Fore.LIGHTCYAN_EX}Paste your investigation notes for Flag {flag['flag_number']}:{Fore.RESET}")
            print(f"{Fore.LIGHTBLACK_EX}(Include: scenario, objective, KQL, output, findings, etc.)")
            print(f"{Fore.LIGHTBLACK_EX}Type 'DONE' on new line when finished{Fore.RESET}\n")
            
            # Collect multi-line input
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
            
            # Parse the pasted notes for key sections
            flag_logic_entry = {
                "flag_number": flag['flag_number'],
                "title": flag['title'],
                "answer": flag['answer'],
                "stage": flag.get('stage', ''),
                "mitre": flag.get('mitre', ''),
                "detailed_notes": detailed_notes,
                "kql_used": flag.get('kql_used', ''),
                "captured_at": flag.get('captured_at', '')
            }
            
            # Try to extract structured info from pasted notes
            extracted = extract_structured_notes(detailed_notes)
            if extracted:
                flag_logic_entry.update(extracted)
            
            flag_logic_data['flags_logic'].append(flag_logic_entry)
            
            print(f"\n{Fore.LIGHTGREEN_EX}✓ Notes captured for Flag {flag['flag_number']}{Fore.RESET}")
        
        # Save flag logic to JSON file
        logic_file = session.session_dir + "flag_investigation_logic.json"
        
        with open(logic_file, 'w', encoding='utf-8') as f:
            json.dump(flag_logic_data, f, indent=2, ensure_ascii=False)
        
        print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
        print(f"{Fore.LIGHTGREEN_EX}✓ Flag investigation logic saved!")
        print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
        print(f"{Fore.WHITE}Saved to: {Fore.LIGHTYELLOW_EX}{logic_file}{Fore.RESET}\n")
        print(f"{Fore.LIGHTBLACK_EX}This file contains your detailed investigation methodology{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}and can be used for writeups, reports, or future reference.{Fore.RESET}\n")
        
    except (KeyboardInterrupt, EOFError):
        print(f"\n{Fore.YELLOW}Skipped flag logic review.{Fore.RESET}\n")


def extract_structured_notes(notes_text):
    """
    Extract structured information from pasted notes
    Looks for common patterns like:
    - Scenario Context:
    - Objective:
    - KQL Query:
    - Output:
    - Finding:
    """
    
    extracted = {}
    
    # Try to find sections
    if "Objective:" in notes_text or "OBJECTIVE:" in notes_text:
        try:
            objective = notes_text.split("Objective:")[1].split("\n")[0].strip()
            if not objective:
                objective = notes_text.split("OBJECTIVE:")[1].split("\n")[0].strip()
            extracted['objective'] = objective
        except:
            pass
    
    if "Output:" in notes_text or "OUTPUT:" in notes_text:
        try:
            output = notes_text.split("Output:")[1].split("\n")[0].strip()
            if not output:
                output = notes_text.split("OUTPUT:")[1].split("\n")[0].strip()
            extracted['output'] = output
        except:
            pass
    
    if "Finding:" in notes_text or "FINDING:" in notes_text:
        try:
            finding = notes_text.split("Finding:")[1].split("\n")[0].strip()
            if not finding:
                finding = notes_text.split("FINDING:")[1].split("\n")[0].strip()
            extracted['finding'] = finding
        except:
            pass
    
    # Extract KQL if present (between code blocks or after "KQL" keyword)
    if "```kql" in notes_text or "```sql" in notes_text:
        try:
            kql_block = notes_text.split("```")[1]
            if kql_block.startswith("kql") or kql_block.startswith("sql"):
                kql_block = kql_block[3:]
            extracted['kql_from_notes'] = kql_block.strip()
        except:
            pass
    
    return extracted

