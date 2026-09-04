# Standard library
import time

# Third-party libraries
from color_support import Fore, init, Style
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient

# Local modules
import _keys
import SEVERITY_LEVELS
import COMPLIANCE_PROFILES
import MODEL_SELECTOR
import THREAT_HUNT_PIPELINE
import ANOMALY_DETECTION_PIPELINE
import CORRELATION_ENGINE
import CTF_HUNT_MODE
import OLLAMA_CLIENT

# Initialize
init(autoreset=True)

# Pre-flight: verify Artemis volume and the local Ollama model before anything else
try:
    print(Fore.LIGHTGREEN_EX + OLLAMA_CLIENT.verify_artemis_and_ollama() + Fore.RESET)
except RuntimeError as e:
    print(f"{Fore.RED}{'='*70}\nLOCAL MODEL PRE-FLIGHT FAILED\n{'='*70}{Fore.RESET}")
    print(f"{Fore.YELLOW}{e}{Fore.RESET}\n")
    exit(1)

# Build Azure Log Analytics Client
try:
    credential = DefaultAzureCredential(process_timeout=60)  # az CLI token fetch takes 6s+ on this Mac; default 10s timeout caused startup failures
    law_client = LogsQueryClient(credential=credential)
    
    # Test authentication and permissions
    print(f"{Fore.LIGHTCYAN_EX}Testing Azure Log Analytics connection...{Fore.RESET}")
    test_query = "union * | take 1"  # Simple query to test access
    from datetime import timedelta
    try:
        test_response = law_client.query_workspace(
            workspace_id=_keys.LOG_ANALYTICS_WORKSPACE_ID,
            query=test_query,
            timespan=timedelta(days=1)
        )
        print(f"{Fore.LIGHTGREEN_EX}✓ Successfully connected to Log Analytics workspace{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}  Workspace ID: {_keys.LOG_ANALYTICS_WORKSPACE_ID[:8]}...{Fore.RESET}\n")
    except Exception as auth_error:
        print(f"{Fore.RED}{'='*70}")
        print(f"{Fore.RED}AUTHENTICATION/PERMISSION ERROR")
        print(f"{Fore.RED}{'='*70}{Fore.RESET}")
        print(f"{Fore.YELLOW}Could not access Log Analytics workspace:{Fore.RESET}")
        print(f"{Fore.WHITE}{auth_error}{Fore.RESET}\n")
        print(f"{Fore.LIGHTCYAN_EX}Possible fixes:{Fore.RESET}")
        print(f"{Fore.WHITE}1. Run: {Fore.LIGHTGREEN_EX}az login{Fore.WHITE} (authenticate with Azure)")
        print(f"{Fore.WHITE}2. Verify workspace ID in {Fore.LIGHTYELLOW_EX}_keys.py")
        print(f"{Fore.WHITE}3. Check you have 'Log Analytics Reader' role on the workspace")
        print(f"{Fore.WHITE}4. Verify workspace exists: Azure Portal → Log Analytics Workspaces{Fore.RESET}\n")
        print(f"{Fore.RED}Exiting...{Fore.RESET}\n")
        exit(1)

except Exception as e:
    print(f"{Fore.RED}Failed to create Azure Log Analytics client: {e}{Fore.RESET}")
    exit(1)

# OpenAI decommissioned 2026-09-04: the engine runs on the local model and Claude only.
# Pipelines still accept an `openai_client` argument for compatibility; it is always None.
openai_client = None

# Welcome banner
print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
print(f"{Fore.LIGHTCYAN_EX}🛡️  AGENTIC SOC ANALYST")
print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
print(f"{Fore.WHITE}Advanced Threat Hunting & Anomaly Detection System")
print(f"{Fore.LIGHTCYAN_EX}{'='*70}\n")

# ═══════════════════════════════════════════════════════════════════
# PIPELINE SELECTION
# ═══════════════════════════════════════════════════════════════════

print(f"{Fore.LIGHTCYAN_EX}SELECT INVESTIGATION MODE:{Fore.RESET}\n")

print(f"{Fore.LIGHTGREEN_EX}[1] 🎯 THREAT HUNTING - Targeted Investigation")
print(f"{Fore.LIGHTBLACK_EX}    Investigate specific suspicions with focused queries")
print(f"{Fore.LIGHTBLACK_EX}    • User-directed hypothesis testing")
print(f"{Fore.LIGHTBLACK_EX}    • Single-table targeted analysis")
print(f"{Fore.LIGHTBLACK_EX}    • Deep dive on specific devices/users")
print(f"{Fore.LIGHTBLACK_EX}    • Best for: Incident response, alert triage\n")

print(f"{Fore.LIGHTYELLOW_EX}[2] 🔍 ANOMALY DETECTION - Automated Scanning")
print(f"{Fore.LIGHTBLACK_EX}    Discover unknown threats through broad scanning")
print(f"{Fore.LIGHTBLACK_EX}    • Multi-table automated sweep")
print(f"{Fore.LIGHTBLACK_EX}    • Behavioral baseline comparison")
print(f"{Fore.LIGHTBLACK_EX}    • Statistical outlier detection")
print(f"{Fore.LIGHTBLACK_EX}    • Best for: Proactive hunting, scheduled scans\n")

print(f"{Fore.LIGHTMAGENTA_EX}[3] 🏆 CTF MODE - Interactive Flag Hunting")
print(f"{Fore.LIGHTBLACK_EX}    Step-by-step CTF investigation with session memory")
print(f"{Fore.LIGHTBLACK_EX}    • Progressive flag capture with correlation")
print(f"{Fore.LIGHTBLACK_EX}    • LLM-assisted query building and analysis")
print(f"{Fore.LIGHTBLACK_EX}    • Accumulated IOC tracking across flags")
print(f"{Fore.LIGHTBLACK_EX}    • Best for: CTF competitions, structured hunts\n")

print(f"{Fore.LIGHTRED_EX}[4] Exit{Fore.RESET}\n")

try:
    pipeline_choice = input(f"{Fore.LIGHTGREEN_EX}Select mode [1-4]: {Fore.RESET}").strip()
except (KeyboardInterrupt, EOFError):
    print(f"\n{Fore.YELLOW}Exiting...{Fore.RESET}")
    exit(0)

if pipeline_choice == '4' or not pipeline_choice:
    print(f"{Fore.YELLOW}Exiting...{Fore.RESET}")
    exit(0)

# ═══════════════════════════════════════════════════════════════════
# MODEL & SEVERITY SELECTION (Skip for CTF mode - happens after intel capture)
# ═══════════════════════════════════════════════════════════════════

if pipeline_choice == '3':  # CTF mode - model selection happens after Stage 1 (Flag Intel Capture)
    model = None  # Will be selected after Stage 1
    severity_config = None  # Will be selected after Stage 1
else:
    # Estimate input tokens for time calculation (if we have query context)
    input_tokens = None
    try:
        import TIME_ESTIMATOR
        table_for_estimate = 'DeviceProcessEvents'
        if pipeline_choice == '1':
            qc = locals().get('query_context')
            if qc:
                table_for_estimate = qc.get('table_name', 'DeviceProcessEvents')
        # Create sample messages to estimate token count
        sample_messages = [
            {"role": "system", "content": "You are a security analyst."},
            {"role": "user", "content": f"Analyze these logs: {table_for_estimate}"}
        ]
        input_tokens = TIME_ESTIMATOR.estimate_tokens(sample_messages, "gpt-4")
    except:
        pass  # Fallback to no time estimation

    # Select model with time estimation
    model = MODEL_SELECTOR.prompt_model_selection(input_tokens)

    # Select severity level
    severity_level = SEVERITY_LEVELS.prompt_severity_selection()
    severity_config = SEVERITY_LEVELS.get_severity_config(severity_level)

    # Display selected configuration
    SEVERITY_LEVELS.display_severity_banner(severity_level)

    # Select framework profile and merge into severity config
    profile_key = COMPLIANCE_PROFILES.prompt_profile_selection()
    severity_config = COMPLIANCE_PROFILES.apply_profile(severity_config, profile_key)

    # Select result view mode (affects post-processing, not scanning)
    print(f"{Fore.LIGHTCYAN_EX}Result View Mode:{Fore.RESET}")
    print(f"{Fore.WHITE}  [1] Strict (default){Fore.RESET}")
    print(f"{Fore.WHITE}  [2] Only Critical (High-Signal subset){Fore.RESET}")
    print(f"{Fore.WHITE}  [3] Critical + Strict (two sets){Fore.RESET}")
    try:
        result_view_choice = input(f"{Fore.LIGHTGREEN_EX}Select [1-3] (default: 1): {Fore.RESET}").strip()
        if result_view_choice not in ['1','2','3']:
            result_view_choice = '1'
    except (KeyboardInterrupt, EOFError):
        result_view_choice = '1'

# Removed early confirmation; confirmation will occur post-query, pre-inference

# ═══════════════════════════════════════════════════════════════════
# MODE-SPECIFIC CONFIGURATION (Only for Mode 1: Threat Hunting)
# ═══════════════════════════════════════════════════════════════════

if pipeline_choice == '1':
    # ═══════════════════════════════════════════════════════════════════
    # INVESTIGATION CONTEXT (OPTIONAL)
    # ═══════════════════════════════════════════════════════════════════
    
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}INVESTIGATION CONTEXT (Optional)")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.WHITE}Provide hints, IOCs, or context to guide the investigation.{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}Examples:{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  • Known IOCs: 'IP 192.168.1.100, hash abc123...'")
    print(f"{Fore.LIGHTBLACK_EX}  • Techniques: 'Look for credential dumping'")
    print(f"{Fore.LIGHTBLACK_EX}  • Time hints: 'Attack occurred around 3PM'")
    print(f"{Fore.LIGHTBLACK_EX}  • Suspicious users: 'Focus on user admin123'")
    print(f"{Fore.LIGHTBLACK_EX}  • Press Enter to skip{Fore.RESET}\n")
    
    try:
        investigation_context = input(f"{Fore.LIGHTGREEN_EX}Context/Hints: {Fore.RESET}").strip()
        
        if investigation_context:
            print(f"\n{Fore.LIGHTGREEN_EX}✓ Context recorded:{Fore.RESET}")
            print(f"{Fore.LIGHTYELLOW_EX}  {investigation_context}{Fore.RESET}")
            print(f"{Fore.LIGHTBLACK_EX}  This will be included in the analysis prompt.{Fore.RESET}\n")
        else:
            investigation_context = ""
            print(f"{Fore.LIGHTBLACK_EX}No context provided - proceeding with standard analysis.{Fore.RESET}\n")
            
    except (KeyboardInterrupt, EOFError):
        print(f"\n{Fore.YELLOW}Skipping context input...{Fore.RESET}")
        investigation_context = ""
    
    # ═══════════════════════════════════════════════════════════════════
    # OPTIONAL GUIDANCE TOGGLES (flag-gated exemplar/evidence requirements)
    # ═══════════════════════════════════════════════════════════════════
    guidance_on = False
    known_killchain = ""
    try:
        ans = input(f"{Fore.LIGHTGREEN_EX}Enable guidance (tiny exemplar + evidence requirements)? [y/N]: {Fore.RESET}").strip().lower()
        guidance_on = ans in ['y', 'yes']
        if guidance_on:
            known_killchain = input(f"{Fore.LIGHTGREEN_EX}Known killchain (optional, e.g., rdp_password_spray): {Fore.RESET}").strip()
    except (KeyboardInterrupt, EOFError):
        guidance_on = False
        known_killchain = ""
    
    # ═══════════════════════════════════════════════════════════════════
    # QUERY METHOD SELECTION (LLM vs Manual)
    # ═══════════════════════════════════════════════════════════════════
    
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}QUERY METHOD SELECTION")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}\n")
    
    print(f"{Fore.LIGHTGREEN_EX}[1] 🤖 Natural Language (LLM-Assisted)")
    print(f"{Fore.LIGHTBLACK_EX}    Describe what you're hunting for in plain English")
    print(f"{Fore.LIGHTBLACK_EX}    Example: 'Find PowerShell exfiltration from slflare'")
    print(f"{Fore.LIGHTBLACK_EX}    • LLM picks table & filters automatically")
    print(f"{Fore.LIGHTBLACK_EX}    • Uses investigation context")
    print(f"{Fore.LIGHTBLACK_EX}    • Best for: Complex queries, natural language input\n")
    
    # Removed option 2 (Structured Input) to keep modes simple: LLM or Custom KQL only
    
    print(f"{Fore.LIGHTMAGENTA_EX}[2] 💻 Custom KQL (Expert Mode)")
    print(f"{Fore.LIGHTBLACK_EX}    Write your own KQL query, LLM filters results")
    print(f"{Fore.LIGHTBLACK_EX}    Example: 'DeviceProcessEvents | where ProcessCommandLine contains \"malware\"'")
    print(f"{Fore.LIGHTBLACK_EX}    • Full KQL control")
    print(f"{Fore.LIGHTBLACK_EX}    • LLM analyzes and filters results based on context")
    print(f"{Fore.LIGHTBLACK_EX}    • Best for: Advanced users with KQL knowledge\n")
    
    try:
        query_method = input(f"{Fore.LIGHTGREEN_EX}Select query method [1 or 2]: {Fore.RESET}").strip()
        
        if query_method not in ['1', '2']:
            print(f"{Fore.YELLOW}Invalid selection. Defaulting to Natural Language (1).{Fore.RESET}")
            query_method = '1'
        
        use_llm_query = (query_method == '1')
        use_custom_kql = (query_method == '2')
        
        if use_llm_query:
            print(f"{Fore.LIGHTGREEN_EX}✓ Using LLM-assisted query building{Fore.RESET}\n")
        elif use_custom_kql:
            print(f"{Fore.LIGHTMAGENTA_EX}✓ Using custom KQL expert mode{Fore.RESET}\n")
        # Structured manual input removed
            
    except (KeyboardInterrupt, EOFError):
        print(f"\n{Fore.YELLOW}Defaulting to Natural Language (LLM-Assisted)...{Fore.RESET}")
        use_llm_query = True

else:
    # For Mode 2 (Anomaly) and Mode 3 (CTF): No context or query method needed
    investigation_context = ""
    use_llm_query = False
    use_custom_kql = False

# ═══════════════════════════════════════════════════════════════════
# INVESTIGATION TIMEFRAME (AUTO-SET)
# ═══════════════════════════════════════════════════════════════════

from datetime import datetime, timedelta

# Optional: Check workspace data availability (informational only)
try:
    retention_query = """
    union DeviceLogonEvents, DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, SigninLogs, AzureActivity
    | summarize 
        EarliestEvent=min(TimeGenerated), 
        LatestEvent=max(TimeGenerated),
        TotalRecords=count()
    | extend RetentionDays = datetime_diff('day', LatestEvent, EarliestEvent)
    """
    
    retention_check = law_client.query_workspace(
        workspace_id=_keys.LOG_ANALYTICS_WORKSPACE_ID,
        query=retention_query,
        timespan=timedelta(days=365)
    )
    
    if retention_check.tables and len(retention_check.tables[0].rows) > 0:
        row = retention_check.tables[0].rows[0]
        earliest = row[0]
        latest = row[1]
        total_records = row[2]
        retention_days = row[3] if len(row) > 3 else 0
        
        print(f"\n{Fore.LIGHTBLACK_EX}{'─'*70}")
        print(f"{Fore.LIGHTBLACK_EX}Workspace Data: {total_records:,} records | {retention_days} days span | {str(earliest)[:10]} to {str(latest)[:10]}")
        print(f"{Fore.LIGHTBLACK_EX}{'─'*70}{Fore.RESET}")
except Exception as e:
    pass  # Silent fail - not critical

# ═══════════════════════════════════════════════════════════════════
# AUTO-SET TIMEFRAME: 30 DAYS (NO PROMPTS)
# ═══════════════════════════════════════════════════════════════════

try:
    # HARDCODED: ALWAYS 30 DAYS BACK (NO USER INPUT)
    HARDCODED_DEFAULT_DAYS = 365
    
    start_date = datetime.now() - timedelta(days=HARDCODED_DEFAULT_DAYS)
    end_date = datetime.now()
    timerange_hours = HARDCODED_DEFAULT_DAYS * 24
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}INVESTIGATION TIMEFRAME (Auto-Set)")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.WHITE}  From: {Fore.LIGHTYELLOW_EX}{start_date.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{Fore.WHITE}  To:   {Fore.LIGHTYELLOW_EX}{end_date.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{Fore.WHITE}  Duration: {Fore.LIGHTGREEN_EX}{HARDCODED_DEFAULT_DAYS} days ({timerange_hours} hours)")
    print(f"{Fore.LIGHTBLACK_EX}  [Auto-configured: Last 30 days]{Fore.RESET}")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}\n")

except (KeyboardInterrupt, EOFError):
    print(f"\n{Fore.YELLOW}Exiting...{Fore.RESET}")
    exit(0)

# ═══════════════════════════════════════════════════════════════════
# EXECUTE SELECTED PIPELINE
# ═══════════════════════════════════════════════════════════════════

if pipeline_choice == '1':
    # ═══ THREAT HUNTING PIPELINE ═══
    hunt_results, query_context = THREAT_HUNT_PIPELINE.run_threat_hunt(
        openai_client=openai_client,
        law_client=law_client,
        workspace_id=_keys.LOG_ANALYTICS_WORKSPACE_ID,
        model=model,
        severity_config=severity_config,
        timerange_hours=timerange_hours,
        start_date=start_date,
        end_date=end_date,
        investigation_context=investigation_context,  # Pass investigation context
        use_llm_query=use_llm_query,  # Pass query method flag
        use_custom_kql=use_custom_kql,  # Pass custom KQL flag
        guidance_on=guidance_on,
        known_killchain=known_killchain
    )

    # Post-process results per Result View Mode
    try:
        if hunt_results and 'findings' in hunt_results:
            findings = hunt_results.get('findings', [])
            critical_only = [f for f in findings if f.get('confidence','Medium') == 'High']
            if result_view_choice == '2':
                hunt_results['findings'] = critical_only
                print(f"{Fore.LIGHTCYAN_EX}View Mode: Only Critical — {len(critical_only)} finding(s){Fore.RESET}")
            elif result_view_choice == '3':
                # Keep both sets for display or downstream
                hunt_results['critical_findings'] = critical_only
                hunt_results['strict_findings'] = findings
                print(f"{Fore.LIGHTCYAN_EX}View Mode: Critical + Strict — Critical: {len(critical_only)}, Strict: {len(findings)}{Fore.RESET}")
            else:
                print(f"{Fore.LIGHTCYAN_EX}View Mode: Strict — {len(findings)} finding(s){Fore.RESET}")
    except Exception:
        pass

elif pipeline_choice == '2':
    # ═══ ANOMALY DETECTION PIPELINE ═══
    hunt_results = ANOMALY_DETECTION_PIPELINE.run_anomaly_detection(
        openai_client=openai_client,
        law_client=law_client,
        workspace_id=_keys.LOG_ANALYTICS_WORKSPACE_ID,
        model=model,
        severity_config=severity_config
    )
    
    # Correlate findings if multiple found
    if hunt_results and len(hunt_results.get('findings', [])) > 1:
        chains = CORRELATION_ENGINE.correlate_findings(hunt_results['findings'])
        if chains:
            CORRELATION_ENGINE.get_correlation_engine().display_attack_chains(chains)

elif pipeline_choice == '3':
    # ═══ CTF HUNT MODE ═══
    # CTF Mode uses Azure Sentinel / Log Analytics exclusively for longer data retention
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}CTF HUNT MODE - Azure Sentinel")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    print(f"{Fore.LIGHTGREEN_EX}✓ Using Azure Sentinel / Log Analytics{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  • Longer data retention than MDE{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  • Multi-source correlation{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}  • Historical analysis support{Fore.RESET}\n")
    
    # CTF Mode always uses Log Analytics (Sentinel)
    query_client = law_client
    workspace_id = _keys.LOG_ANALYTICS_WORKSPACE_ID
    
    # DEBUG: Verify client type
    print(f"{Fore.LIGHTYELLOW_EX}🔍 DEBUG start_button.py: query_client type = '{type(query_client).__name__}'{Fore.RESET}")
    print(f"{Fore.LIGHTYELLOW_EX}🔍 DEBUG start_button.py: Has query_workspace = {hasattr(query_client, 'query_workspace')}{Fore.RESET}")
    print(f"{Fore.LIGHTYELLOW_EX}🔍 DEBUG start_button.py: Has query_advanced_hunting = {hasattr(query_client, 'query_advanced_hunting')}{Fore.RESET}\n")
    
    hunt_results, report_file = CTF_HUNT_MODE.run_ctf_hunt(
        openai_client=openai_client,
        law_client=query_client,
        workspace_id=workspace_id,
        model=model,
        severity_config=severity_config,
        timerange_hours=timerange_hours,
        start_date=start_date,
        end_date=end_date
    )

else:
    print(f"{Fore.RED}Invalid selection. Exiting.{Fore.RESET}")
    exit(0)

print(f"\n{Fore.LIGHTGREEN_EX}{'='*70}")
print(f"{Fore.LIGHTGREEN_EX}SESSION COMPLETE")
print(f"{Fore.LIGHTGREEN_EX}{'='*70}")
print(f"{Fore.WHITE}All findings have been logged to _threats.jsonl")
print(f"{Fore.LIGHTCYAN_EX}{'='*70}\n")
