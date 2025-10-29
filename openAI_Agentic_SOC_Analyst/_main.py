# Standard library
import time

# Third-party libraries
from color_support import Fore, init, Style
from openai import OpenAI
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient

# Local modules
import _keys
import SEVERITY_LEVELS
import MODEL_SELECTOR
import THREAT_HUNT_PIPELINE
import ANOMALY_DETECTION_PIPELINE
import CORRELATION_ENGINE
import CTF_HUNT_MODE

# Initialize
init(autoreset=True)

# Build Azure Log Analytics Client
try:
    credential = DefaultAzureCredential()
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

# Build OpenAI client
openai_client = OpenAI(api_key=_keys.OPENAI_API_KEY)

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
# MODEL & SEVERITY SELECTION (Common to Both Pipelines)
# ═══════════════════════════════════════════════════════════════════

# Select model
model = MODEL_SELECTOR.prompt_model_selection()

# Select severity level
severity_level = SEVERITY_LEVELS.prompt_severity_selection()
severity_config = SEVERITY_LEVELS.get_severity_config(severity_level)

# Display selected configuration
SEVERITY_LEVELS.display_severity_banner(severity_level)

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
    
    print(f"{Fore.LIGHTYELLOW_EX}[2] 📋 Structured Input (Manual)")
    print(f"{Fore.LIGHTBLACK_EX}    Select table and filters step-by-step")
    print(f"{Fore.LIGHTBLACK_EX}    • More control, predictable")
    print(f"{Fore.LIGHTBLACK_EX}    • No extra LLM cost for query planning")
    print(f"{Fore.LIGHTBLACK_EX}    • Best for: Simple targeted queries\n")
    
    print(f"{Fore.LIGHTMAGENTA_EX}[3] 💻 Custom KQL (Expert Mode)")
    print(f"{Fore.LIGHTBLACK_EX}    Write your own KQL query, LLM filters results")
    print(f"{Fore.LIGHTBLACK_EX}    Example: 'DeviceProcessEvents | where ProcessCommandLine contains \"malware\"'")
    print(f"{Fore.LIGHTBLACK_EX}    • Full KQL control")
    print(f"{Fore.LIGHTBLACK_EX}    • LLM analyzes and filters results based on context")
    print(f"{Fore.LIGHTBLACK_EX}    • Best for: Advanced users with KQL knowledge\n")
    
    try:
        query_method = input(f"{Fore.LIGHTGREEN_EX}Select query method [1-3]: {Fore.RESET}").strip()
        
        if query_method not in ['1', '2', '3']:
            print(f"{Fore.YELLOW}Invalid selection. Defaulting to Natural Language (1).{Fore.RESET}")
            query_method = '1'
        
        use_llm_query = (query_method == '1')
        use_custom_kql = (query_method == '3')
        
        if use_llm_query:
            print(f"{Fore.LIGHTGREEN_EX}✓ Using LLM-assisted query building{Fore.RESET}\n")
        elif use_custom_kql:
            print(f"{Fore.LIGHTMAGENTA_EX}✓ Using custom KQL expert mode{Fore.RESET}\n")
        else:
            print(f"{Fore.LIGHTGREEN_EX}✓ Using structured manual input{Fore.RESET}\n")
            
    except (KeyboardInterrupt, EOFError):
        print(f"\n{Fore.YELLOW}Defaulting to manual mode...{Fore.RESET}")
        use_llm_query = False

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
    HARDCODED_DEFAULT_DAYS = 30
    
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
        use_custom_kql=use_custom_kql  # Pass custom KQL flag
    )

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
    
    # Data Source Selection
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}SELECT DATA SOURCE")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    
    print(f"{Fore.LIGHTGREEN_EX}[1]{Fore.RESET} {Fore.LIGHTCYAN_EX}Microsoft Defender for Endpoint (MDE){Fore.RESET} {Fore.LIGHTGREEN_EX}← Recommended{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}    • All tables available (DeviceRegistryEvents included!){Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}    • Real-time data (no ingestion delay){Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}    • Free (included in MDE license){Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}    • Best for CTF hunting{Fore.RESET}\n")
    
    print(f"{Fore.LIGHTYELLOW_EX}[2]{Fore.RESET} {Fore.WHITE}Azure Sentinel / Log Analytics{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}    • Configured tables only{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}    • Multi-source correlation{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}    • Long-term storage{Fore.RESET}\n")
    
    try:
        data_source_choice = input(f"{Fore.LIGHTGREEN_EX}Select data source [1-2] (default: 1): {Fore.RESET}").strip()
        if not data_source_choice or data_source_choice == '1':
            data_source = 'MDE'
            print(f"{Fore.LIGHTGREEN_EX}✓ Using MDE Advanced Hunting{Fore.RESET}\n")
            
            # Create MDE client
            import MDE_CLIENT
            try:
                mde_client = MDE_CLIENT.create_mde_client(
                    tenant_id=_keys.MDE_TENANT_ID,
                    client_id=_keys.MDE_CLIENT_ID,
                    client_secret=_keys.MDE_CLIENT_SECRET
                )
                print(f"{Fore.LIGHTGREEN_EX}✓ MDE client initialized{Fore.RESET}\n")
                query_client = mde_client
                workspace_id = None  # Not used for MDE
            except Exception as e:
                print(f"{Fore.RED}Failed to initialize MDE client: {e}{Fore.RESET}")
                print(f"{Fore.YELLOW}Falling back to Azure Sentinel...{Fore.RESET}\n")
                data_source = 'Sentinel'
                query_client = law_client
                workspace_id = _keys.LOG_ANALYTICS_WORKSPACE_ID
        else:
            data_source = 'Sentinel'
            print(f"{Fore.LIGHTGREEN_EX}✓ Using Azure Sentinel{Fore.RESET}\n")
            query_client = law_client
            workspace_id = _keys.LOG_ANALYTICS_WORKSPACE_ID
    except (KeyboardInterrupt, EOFError):
        data_source = 'MDE'  # Default
        import MDE_CLIENT
        mde_client = MDE_CLIENT.create_mde_client(
            tenant_id=_keys.MDE_TENANT_ID,
            client_id=_keys.MDE_CLIENT_ID,
            client_secret=_keys.MDE_CLIENT_SECRET
        )
        query_client = mde_client
        workspace_id = None
    
    hunt_results, report_file = CTF_HUNT_MODE.run_ctf_hunt(
        openai_client=openai_client,
        law_client=query_client,
        workspace_id=workspace_id,
        model=model,
        severity_config=severity_config,
        timerange_hours=timerange_hours,
        start_date=start_date,
        end_date=end_date,
        data_source=data_source
    )

else:
    print(f"{Fore.RED}Invalid selection. Exiting.{Fore.RESET}")
    exit(0)

print(f"\n{Fore.LIGHTGREEN_EX}{'='*70}")
print(f"{Fore.LIGHTGREEN_EX}SESSION COMPLETE")
print(f"{Fore.LIGHTGREEN_EX}{'='*70}")
print(f"{Fore.WHITE}All findings have been logged to _threats.jsonl")
print(f"{Fore.LIGHTCYAN_EX}{'='*70}\n")
