"""
Threat Hunt Pipeline - Targeted Investigation Mode
User-directed threat hunting with specific hypothesis
Focuses on targeted queries and deep analysis
"""

import time
from datetime import datetime, timedelta
from color_support import Fore
import EXECUTOR
import UTILITIES
import GUARDRAILS
import PROMPT_MANAGEMENT
import MODEL_SELECTOR
import SEVERITY_LEVELS
import CHAT_MODE

def get_timeframe():
    """Prompt user for investigation timeframe"""
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}INVESTIGATION TIMEFRAME")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.WHITE}Specify the time range for your investigation.{Fore.RESET}\n")
    
    try:
        # Get start date
        start_input = input(f"{Fore.LIGHTGREEN_EX}Start date (YYYY-MM-DD) or hours ago [default: 168 hours/7 days ago]: {Fore.RESET}").strip()
        
        if not start_input:
            # Default to 7 days ago
            start_date = datetime.now() - timedelta(hours=168)
            hours_back = 168
        elif start_input.isdigit():
            # User entered hours
            hours_back = int(start_input)
            start_date = datetime.now() - timedelta(hours=hours_back)
        else:
            # User entered a date
            start_date = datetime.strptime(start_input, '%Y-%m-%d')
            hours_back = int((datetime.now() - start_date).total_seconds() / 3600)
        
        # Get end date
        end_input = input(f"{Fore.LIGHTGREEN_EX}End date (YYYY-MM-DD) or press Enter for now: {Fore.RESET}").strip()
        
        if not end_input:
            end_date = datetime.now()
        else:
            end_date = datetime.strptime(end_input, '%Y-%m-%d')
            # Add 23:59:59 to end date to include the whole day
            end_date = end_date.replace(hour=23, minute=59, second=59)
            # If end date is in the future, use now
            if end_date > datetime.now():
                end_date = datetime.now()
        
        # Calculate hours between dates
        time_diff = end_date - start_date
        timerange_hours = int(time_diff.total_seconds() / 3600)
        
        if timerange_hours <= 0:
            print(f"{Fore.RED}Error: End date must be after start date.{Fore.RESET}")
            return None, None, None
        
        # Display selected timeframe
        print(f"\n{Fore.LIGHTCYAN_EX}Selected Timeframe:{Fore.RESET}")
        print(f"{Fore.WHITE}  From: {Fore.LIGHTYELLOW_EX}{start_date.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.WHITE}  To:   {Fore.LIGHTYELLOW_EX}{end_date.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.WHITE}  Duration: {Fore.LIGHTYELLOW_EX}{timerange_hours} hours (~{timerange_hours//24} days){Fore.RESET}\n")
        
        return timerange_hours, start_date, end_date
    
    except ValueError as e:
        print(f"{Fore.RED}Invalid date format. Please use YYYY-MM-DD (e.g., 2025-10-01){Fore.RESET}")
        return None, None, None
    except (KeyboardInterrupt, EOFError):
        print(f"\n{Fore.YELLOW}Cancelled.{Fore.RESET}")
        return None, None, None

def get_structured_query_params():
    """Get structured query parameters directly from user"""
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}📋 THREAT HUNT PARAMETERS")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.WHITE}Specify your investigation parameters.{Fore.RESET}\n")
    
    try:
        # Select table
        print(f"{Fore.LIGHTCYAN_EX}Available Tables:{Fore.RESET}")
        print(f"{Fore.WHITE}[1] DeviceLogonEvents (login/authentication activity)")
        print(f"{Fore.WHITE}[2] DeviceProcessEvents (process execution)")
        print(f"{Fore.WHITE}[3] DeviceNetworkEvents (network connections)")
        print(f"{Fore.WHITE}[4] DeviceFileEvents (file operations)")
        print(f"{Fore.WHITE}[5] DeviceRegistryEvents (registry modifications)")
        print(f"{Fore.WHITE}[6] SigninLogs (Azure AD sign-ins)")
        print(f"{Fore.WHITE}[7] AuditLogs (Azure AD audit events)")
        print(f"{Fore.WHITE}[8] AzureActivity (Azure resource operations)")
        print(f"{Fore.WHITE}[9] AlertInfo (alert metadata)")
        print(f"{Fore.WHITE}[10] AlertEvidence (alert details)")
        print(f"{Fore.WHITE}[11] AzureNetworkAnalytics_CL (NSG flow logs)")
        print(f"{Fore.WHITE}[12] AzureNetworkAnalyticsIPDetails_CL (IP details from NSG){Fore.RESET}\n")
        
        table_choice = input(f"{Fore.LIGHTGREEN_EX}Select table [1-12]: {Fore.RESET}").strip()
        
        table_map = {
            '1': 'DeviceLogonEvents',
            '2': 'DeviceProcessEvents',
            '3': 'DeviceNetworkEvents',
            '4': 'DeviceFileEvents',
            '5': 'DeviceRegistryEvents',
            '6': 'SigninLogs',
            '7': 'AuditLogs',
            '8': 'AzureActivity',
            '9': 'AlertInfo',
            '10': 'AlertEvidence',
            '11': 'AzureNetworkAnalytics_CL',
            '12': 'AzureNetworkAnalyticsIPDetails_CL'
        }
        
        table_name = table_map.get(table_choice, 'DeviceLogonEvents')
        
        print(f"\n{Fore.LIGHTCYAN_EX}Filters (leave blank to query all):{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}Note: If you specify both, query requires BOTH conditions to match{Fore.RESET}\n")
        
        # Get filters
        device_name = input(f"{Fore.LIGHTGREEN_EX}DeviceName contains (optional, press Enter for all): {Fore.RESET}").strip()
        account_name = input(f"{Fore.LIGHTGREEN_EX}AccountName contains (optional, press Enter for all): {Fore.RESET}").strip()
        
        # Show what will be queried
        print(f"\n{Fore.LIGHTCYAN_EX}Query will search for:{Fore.RESET}")
        if device_name and account_name:
            print(f"{Fore.LIGHTYELLOW_EX}  Records where DeviceName contains '{device_name}' AND AccountName contains '{account_name}'")
            print(f"{Fore.YELLOW}  (Both conditions must match){Fore.RESET}")
        elif device_name:
            print(f"{Fore.LIGHTGREEN_EX}  All records where DeviceName contains '{device_name}'{Fore.RESET}")
        elif account_name:
            print(f"{Fore.LIGHTGREEN_EX}  All records where AccountName contains '{account_name}'{Fore.RESET}")
        else:
            print(f"{Fore.LIGHTBLACK_EX}  All records (no filters){Fore.RESET}")
        
        return {
            'table_name': table_name,
            'device_name': device_name,
            'account_name': account_name
        }
    
    except (KeyboardInterrupt, EOFError):
        print(f"\n{Fore.YELLOW}Cancelled.{Fore.RESET}")
        return None

def run_threat_hunt(openai_client, law_client, workspace_id, model, severity_config, timerange_hours, start_date, end_date, investigation_context="", use_llm_query=False, use_custom_kql=False, guidance_on: bool = False, known_killchain: str = ""):
    """Execute targeted threat hunting workflow"""
    
    # Import required modules
    import EXECUTOR
    import LOCAL_QUERY_PARSER
    import pandas as pd
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}🎯 THREAT HUNTING MODE")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.WHITE}Investigate specific suspicions with targeted queries.{Fore.RESET}\n")
    
    # Display investigation context if provided
    if investigation_context:
        print(f"{Fore.LIGHTYELLOW_EX}📌 Investigation Context:{Fore.RESET}")
        print(f"{Fore.WHITE}  {investigation_context}{Fore.RESET}\n")
    
    # ═══════════════════════════════════════════════════════════════════
    # QUERY BUILDING: LLM-Assisted vs Manual vs Custom KQL
    # ═══════════════════════════════════════════════════════════════════
    
    if use_custom_kql:
        # ═══ CUSTOM KQL MODE ═══
        print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
        print(f"{Fore.LIGHTMAGENTA_EX}💻 CUSTOM KQL EXPERT MODE")
        print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
        print(f"{Fore.WHITE}Write your own KQL query. Results will be filtered by LLM based on your context.{Fore.RESET}\n")
        print(f"{Fore.LIGHTBLACK_EX}Examples:{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}  • DeviceProcessEvents | where ProcessCommandLine contains 'powershell'")
        print(f"{Fore.LIGHTBLACK_EX}  • DeviceLogonEvents | where RemoteIP == '79.76.123.251'")
        print(f"{Fore.LIGHTBLACK_EX}  • union DeviceProcessEvents, DeviceNetworkEvents | where AccountName contains 'slflare'")
        print(f"{Fore.LIGHTBLACK_EX}Note: Time filter will be added automatically{Fore.RESET}\n")
        
        try:
            print(f"{Fore.LIGHTCYAN_EX}Enter your KQL query (multi-line supported, type 'END' on new line when done):{Fore.RESET}")
            custom_kql_lines = []
            while True:
                line = input(f"{Fore.WHITE}  {Fore.RESET}").strip()
                if line.upper() == 'END':
                    break
                if line:
                    custom_kql_lines.append(line)
            
            if not custom_kql_lines:
                print(f"{Fore.RED}No query provided. Exiting.{Fore.RESET}")
                return None, None
            
            custom_kql = ' '.join(custom_kql_lines)
            
            # Add time filter if not present
            if 'where TimeGenerated' not in custom_kql and 'where Timestamp' not in custom_kql:
                # Detect which time field the table uses
                table_match = custom_kql.split()[0]  # First word should be table name
                time_field = EXECUTOR.detect_time_field(law_client, workspace_id, table_match)
                
                time_filter = f"| where {time_field} between (datetime({start_date.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}) .. datetime({end_date.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}))"
                
                # Insert time filter after table name
                parts = custom_kql.split('|', 1)
                if len(parts) == 2:
                    custom_kql = f"{parts[0].strip()}\n{time_filter}\n| {parts[1].strip()}"
                else:
                    custom_kql = f"{parts[0].strip()}\n{time_filter}"
            
            print(f"\n{Fore.LIGHTGREEN_EX}{'='*70}")
            print(f"{Fore.LIGHTGREEN_EX}FINAL KQL QUERY (with time filter)")
            print(f"{Fore.LIGHTGREEN_EX}{'='*70}")
            print(f"{Fore.LIGHTYELLOW_EX}{custom_kql}")
            print(f"{Fore.LIGHTGREEN_EX}{'='*70}\n")
            
            # Execute custom KQL
            print(f"{Fore.LIGHTCYAN_EX}Executing custom query...{Fore.RESET}\n")
            
            response = law_client.query_workspace(
                workspace_id=workspace_id,
                query=custom_kql,
                timespan=timedelta(hours=timerange_hours)
            )
            
            if not response.tables or len(response.tables[0].rows) == 0:
                print(f"{Fore.YELLOW}No data returned from custom query.{Fore.RESET}")
                return None, None
            
            # Convert results to CSV format
            table = response.tables[0]
            columns = table.columns
            rows = table.rows
            df = pd.DataFrame(rows, columns=columns)
            records_csv = df.to_csv(index=False)
            record_count = len(rows)
            
            print(f"{Fore.LIGHTGREEN_EX}✓ Query returned {record_count} record(s){Fore.RESET}\n")
            
            # Build query context for downstream processing
            query_context = {
                'table_name': 'CustomKQL',
                'device_name': '',
                'user_principal_name': '',
                'caller': '',
                'time_range_hours': timerange_hours,
                'fields': ', '.join(columns),
                'about_individual_user': False,
                'about_individual_host': False,
                'about_network_security_group': False,
                'rationale': f"Custom KQL query with {record_count} results",
                'start_date': start_date,
                'end_date': end_date,
                'custom_kql': custom_kql
            }
            
            # Store results for LLM analysis
            law_query_results = {"records": records_csv, "count": record_count}
            user_query = f"Analyze custom KQL results for suspicious activity and threats"
            
        except (KeyboardInterrupt, EOFError):
            print(f"\n{Fore.YELLOW}Cancelled.{Fore.RESET}")
            return None, None
        except Exception as e:
            print(f"{Fore.RED}Error executing custom KQL: {e}{Fore.RESET}")
            return None, None
    
    elif use_llm_query:
        # ═══ LLM-ASSISTED QUERY BUILDING ═══
        print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
        print(f"{Fore.LIGHTCYAN_EX}🤖 NATURAL LANGUAGE QUERY (LLM-Assisted)")
        print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
        print(f"{Fore.WHITE}Describe what you want to hunt for in plain English.{Fore.RESET}\n")
        print(f"{Fore.LIGHTBLACK_EX}Examples:{Fore.RESET}")
        print(f"{Fore.LIGHTBLACK_EX}  • 'Find PowerShell with encoded commands from user slflare'")
        print(f"{Fore.LIGHTBLACK_EX}  • 'Show failed logins from IP 192.168.1.100'")
        print(f"{Fore.LIGHTBLACK_EX}  • 'Detect credential dumping on server-01'")
        print(f"{Fore.LIGHTBLACK_EX}  • 'Track lateral movement from compromised account'{Fore.RESET}\n")
        
        try:
            user_query = input(f"{Fore.LIGHTGREEN_EX}Your hunt description: {Fore.RESET}").strip()
            
            if not user_query:
                print(f"{Fore.RED}No query provided. Exiting.{Fore.RESET}")
                return None, None
            
            # Combine investigation context with user query for better LLM understanding
            if investigation_context:
                enhanced_query = f"{user_query}\n\nContext: {investigation_context}"
            else:
                enhanced_query = user_query
            
            print(f"\n{Fore.LIGHTCYAN_EX}LLM is analyzing your request and planning the query...{Fore.RESET}\n")
            
            # Use LLM to determine query parameters
            user_message = {"role": "user", "content": enhanced_query}
            query_context = EXECUTOR.get_query_context(openai_client, user_message, model)
            
            # Add timeframe and dates
            query_context['time_range_hours'] = timerange_hours
            query_context['start_date'] = start_date
            query_context['end_date'] = end_date
            
        except (KeyboardInterrupt, EOFError):
            print(f"\n{Fore.YELLOW}Cancelled.{Fore.RESET}")
            return None, None
            
    else:
        # ═══ MANUAL STRUCTURED INPUT ═══
        params = get_structured_query_params()
        if params is None:
            print(f"{Fore.RED}Invalid input. Exiting threat hunt.{Fore.RESET}")
            return None, None
        
        # Build query context from structured parameters
        parser = LOCAL_QUERY_PARSER.get_local_parser()
        default_fields = parser.default_fields.get(params['table_name'], [])
        
        query_context = {
            'table_name': params['table_name'],
            'device_name': params['device_name'],
            'user_principal_name': params['account_name'],
            'caller': params['account_name'] if params['table_name'] == 'AzureActivity' else '',
            'time_range_hours': timerange_hours,
            'fields': default_fields,
            'about_individual_user': bool(params['account_name']),
            'about_individual_host': bool(params['device_name']),
            'about_network_security_group': False,
            'rationale': f"Structured hunt on {params['table_name']} for {timerange_hours} hours",
            'start_date': start_date,
            'end_date': end_date
        }
    
    # ═══════════════════════════════════════════════════════════════════
    # COMMON: Sanitize, Validate & Execute Query
    # ═══════════════════════════════════════════════════════════════════
    
    # Skip query execution if we already have results from custom KQL
    if not use_custom_kql:
        # Sanitize and validate
        query_context = UTILITIES.sanitize_query_context(query_context)
        UTILITIES.display_query_context(query_context)
        GUARDRAILS.validate_tables_and_fields(query_context["table_name"], query_context["fields"])
        
        # Query Log Analytics
        law_query_results = EXECUTOR.query_log_analytics(
            log_analytics_client=law_client,
            workspace_id=workspace_id,
            timerange_hours=query_context["time_range_hours"],
            table_name=query_context["table_name"],
            device_name=query_context["device_name"],
            fields=query_context["fields"],
            caller=query_context["caller"],
            user_principal_name=query_context["user_principal_name"],
            start_date=start_date,
            end_date=end_date
        )
        
        number_of_records = law_query_results['count']
        print(f"{Fore.WHITE}{number_of_records} record(s) returned.\n")

        # Post-query confirmation with real size/ETA
        try:
            import CONFIRMATION_MANAGER
            import TIME_ESTIMATOR
            records_csv = law_query_results.get("records", "")
            approx_tokens = max(1, len(records_csv) // 4)  # ~4 chars/token

            # Choose a conservative limit for hybrid/local models
            if model == "local-mix":
                limit = min(TIME_ESTIMATOR.get_model_context_limit('qwen3:8b'),
                            TIME_ESTIMATOR.get_model_context_limit('gpt-oss:20b'))
            else:
                limit = TIME_ESTIMATOR.get_model_context_limit(model)

            # Always confirm right before inference using real size/ETA
            cost_info = CONFIRMATION_MANAGER.get_cost_info(model)
            ok = CONFIRMATION_MANAGER.confirm_analysis_with_time_estimate(
                model_name=model,
                input_tokens=approx_tokens,
                cost_info=cost_info,
                investigation_mode="threat_hunt",
                severity_config=severity_config
            )
            if not ok:
                print(f"{Fore.YELLOW}Cancelled before analysis. Returning to menu.{Fore.RESET}")
                return None, query_context
        except Exception:
            # Non-fatal: if estimation fails, continue without confirmation
            pass
    else:
        # Custom KQL: already executed, just display context
        number_of_records = law_query_results['count']
        print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
        print(f"{Fore.LIGHTCYAN_EX}QUERY CONTEXT")
        print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
        print(f"{Fore.WHITE}  Custom KQL Mode")
        print(f"{Fore.WHITE}  Records: {Fore.LIGHTCYAN_EX}{number_of_records}")
        print(f"{Fore.WHITE}  Columns: {Fore.LIGHTCYAN_EX}{query_context['fields']}")
        print(f"{Fore.LIGHTCYAN_EX}{'='*70}\n")
        # Post-query confirmation with real size/ETA for Custom KQL path
        try:
            import CONFIRMATION_MANAGER
            records_csv = law_query_results.get("records", "")
            approx_tokens = max(1, len(records_csv) // 4)
            cost_info = CONFIRMATION_MANAGER.get_cost_info(model)
            ok = CONFIRMATION_MANAGER.confirm_analysis_with_time_estimate(
                model_name=model,
                input_tokens=approx_tokens,
                cost_info=cost_info,
                investigation_mode="threat_hunt",
                severity_config=severity_config
            )
            if not ok:
                print(f"{Fore.YELLOW}Cancelled before analysis. Returning to menu.{Fore.RESET}")
                return None, query_context
        except Exception:
            pass
    
    if number_of_records == 0:
        print(f"{Fore.YELLOW}No data found. Try adjusting your query or time range.{Fore.RESET}")
        return None, query_context
    
    # Build threat hunt prompt
    if use_custom_kql:
        # Custom KQL mode - emphasize context filtering
        user_prompt = f"""Analyze the results from this custom KQL query:

{query_context.get('custom_kql', 'Custom query')}

Focus on filtering and identifying relevant findings based on the investigation context.
Look for patterns, encoded data, or anomalies that match the investigation hints provided."""
    elif use_llm_query:
        # Use the natural language query from LLM mode
        user_prompt = user_query
    else:
        # Build structured prompt from manual input
        user_prompt = f"Analyze {params['table_name']} for suspicious activity"
        if params['account_name']:
            user_prompt += f" from account '{params['account_name']}'"
        if params['device_name']:
            user_prompt += f" on device '{params['device_name']}'"
    
    threat_hunt_user_message = PROMPT_MANAGEMENT.build_threat_hunt_prompt(
        user_prompt=user_prompt,
        table_name=query_context["table_name"],
        log_data=law_query_results["records"],
        investigation_context=investigation_context,  # Pass investigation hints to LLM
        guidance_on=guidance_on,
        known_killchain=known_killchain
    )
    
    threat_hunt_system_message = PROMPT_MANAGEMENT.SYSTEM_PROMPT_THREAT_HUNT
    threat_hunt_messages = [threat_hunt_system_message, threat_hunt_user_message]
    
    # Count tokens and select model
    number_of_tokens = MODEL_SELECTOR.count_tokens(threat_hunt_messages, model)
    model = MODEL_SELECTOR.choose_model(model, number_of_tokens)
    MODEL_SELECTOR.validate_model(model)
    
    print(f"{Fore.LIGHTGREEN_EX}Initiating cognitive threat hunt...{Fore.RESET}\n")
    
    # Execute hunt
    start_time = time.time()
    # Prepare investigation context for hybrid model
    investigation_context = {
        'mode': 'threat_hunt',
        'query_method': 'llm' if use_llm_query else 'structured',
        'table_name': query_context.get('table_name'),
        'time_range_hours': timerange_hours,
        'start_date': start_date,
        'end_date': end_date
    }
    
    hunt_results = EXECUTOR.hunt(
        openai_client=openai_client,
        threat_hunt_system_message=threat_hunt_system_message,
        threat_hunt_user_message=threat_hunt_user_message,
        openai_model=model,
        severity_config=severity_config,
        table_name=query_context.get('table_name'),  # Pass table name for smart model selection
        investigation_context=investigation_context
    )
    
    if not hunt_results:
        return None, query_context
    
    elapsed = time.time() - start_time
    
    # Apply severity filtering
    raw_findings_count = len(hunt_results.get('findings', []))
    filtered_findings = SEVERITY_LEVELS.filter_findings_by_severity(
        hunt_results['findings'],
        severity_config
    )
    hunt_results['findings'] = filtered_findings
    
    # Display results
    suppressed_count = raw_findings_count - len(filtered_findings)
    print(f"{Fore.WHITE}Threat hunt complete. Took {elapsed:.2f} seconds.")
    print(f"{Fore.WHITE}Raw findings: {Fore.LIGHTYELLOW_EX}{raw_findings_count}")
    print(f"{Fore.WHITE}Reported ({severity_config['name']}): {Fore.LIGHTRED_EX}{len(filtered_findings)} {Fore.WHITE}potential threat(s)")
    
    if suppressed_count > 0:
        print(f"{Fore.LIGHTBLUE_EX}Suppressed: {suppressed_count} low-confidence findings{Fore.RESET}\n")
    
    if len(filtered_findings) == 0:
        print(f"{Fore.YELLOW}No threats detected at current severity level.{Fore.RESET}")
        return hunt_results, query_context
    
    # Display findings
    input(f"Press {Fore.LIGHTGREEN_EX}[Enter]{Fore.WHITE} to see results.")
    UTILITIES.display_threats(threat_list=hunt_results['findings'])
    
    # Offer chat mode for local models
    if model in {"qwen", "gpt-oss:20b"}:
        try:
            chat_choice = input(f"\n{Fore.LIGHTGREEN_EX}💬 Discuss findings? [y/N]: {Fore.RESET}").strip().lower()
            
            if chat_choice in ['y', 'yes']:
                log_summary = f"{number_of_records} records from {query_context['table_name']}"
                CHAT_MODE.start_chat_mode(
                    findings=hunt_results['findings'],
                    log_data_summary=log_summary,
                    query_context=query_context,
                    model_name=model
                )
        except (KeyboardInterrupt, EOFError, ValueError):
            pass
    
    return hunt_results, query_context

