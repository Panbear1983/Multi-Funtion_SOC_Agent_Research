# Standard library
from datetime import timedelta
import json

# Third-party libraries
import pandas as pd
from color_support import Fore, Style
from openai import RateLimitError, OpenAIError
import OLLAMA_CLIENT
import QWEN_ENHANCER
import GPT_OSS_ENHANCER

# Local modules
import PROMPT_MANAGEMENT
import TIME_ESTIMATOR

def select_optimal_local_model(messages, table_name=None, severity_config=None):
    """
    Intelligently select which local model to use based on task characteristics
    
    Selection Strategy:
    - High-volume tables (lots of data) → Qwen (128K context, faster)
    - Reasoning-heavy tables (complex analysis) → GPT-OSS (20B params, better logic)
    - Token count fallback → Qwen if >50K tokens, GPT-OSS if ≤50K
    """
    
    # Define table categories
    HIGH_VOLUME_TABLES = {
        'DeviceNetworkEvents',      # Lots of network connections
        'DeviceFileEvents',          # Many file operations  
        'SigninLogs',                # Many authentication events
        'AzureNetworkAnalytics_CL'   # Network flow data
    }
    
    REASONING_HEAVY_TABLES = {
        'DeviceProcessEvents',       # Command line analysis, tactics
        'DeviceRegistryEvents',      # Persistence mechanisms
        'AzureActivity',             # Cloud policy violations
        'DeviceLogonEvents'          # Login pattern analysis
    }
    
    # Strategy 1: Table-based routing (if table_name provided)
    if table_name:
        if table_name in HIGH_VOLUME_TABLES:
            return "qwen"
        elif table_name in REASONING_HEAVY_TABLES:
            return "gpt-oss:20b"
    
    # Strategy 2: Token count routing (fallback)
    import MODEL_SELECTOR
    try:
        token_count = MODEL_SELECTOR.count_tokens(messages, "qwen")
        
        if token_count > 50000:
            # Large dataset → Qwen (handles volume better)
            return "qwen"
        else:
            # Smaller dataset → GPT-OSS (better reasoning)
            return "gpt-oss:20b"
    except:
        # Default fallback
        return "qwen"

def _should_chunk_messages(model_name, messages):
    """Check if messages need chunking based on model limits"""
    try:
        input_tokens = TIME_ESTIMATOR.estimate_tokens(messages, "gpt-4")
        model_limit = TIME_ESTIMATOR.get_model_context_limit(model_name)
        
        # Use 80% of limit as threshold for safety
        threshold = int(model_limit * 0.8)
        
        return input_tokens > threshold, input_tokens, threshold
    except:
        return False, 0, 0

def _calculate_available_chunk_size(messages, model_name, total_chunk_size_tokens):
    """
    Calculate available tokens for CSV data chunking.
    Accounts for system message and user message prefix (instructions before Log Data).
    """
    # Extract system message and user message prefix
    system_tokens = 0
    user_prefix_tokens = 0
    
    for msg in messages:
        if isinstance(msg, dict):
            if msg.get("role") == "system":
                system_content = msg.get("content", "")
                # Use "gpt-4" encoding for token estimation (works for all models, fallback handles Ollama)
                system_tokens = TIME_ESTIMATOR.estimate_tokens([system_content], "gpt-4")
            elif msg.get("role") == "user":
                content = msg.get("content", "")
                # Extract user prefix (everything before "Log Data:" or "Analyze these logs:")
                if "Log Data:" in content:
                    user_prefix = content.split("Log Data:")[0]
                elif "Analyze these logs:" in content:
                    user_prefix = content.split("Analyze these logs:")[0]
                else:
                    user_prefix = content
                # Use "gpt-4" encoding for token estimation (works for all models, fallback handles Ollama)
                user_prefix_tokens = TIME_ESTIMATOR.estimate_tokens([user_prefix], "gpt-4")
    
    # Calculate available tokens for CSV data
    # Reserve 1K tokens for safety buffer (model overhead, formatting, etc.)
    safety_buffer = 1000
    available_for_csv = total_chunk_size_tokens - system_tokens - user_prefix_tokens - safety_buffer
    
    # Ensure minimum chunk size (at least 1K tokens for CSV)
    available_for_csv = max(available_for_csv, 1000)
    
    return available_for_csv, system_tokens, user_prefix_tokens

def _chunk_and_process_local_model(enhancer, messages, model_name, max_lines, chunk_size_tokens):
    """Chunk messages and process with local model"""
    from color_support import Fore
    
    # Calculate actual available chunk size for CSV data (accounts for system/user messages)
    available_csv_tokens, system_tokens, user_prefix_tokens = _calculate_available_chunk_size(
        messages, model_name, chunk_size_tokens
    )
    
    if available_csv_tokens < 1000:
        print(f"{Fore.YELLOW}⚠️  Warning: System/user messages use most of context window. Available for CSV: {available_csv_tokens:,} tokens{Fore.RESET}")
    
    print(f"{Fore.LIGHTBLACK_EX}Chunk size breakdown: System={system_tokens:,} | User prefix={user_prefix_tokens:,} | Available for CSV={available_csv_tokens:,} | Total limit={chunk_size_tokens:,}{Fore.RESET}")
    
    # Extract CSV data
    csv_data = ""
    for msg in messages:
        if isinstance(msg, dict) and msg.get("role") == "user":
            content = msg.get("content", "")
            if "Log Data:" in content:
                csv_start = content.find("Log Data:") + len("Log Data:")
                csv_data = content[csv_start:].strip()
                break
            elif "Analyze these logs:" in content:
                csv_start = content.find("Analyze these logs:") + len("Analyze these logs:")
                csv_data = content[csv_start:].strip()
                break
    
    if not csv_data:
        print(f"{Fore.YELLOW}No CSV data found for chunking{Fore.RESET}")
        return enhancer.enhanced_hunt(messages, model_name=model_name, max_lines=max_lines)
    
    # Split CSV into chunks using AVAILABLE tokens (not total chunk size)
    lines = csv_data.split('\n')
    if len(lines) < 2:
        return enhancer.enhanced_hunt(messages, model_name=model_name, max_lines=max_lines)
    
    header = lines[0]
    data_lines = lines[1:]
    
    chunks = []
    current_chunk = [header]
    # Use "gpt-4" encoding for consistent token estimation (fallback handles Ollama models)
    current_tokens = TIME_ESTIMATOR.estimate_tokens([header], "gpt-4")
    
    for line in data_lines:
        if not line.strip():
            continue
        
        line_tokens = TIME_ESTIMATOR.estimate_tokens([line], "gpt-4")
        
        # Use available_csv_tokens instead of chunk_size_tokens
        if current_tokens + line_tokens > available_csv_tokens and len(current_chunk) > 1:
            chunks.append('\n'.join(current_chunk))
            current_chunk = [header, line]
            current_tokens = TIME_ESTIMATOR.estimate_tokens([header, line], "gpt-4")
        else:
            current_chunk.append(line)
            current_tokens += line_tokens
    
    if len(current_chunk) > 1:
        chunks.append('\n'.join(current_chunk))
    
    print(f"{Fore.LIGHTCYAN_EX}Processing {len(chunks)} chunks with {model_name}...{Fore.RESET}")
    
    all_results = []
    
    for i, chunk in enumerate(chunks):
        print(f"{Fore.WHITE}Processing chunk {i+1}/{len(chunks)}...{Fore.RESET}")

        try:
            # Create chunk-specific messages
            chunk_messages = []
            for msg in messages:
                if isinstance(msg, dict) and msg.get("role") == "user" and ("Log Data:" in msg.get("content", "") or "Analyze these logs:" in msg.get("content", "")):
                    content = msg.get("content", "")
                    if "Log Data:" in content:
                        new_content = content.split("Log Data:")[0] + f"Log Data:\n{chunk}"
                    else:
                        new_content = content.split("Analyze these logs:")[0] + f"Analyze these logs:\n{chunk}"
                    chunk_messages.append({"role": "user", "content": new_content})
                elif isinstance(msg, dict) and msg.get("role") == "system":
                    chunk_messages.append(msg)

            # Process chunk
            chunk_results = enhancer.enhanced_hunt(chunk_messages, model_name=model_name, max_lines=max_lines)
            if isinstance(chunk_results, dict) and 'findings' in chunk_results:
                current_findings = chunk_results['findings']
                all_results.extend(current_findings)
            elif isinstance(chunk_results, list):
                current_findings = chunk_results
                all_results.extend(current_findings)
            else:
                current_findings = []

            # Persist after each chunk to allow recovery on cancel
            try:
                with open("_partial_results.jsonl", "a", encoding="utf-8") as f:
                    f.write(json.dumps({"chunk": i+1, "findings": current_findings}, ensure_ascii=False) + "\n")
            except Exception:
                pass

            print(f"{Fore.LIGHTGREEN_EX}  ✓ Chunk {i+1} complete: {len(current_findings)} findings{Fore.RESET}")
        except KeyboardInterrupt:
            print(f"{Fore.YELLOW}Interrupted. Returning {len(all_results)} findings completed so far.{Fore.RESET}")
            return {"findings": all_results}
        except Exception as e:
            print(f"{Fore.YELLOW}Chunk {i+1} failed: {e}. Continuing...{Fore.RESET}")
            continue
    
    print(f"{Fore.LIGHTGREEN_EX}✓ All chunks processed: {len(all_results)} total findings{Fore.RESET}")
    
    return {"findings": all_results}

def hunt(openai_client, threat_hunt_system_message, threat_hunt_user_message, openai_model, severity_config=None, table_name=None, investigation_context=None):
    """
    Runs the threat hunting flow:
    1. Formats the logs into a string
    2. Selects appropriate system prompt from context
    3. Passes logs + role to model
    4. Parses and returns a raw array
    Handles rate-limit/token overage errors gracefully.
    
    NEW: Supports 'local-mix' for TRUE HYBRID MODEL (Qwen + GPT-OSS)
    """

    results = []
    
    messages = [
        threat_hunt_system_message,
        threat_hunt_user_message
    ]

    try:
        # NEW: Handle local-mix with TRUE HYBRID MODEL
        if openai_model == "local-mix":
            print(f"{Fore.LIGHTCYAN_EX}🔀 Using TRUE HYBRID MODEL (Qwen + GPT-OSS - Fully Offline){Fore.RESET}")
            
            # Import hybrid engine
            import HYBRID_ENGINE
            
            # Determine investigation mode from context
            investigation_mode = investigation_context.get('mode', 'threat_hunt') if investigation_context else 'threat_hunt'
            query_method = investigation_context.get('query_method', 'llm') if investigation_context else 'llm'
            
            # Initialize hybrid engine with dynamic configuration
            hybrid_engine = HYBRID_ENGINE.HybridEngine(
                investigation_mode=investigation_mode,
                severity_config=severity_config,
                query_method=query_method,
                openai_client=openai_client
            )
            
            # Run hybrid analysis
            results = hybrid_engine.analyze(
                messages=messages,
                table_name=table_name,
                context=investigation_context
            )
            
            # For CTF mode, extract CTF format from results
            if investigation_context and investigation_context.get('mode') == 'ctf':
                import RESPONSE_PARSER
                # Check if results already in CTF format or need extraction from findings
                if isinstance(results, dict) and "suggested_answer" in results:
                    # Already CTF format
                    return results
                elif isinstance(results, dict) and "findings" in results:
                    # Extract CTF data from findings format
                    findings = results.get("findings", [])
                    for finding in findings:
                        if isinstance(finding, dict) and "_ctf_analysis" in finding:
                            return finding["_ctf_analysis"]
                    # If no _ctf_analysis, try to parse from findings structure
                    return RESPONSE_PARSER.parse_response(json.dumps(results), "ctf")
            
            # Threat hunt mode - enrich findings
            try:
                import UTILITIES
                enriched, summary = UTILITIES.enrich_findings_with_entities_and_vectors(results.get("findings", []))
                results["findings"] = enriched
                results["entity_summary"] = summary
            except Exception:
                pass
            return results
        
        # Check if this is an Ollama model (local)
        if openai_model == "qwen":
            print(f"{Fore.LIGHTCYAN_EX}Using Ollama local model (qwen3:8b) with GUARDRAILS enforcement...{Fore.RESET}")
            # Use enhanced pipeline for Qwen models with severity config
            severity_mult = severity_config['pattern_multiplier'] if severity_config else 1.0
            max_lines = severity_config['max_log_lines'] if severity_config else 50
            
            # Check if chunking is needed
            should_chunk, input_tokens, threshold = _should_chunk_messages("qwen3:8b", messages)
            
            if should_chunk:
                print(f"{Fore.LIGHTCYAN_EX}Large dataset detected ({input_tokens:,} tokens) - Using chunked processing{Fore.RESET}")
                print(f"{Fore.LIGHTBLACK_EX}Model limit: {TIME_ESTIMATOR.get_model_context_limit('qwen3:8b'):,} | Threshold: {threshold:,}{Fore.RESET}")
            
            # Initialize enhancer with GUARDRAILS awareness and optional GPT refinement
            enhancer = QWEN_ENHANCER.QwenEnhancer(
                severity_multiplier=severity_mult,
                openai_client=openai_client,
                use_gpt_refinement=False,  # Can be enabled via config
                refinement_model="gpt-4o"
            )
            
            # Enable GUARDRAILS based on MODEL_SELECTOR config
            import MODEL_SELECTOR
            guardrails_config = MODEL_SELECTOR.get_offline_guardrails_config()
            enhancer.guardrails_enabled = guardrails_config["enabled"]
            
            if enhancer.guardrails_enabled:
                print(f"{Fore.LIGHTGREEN_EX}  ✓ GUARDRAILS enabled (defense-in-depth security){Fore.RESET}")
            
            if enhancer.use_gpt_refinement:
                print(f"{Fore.LIGHTYELLOW_EX}  ✓ GPT-4o refinement enabled (hybrid mode){Fore.RESET}")
            
            if should_chunk:
                # Use chunked processing
                chunk_size = int(TIME_ESTIMATOR.get_model_context_limit("qwen3:8b") * 0.8)
                results = _chunk_and_process_local_model(enhancer, messages, "qwen3:8b", max_lines, chunk_size)
            else:
                # Normal processing - pass investigation_context for CTF mode
                results = enhancer.enhanced_hunt(messages, model_name="qwen3:8b", max_lines=max_lines, investigation_context=investigation_context)
            
            # For CTF mode, extract CTF format from results (enhancers return CTF format directly for CTF mode)
            if investigation_context and investigation_context.get('mode') == 'ctf':
                # QwenEnhancer returns CTF format directly when is_ctf_mode=True (see QWEN_ENHANCER.py line 1236-1240)
                if isinstance(results, dict) and "suggested_answer" in results:
                    return results  # Already CTF format
                # If still in findings format, extract CTF data
                elif isinstance(results, dict) and "findings" in results:
                    findings = results.get("findings", [])
                    for finding in findings:
                        if isinstance(finding, dict) and "_ctf_analysis" in finding:
                            return finding["_ctf_analysis"]
            
            # Threat hunt mode - enrich findings
            try:
                import UTILITIES
                enriched, summary = UTILITIES.enrich_findings_with_entities_and_vectors(results.get("findings", []))
                results["findings"] = enriched
                results["entity_summary"] = summary
            except Exception:
                pass
            return results
            
        elif openai_model == "gpt-oss:20b":
            print(f"{Fore.LIGHTCYAN_EX}Using Ollama local model (GPT-OSS 20B) with GUARDRAILS enforcement...{Fore.RESET}")
            # Use specialized GPT-OSS enhancer optimized for 32K token limit
            severity_mult = severity_config['pattern_multiplier'] if severity_config else 1.0
            max_lines = severity_config['max_log_lines'] if severity_config else 15  # GPT-OSS has 32K context but needs aggressive slicing
            
            # Check if chunking is needed
            should_chunk, input_tokens, threshold = _should_chunk_messages("gpt-oss:20b", messages)
            
            if should_chunk:
                print(f"{Fore.LIGHTCYAN_EX}Large dataset detected ({input_tokens:,} tokens) - Using chunked processing{Fore.RESET}")
                print(f"{Fore.LIGHTBLACK_EX}Model limit: {TIME_ESTIMATOR.get_model_context_limit('gpt-oss:20b'):,} | Threshold: {threshold:,}{Fore.RESET}")
            
            # Initialize enhancer with GUARDRAILS awareness and optional GPT refinement
            enhancer = GPT_OSS_ENHANCER.GptOssEnhancer(
                severity_multiplier=severity_mult,
                openai_client=openai_client,
                use_gpt_refinement=False,  # Can be enabled via config
                refinement_model="gpt-4o"
            )
            
            # Enable GUARDRAILS based on MODEL_SELECTOR config
            import MODEL_SELECTOR
            guardrails_config = MODEL_SELECTOR.get_offline_guardrails_config()
            enhancer.guardrails_enabled = guardrails_config["enabled"]
            
            if enhancer.guardrails_enabled:
                print(f"{Fore.LIGHTGREEN_EX}  ✓ GUARDRAILS enabled (defense-in-depth security){Fore.RESET}")
            
            if enhancer.use_gpt_refinement:
                print(f"{Fore.LIGHTYELLOW_EX}  ✓ GPT-4o refinement enabled (hybrid mode){Fore.RESET}")
            
            if should_chunk:
                # Use chunked processing
                chunk_size = int(TIME_ESTIMATOR.get_model_context_limit("gpt-oss:20b") * 0.8)
                results = _chunk_and_process_local_model(enhancer, messages, "gpt-oss:20b", max_lines, chunk_size)
            else:
                # Normal processing - pass investigation_context for CTF mode
                results = enhancer.enhanced_hunt(messages, model_name="gpt-oss:20b", max_lines=max_lines, investigation_context=investigation_context)
            
            # For CTF mode, extract CTF format from results (enhancers return CTF format directly for CTF mode)
            if investigation_context and investigation_context.get('mode') == 'ctf':
                # GptOssEnhancer returns CTF format directly when is_ctf_mode=True (see GPT_OSS_ENHANCER.py line 786-790)
                if isinstance(results, dict) and "suggested_answer" in results:
                    return results  # Already CTF format
                # If still in findings format, extract CTF data
                elif isinstance(results, dict) and "findings" in results:
                    findings = results.get("findings", [])
                    for finding in findings:
                        if isinstance(finding, dict) and "_ctf_analysis" in finding:
                            return finding["_ctf_analysis"]
            
            # Threat hunt mode - enrich findings
            try:
                import UTILITIES
                enriched, summary = UTILITIES.enrich_findings_with_entities_and_vectors(results.get("findings", []))
                results["findings"] = enriched
                results["entity_summary"] = summary
            except Exception:
                pass
            return results
        else:
            # Use OpenAI API
            print(f"{Fore.LIGHTCYAN_EX}Using OpenAI API model: {openai_model}...{Fore.RESET}")
            response = openai_client.chat.completions.create(
                model=openai_model,
                messages=messages,
                response_format={"type": "json_object"}
            )

            results = json.loads(response.choices[0].message.content)
            
            # Format-aware routing: Parse CTF format if mode is 'ctf'
            if investigation_context and investigation_context.get('mode') == 'ctf':
                import RESPONSE_PARSER
                results = RESPONSE_PARSER.parse_response(response.choices[0].message.content, "ctf")
            
            return results

    except RateLimitError as e:
        error_msg = str(e)

        # Print dark red warning
        print(f"{Fore.LIGHTRED_EX}{Style.BRIGHT}🚨ERROR: Rate limit or token overage detected!{Style.RESET_ALL}")
        print(f"{Fore.LIGHTRED_EX}{Style.BRIGHT}The input was too large for this model or hit rate limits.")
        print(f"{Style.RESET_ALL}——————————\nRaw Error:\n{error_msg}\n——————————")
        print(f"{Fore.WHITE}Suggestions:")
        print(f"- Use fewer logs or reduce input size.")
        print(f"- Switch to a model with a larger context window.")
        print(f"- Retry later if rate-limited.\n")

        return None  # You can also choose to raise again or exit

    except OpenAIError as e:
        print(f"{Fore.RED}Unexpected OpenAI API error:\n{e}")
        return None

# Extract and parse the function call selected by the LLM.
# This tool call is part of OpenAI's function calling feature, where the model chooses a tool (function)
# from the provided list, and returns the arguments it wants to use to call it.
# In this case, the function selected queries log data from Microsoft Defender via Log Analytics.
#
# Docs: https://platform.openai.com/docs/guides/function-calling
def get_query_context(openai_client, user_message, model):
    
    print(f"{Fore.LIGHTGREEN_EX}\nDeciding log search parameters based on user request...\n")

    system_message = PROMPT_MANAGEMENT.SYSTEM_PROMPT_TOOL_SELECTION

    # Handle local-mix model - convert to actual model for query planning
    if model == "local-mix":
        # For query planning, we still need OpenAI function calling
        # So route to gpt-4o-mini (cheap and fast)
        print(f"{Fore.YELLOW}Note: Using gpt-4o-mini for query planning (local-mix uses hybrid model for analysis){Fore.RESET}")
        query_model = "gpt-4o-mini"
    # If Ollama model selected, use a capable OpenAI model for tool selection
    # (Ollama doesn't support function calling well)
    elif model in {"qwen", "gpt-oss:20b"}:
        print(f"{Fore.YELLOW}Note: Using gpt-4o-mini for query planning (Local models don't support function calling){Fore.RESET}")
        query_model = "gpt-4o-mini"
    else:
        query_model = model

    response = openai_client.chat.completions.create(
        model=query_model,
        messages=[system_message, user_message],
        tools=PROMPT_MANAGEMENT.TOOLS,
        tool_choice="required"
    )

    #TODO: Fix this (if there are no returns)
    function_call = response.choices[0].message.tool_calls[0]
    args = json.loads(function_call.function.arguments)

    return args  # or return function_call, args


def detect_time_field(log_analytics_client, workspace_id, table_name):
    """
    Auto-detect the correct time field name for a given table.
    Returns the time field name (e.g., 'TimeGenerated', 'Timestamp', etc.)
    """
    try:
        # Query one row to get schema
        schema_query = f"{table_name} | take 1"
        schema_response = log_analytics_client.query_workspace(
            workspace_id=workspace_id,
            query=schema_query,
            timespan=timedelta(days=90)  # Look back 90 days to find any data
        )
        
        if not schema_response.tables or len(schema_response.tables) == 0:
            print(f"{Fore.YELLOW}Warning: Could not detect schema. Defaulting to 'TimeGenerated'{Fore.RESET}")
            return 'TimeGenerated'
        
        columns = schema_response.tables[0].columns
        
        # Check for common time field names (in order of preference)
        time_field_candidates = ['TimeGenerated', 'Timestamp', 'EventTime', 'Time', 'DateTime']
        
        for candidate in time_field_candidates:
            for col in columns:
                if col == candidate:
                    return col
        
        # If no exact match, look for any column with 'time' in the name
        for col in columns:
            if 'time' in col.lower():
                print(f"{Fore.YELLOW}Using non-standard time field: {col}{Fore.RESET}")
                return col
        
        # Last resort: default to TimeGenerated
        print(f"{Fore.YELLOW}Warning: No time field detected. Defaulting to 'TimeGenerated'{Fore.RESET}")
        return 'TimeGenerated'
        
    except Exception as e:
        print(f"{Fore.YELLOW}Warning: Time field detection failed ({e}). Defaulting to 'TimeGenerated'{Fore.RESET}")
        return 'TimeGenerated'


def query_log_analytics(log_analytics_client, workspace_id, timerange_hours, table_name, device_name, fields, caller, user_principal_name, start_date=None, end_date=None):
    
    # Calculate time range for KQL query
    from datetime import datetime, timezone
    
    # Use provided dates if available, otherwise calculate from hours
    if start_date and end_date:
        start_time = start_date
        end_time = end_date
    else:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=timerange_hours)
    
    # Format for KQL
    start_time_str = start_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    end_time_str = end_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    
    # AUTO-DETECT the correct time field name for this table
    # Different tables may use 'TimeGenerated', 'Timestamp', or other field names
    print(f"{Fore.LIGHTBLACK_EX}Detecting time field for table '{table_name}'...{Fore.RESET}")
    time_field = detect_time_field(log_analytics_client, workspace_id, table_name)
    
    # Build time range clause with correct field name
    time_filter = f"| where {time_field} between (datetime({start_time_str}) .. datetime({end_time_str}))"
    
    print(f"{Fore.LIGHTGREEN_EX}✓ Time field: {time_field}{Fore.RESET}")

    if table_name == "AzureNetworkAnalytics_CL":
        user_query = f'''{table_name}
{time_filter}
| where FlowType_s == "MaliciousFlow"
| project {fields}'''
        
    elif table_name == "AzureActivity":
        user_query = f'''{table_name}
{time_filter}
| where isnotempty(Caller) and Caller !in ("d37a587a-4ef3-464f-a288-445e60ed248c","ef669d55-9245-4118-8ba7-f78e3e7d0212","3e4fe3d2-24ff-4972-92b3-35518d6e6462")
| where Caller contains "{caller}"
| project {fields}'''
        
    elif table_name == "SigninLogs":
        user_query = f'''{table_name}
{time_filter}
| where UserPrincipalName contains "{user_principal_name}"
| project {fields}'''
        
    else:
        # Build dynamic where clause based on what's provided
        where_clauses = []
        
        if device_name:
            where_clauses.append(f'DeviceName contains "{device_name}"')
        
        # Map user_principal_name to correct field based on table (only if table has user/account field)
        if user_principal_name:
            # Tables with AccountName field
            if table_name in ["DeviceLogonEvents", "DeviceProcessEvents"]:
                where_clauses.append(f'AccountName contains "{user_principal_name}"')
            # DeviceFileEvents uses InitiatingProcessAccountName instead
            elif table_name == "DeviceFileEvents":
                where_clauses.append(f'InitiatingProcessAccountName contains "{user_principal_name}"')
            # Note: DeviceNetworkEvents and DeviceRegistryEvents don't have user/account fields
            # If user specified account for those tables, we skip the filter (query will return all for device)
        
        # Combine clauses
        if where_clauses:
            where_statement = "| where " + " and ".join(where_clauses)
        else:
            where_statement = ""
        
        user_query = f'''{table_name}
{time_filter}
{where_statement}
| project {fields}'''
        
    print(f"{Fore.LIGHTGREEN_EX}{'='*70}")
    print(f"{Fore.LIGHTGREEN_EX}CONSTRUCTED KQL QUERY")
    print(f"{Fore.LIGHTGREEN_EX}{'='*70}")
    print(f"{Fore.LIGHTYELLOW_EX}{user_query}")
    print(f"{Fore.LIGHTGREEN_EX}{'='*70}\n")

    print(f"{Fore.LIGHTGREEN_EX}Querying Log Analytics Workspace ID: '{workspace_id}'...")
    
    # Azure SDK requires timespan parameter (even if we have dates in WHERE clause)
    # Use the calculated time difference for the timespan
    if start_date and end_date:
        time_diff = end_time - start_time
        print(f"{Fore.LIGHTBLACK_EX}Using explicit date range: {start_time.strftime('%Y-%m-%d')} to {end_time.strftime('%Y-%m-%d')}{Fore.RESET}")
    else:
        time_diff = timedelta(hours=timerange_hours)
    
    print(f"{Fore.LIGHTBLACK_EX}Timespan parameter: {time_diff}{Fore.RESET}")
    print(f"{Fore.LIGHTCYAN_EX}Executing query...{Fore.RESET}\n")
    
    response = log_analytics_client.query_workspace(
        workspace_id=workspace_id,
        query=user_query,
        timespan=time_diff  # Required parameter
    )

    # Handle partial results or errors
    if hasattr(response, 'partial_error') and response.partial_error:
        print(f"{Fore.YELLOW}Warning: Query returned partial results due to timeout or limits.")
        print(f"{Fore.WHITE}Partial error: {response.partial_error}")
    
    # Check if we have tables (LogsQueryResult) or partial results
    if not hasattr(response, 'tables'):
        print(f"{Fore.RED}Error: Query did not return expected table structure.")
        print(f"{Fore.WHITE}Response type: {type(response)}")
        return { "records": "", "count": 0 }
    
    if len(response.tables) == 0 or len(response.tables[0].rows) == 0:
        print(f"{Fore.WHITE}No data returned from Log Analytics.")
        
        # Diagnostic: Try to determine if field name is the issue
        print(f"\n{Fore.YELLOW}🔍 DIAGNOSTIC: Testing if data exists with different field names...{Fore.RESET}")
        
        # Try a simple count query without time filter to see if table has data
        test_query = f"{table_name} | take 1"
        try:
            test_response = log_analytics_client.query_workspace(
                workspace_id=workspace_id,
                query=test_query,
                timespan=timedelta(days=30)  # Look back 30 days for diagnostic
            )
            if test_response.tables and len(test_response.tables[0].rows) > 0:
                print(f"{Fore.LIGHTGREEN_EX}✓ Table '{table_name}' exists and has data in Log Analytics{Fore.RESET}")
                
                # Show available columns and identify time field
                columns = test_response.tables[0].columns
                print(f"\n{Fore.LIGHTCYAN_EX}Available columns in {table_name}:{Fore.RESET}")
                
                # Identify time field
                time_field_found = None
                for col in columns:
                    if col.lower() in ['timestamp', 'timegenerated', 'time', 'datetime']:
                        time_field_found = col
                        print(f"{Fore.LIGHTGREEN_EX}  • {col} ← TIME FIELD{Fore.RESET}")
                    else:
                        print(f"{Fore.WHITE}  • {col}")
                
                if not time_field_found:
                    print(f"\n{Fore.RED}⚠️  WARNING: No standard time field found!{Fore.RESET}")
                    print(f"{Fore.YELLOW}Expected: 'Timestamp' or 'TimeGenerated'{Fore.RESET}")
                else:
                    print(f"\n{Fore.LIGHTGREEN_EX}Time field in table: {time_field_found}{Fore.RESET}")
                    print(f"{Fore.LIGHTBLACK_EX}Your query uses: {time_field}{Fore.RESET}")
                    if time_field_found != time_field:
                        print(f"{Fore.RED}❌ MISMATCH! This is why the query returns no data!{Fore.RESET}")
                        print(f"{Fore.LIGHTYELLOW_EX}Fix: Update GUARDRAILS.py to use '{time_field_found}' for this table{Fore.RESET}")
                
                # Show sample data from the table - FOCUS ON TIMESTAMPS
                print(f"\n{Fore.LIGHTCYAN_EX}Sample timestamps in {table_name}:{Fore.RESET}")
                if test_response.tables[0].rows:
                    # Get index of time fields - USE THE SAME FIELD AS THE QUERY
                    time_field_idx = None
                    time_field_name = None
                    
                    # First, try to find the EXACT field we're using in the query
                    for i, col in enumerate(columns):
                        if col == time_field:
                            time_field_idx = i
                            time_field_name = col
                            break
                    
                    # If not found (shouldn't happen), fall back to any time field
                    if time_field_idx is None:
                        for i, col in enumerate(columns):
                            if col.lower() in ['timestamp', 'timegenerated', 'time', 'datetime', 'eventtime']:
                                time_field_idx = i
                                time_field_name = col
                                break
                    
                    # Show first 3 rows with their timestamps
                    if time_field_idx is not None:
                        print(f"{Fore.LIGHTGREEN_EX}  Time field detected: {time_field_name}{Fore.RESET}")
                        for row_num, row in enumerate(test_response.tables[0].rows[:3], 1):
                            print(f"{Fore.WHITE}  Row {row_num}: {Fore.LIGHTYELLOW_EX}{row[time_field_idx]}")
                    
                    print(f"\n{Fore.LIGHTCYAN_EX}Your query date range:{Fore.RESET}")
                    print(f"{Fore.WHITE}  From: {Fore.LIGHTYELLOW_EX}{start_time.strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"{Fore.WHITE}  To:   {Fore.LIGHTYELLOW_EX}{end_time.strftime('%Y-%m-%d %H:%M:%S')}")
                    
                    # Check if data is outside range
                    if time_field_idx is not None and len(test_response.tables[0].rows) > 0:
                        from datetime import datetime
                        try:
                            sample_time = test_response.tables[0].rows[0][time_field_idx]
                            if isinstance(sample_time, datetime):
                                if sample_time < start_time:
                                    print(f"\n{Fore.RED}⚠️  DATA IS OLDER THAN YOUR QUERY RANGE!{Fore.RESET}")
                                    print(f"{Fore.YELLOW}Try expanding your time range or using older dates{Fore.RESET}")
                                elif sample_time > end_time:
                                    print(f"\n{Fore.RED}⚠️  DATA IS NEWER THAN YOUR QUERY RANGE!{Fore.RESET}")
                                    print(f"{Fore.YELLOW}Try using more recent dates{Fore.RESET}")
                        except:
                            pass
                    
                    # Sample other fields too
                    print(f"\n{Fore.LIGHTCYAN_EX}Sample row data:{Fore.RESET}")
                    sample_row = test_response.tables[0].rows[0]
                    for i, col in enumerate(columns[:8]):
                        value = sample_row[i] if i < len(sample_row) else "N/A"
                        # Truncate long values
                        if isinstance(value, str) and len(str(value)) > 60:
                            value = str(value)[:60] + "..."
                        print(f"{Fore.LIGHTBLACK_EX}  {col}: {Fore.WHITE}{value}")
                
                # Progressive testing to isolate the issue
                print(f"\n{Fore.LIGHTCYAN_EX}Testing query components...{Fore.RESET}")
                
                # Test 1: Just table (no filters)
                test1_query = f"{table_name} | take 5"
                try:
                    test1 = log_analytics_client.query_workspace(workspace_id=workspace_id, query=test1_query, timespan=timedelta(days=30))
                    count1 = len(test1.tables[0].rows) if test1.tables else 0
                    print(f"{Fore.WHITE}  [1] Table only: {Fore.LIGHTGREEN_EX}{count1} records found{Fore.RESET}")
                except Exception as e:
                    print(f"{Fore.RED}  [1] Table test failed: {e}{Fore.RESET}")
                
                # Test 2: With time filter only
                # Build time filter without "| where" prefix for testing
                time_only_query = f"{table_name} {time_filter} | take 5"
                try:
                    test2 = log_analytics_client.query_workspace(workspace_id=workspace_id, query=time_only_query, timespan=time_diff if 'time_diff' in locals() else timedelta(days=30))
                    count2 = len(test2.tables[0].rows) if test2.tables else 0
                    if count2 > 0:
                        print(f"{Fore.WHITE}  [2] With time filter: {Fore.LIGHTGREEN_EX}{count2} records found{Fore.RESET}")
                        
                        # Show the actual timestamp from data
                        sample = test2.tables[0].rows[0]
                        time_col_idx = None
                        for idx, col in enumerate(test2.tables[0].columns):
                            if col.lower() in ['timestamp', 'timegenerated']:
                                time_col_idx = idx
                                actual_time_field = col
                                break
                        if time_col_idx is not None:
                            print(f"{Fore.LIGHTBLACK_EX}    Actual time field: {Fore.LIGHTYELLOW_EX}{actual_time_field}{Fore.RESET}")
                            print(f"{Fore.LIGHTBLACK_EX}    Sample timestamp: {Fore.WHITE}{sample[time_col_idx]}{Fore.RESET}")
                    else:
                        print(f"{Fore.YELLOW}  [2] With time filter: {Fore.RED}0 records{Fore.RESET}")
                        print(f"{Fore.YELLOW}      → Wrong time field or no data in range{Fore.RESET}")
                except Exception as e:
                    print(f"{Fore.RED}  [2] Time filter test failed: {e}{Fore.RESET}")
                
                # Test 3: With your full query
                print(f"{Fore.WHITE}  [3] With all filters: {Fore.RED}0 records (your query){Fore.RESET}")
                if device_name or user_principal_name:
                    print(f"{Fore.YELLOW}      → Filters might be too restrictive or wrong field names{Fore.RESET}")
                
                print()
            else:
                print(f"{Fore.RED}✗ Table '{table_name}' does NOT exist in this Log Analytics workspace{Fore.RESET}")
                print(f"\n{Fore.YELLOW}{'='*70}")
                print(f"{Fore.YELLOW}IMPORTANT: MDE vs Log Analytics Difference")
                print(f"{Fore.YELLOW}{'='*70}{Fore.RESET}")
                print(f"{Fore.WHITE}You mentioned you can see data in MDE. Note that:{Fore.RESET}")
                print(f"{Fore.WHITE}• MDE Advanced Hunting portal = Direct MDE data source")
                print(f"{Fore.WHITE}• This agent = Queries Azure Log Analytics workspace")
                print(f"\n{Fore.LIGHTYELLOW_EX}These are DIFFERENT data sources!{Fore.RESET}")
                print(f"\n{Fore.WHITE}To use this agent, you need to:{Fore.RESET}")
                print(f"{Fore.WHITE}1. Configure MDE to send data to Log Analytics")
                print(f"{Fore.WHITE}2. Or check if you're using the correct workspace ID")
                print(f"{Fore.WHITE}3. Or verify the table exists in your Log Analytics{Fore.RESET}")
                print(f"\n{Fore.LIGHTCYAN_EX}Check: Azure Portal → Log Analytics Workspace → Tables{Fore.RESET}")
                print(f"{Fore.YELLOW}{'='*70}\n{Fore.RESET}")
        except Exception as e:
            print(f"{Fore.RED}Could not run diagnostic query: {e}{Fore.RESET}\n")
        
        return { "records": "", "count": 0 }
    
    # Extract the table
    table = response.tables[0]
    record_count = len(response.tables[0].rows)

    # Extract columns and rows using dot notation
    columns = table.columns  # Already a list of strings
    rows = table.rows        # List of row data

    df = pd.DataFrame(rows, columns=columns)
    records = df.to_csv(index=False)

    return { "records": records, "count": record_count }

