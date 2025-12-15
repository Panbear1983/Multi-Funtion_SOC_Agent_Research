from color_support import Fore, Style

# TODO: Provide allowed fields later
ALLOWED_TABLES = {
    # All tables in Log Analytics use 'TimeGenerated' field
    "DeviceProcessEvents": { "TimeGenerated", "AccountName", "ActionType", "DeviceName", "InitiatingProcessCommandLine", "ProcessCommandLine" },
    "DeviceNetworkEvents": { "TimeGenerated", "ActionType", "InitiatingProcessCommandLine", "DeviceName", "RemoteIP", "RemotePort" },
    "DeviceLogonEvents": { "TimeGenerated", "AccountName", "DeviceName", "ActionType", "RemoteIP", "RemoteDeviceName" },
    "DeviceFileEvents": {"TimeGenerated","ActionType","DeviceName","FileName","FolderPath","InitiatingProcessAccountName","SHA256"},
    "DeviceRegistryEvents": { "TimeGenerated","ActionType","DeviceName","RegistryKey","InitiatingProcessAccountName" },
    "AlertInfo": {},  # No fields specified in tools
    "AlertEvidence": {},  # No fields specified in tools
    "AzureNetworkAnalytics_CL": { "TimeGenerated", "FlowType_s", "SrcPublicIPs_s", "DestIP_s", "DestPort_d", "VM_s", "AllowedInFlows_d", "AllowedOutFlows_d", "DeniedInFlows_d", "DeniedOutFlows_d" },
    "AzureActivity": {"TimeGenerated", "OperationNameValue", "ActivityStatusValue", "ResourceGroup", "Caller", "CallerIpAddress", "Category" },
    "SigninLogs": {"TimeGenerated", "UserPrincipalName", "OperationName", "Category", "ResultSignature", "ResultDescription", "AppDisplayName", "IPAddress", "LocationDetails" },
    "AuditLogs": {"TimeGenerated", "OperationName", "ResultDescription", "ResultType", "Category", "InitiatedBy", "TargetResources", "CorrelationId", "AADTenantId"},
    "AzureNetworkAnalyticsIPDetails_CL": {"TimeGenerated", "IPAddress_s", "ThreatType_s", "ThreatCategory_s", "ASN_s", "Country_s", "Region_s"},
}

# Token optimization: Model-aware field prioritization
# GPT-OSS (32K limit): Essential fields only for token efficiency
# Qwen (128K limit): All allowed fields (full context)
OPTIMAL_FIELDS_BY_MODEL = {
    "gpt-oss:20b": {
        # GPT-OSS: Essential fields only (token-efficient)
        "DeviceProcessEvents": {"TimeGenerated", "AccountName", "DeviceName", "ProcessCommandLine"},
        "DeviceNetworkEvents": {"TimeGenerated", "DeviceName", "RemoteIP"},
        "DeviceLogonEvents": {"TimeGenerated", "AccountName", "RemoteIP"},
        "DeviceFileEvents": {"TimeGenerated", "DeviceName", "FileName", "SHA256"},
        "DeviceRegistryEvents": {"TimeGenerated", "DeviceName", "RegistryKey"},
        "AzureNetworkAnalytics_CL": {"TimeGenerated", "FlowType_s", "SrcPublicIPs_s", "DestIP_s", "VM_s"},
        "AzureActivity": {"TimeGenerated", "OperationNameValue", "Caller", "CallerIpAddress"},
        "SigninLogs": {"TimeGenerated", "UserPrincipalName", "IPAddress"},
        "AuditLogs": {"TimeGenerated", "OperationName", "InitiatedBy"},
        "AzureNetworkAnalyticsIPDetails_CL": {"TimeGenerated", "IPAddress_s", "ThreatType_s"},
    },
    "qwen": {
        # Qwen: All allowed fields (128K headroom)
        "DeviceProcessEvents": ALLOWED_TABLES["DeviceProcessEvents"],
        "DeviceNetworkEvents": ALLOWED_TABLES["DeviceNetworkEvents"],
        "DeviceLogonEvents": ALLOWED_TABLES["DeviceLogonEvents"],
        "DeviceFileEvents": ALLOWED_TABLES["DeviceFileEvents"],
        "DeviceRegistryEvents": ALLOWED_TABLES["DeviceRegistryEvents"],
        "AzureNetworkAnalytics_CL": ALLOWED_TABLES["AzureNetworkAnalytics_CL"],
        "AzureActivity": ALLOWED_TABLES["AzureActivity"],
        "SigninLogs": ALLOWED_TABLES["SigninLogs"],
        "AuditLogs": ALLOWED_TABLES["AuditLogs"],
        "AzureNetworkAnalyticsIPDetails_CL": ALLOWED_TABLES["AzureNetworkAnalyticsIPDetails_CL"],
    },
    "qwen3:8b": {
        # Qwen3:8b uses same as qwen
        "DeviceProcessEvents": ALLOWED_TABLES["DeviceProcessEvents"],
        "DeviceNetworkEvents": ALLOWED_TABLES["DeviceNetworkEvents"],
        "DeviceLogonEvents": ALLOWED_TABLES["DeviceLogonEvents"],
        "DeviceFileEvents": ALLOWED_TABLES["DeviceFileEvents"],
        "DeviceRegistryEvents": ALLOWED_TABLES["DeviceRegistryEvents"],
        "AzureNetworkAnalytics_CL": ALLOWED_TABLES["AzureNetworkAnalytics_CL"],
        "AzureActivity": ALLOWED_TABLES["AzureActivity"],
        "SigninLogs": ALLOWED_TABLES["SigninLogs"],
        "AuditLogs": ALLOWED_TABLES["AuditLogs"],
        "AzureNetworkAnalyticsIPDetails_CL": ALLOWED_TABLES["AzureNetworkAnalyticsIPDetails_CL"],
    }
}

def get_optimal_fields_for_model(table, model_name):
    """
    Get optimal field set for model (token-aware)
    Falls back to ALLOWED_TABLES if model-specific not defined
    
    Args:
        table: Table name
        model_name: Model name (e.g., "gpt-oss:20b", "qwen")
    
    Returns:
        Set of optimal fields for the model
    """
    model_fields = OPTIMAL_FIELDS_BY_MODEL.get(model_name, {}).get(table)
    if model_fields:
        return model_fields
    
    # Fallback: Use all allowed fields
    return ALLOWED_TABLES.get(table, set())

ALLOWED_MODELS = {
    "gpt-4.1-nano": {"max_input_tokens": 1_047_576, "max_output_tokens": 32_768,  "cost_per_million_input": 0.10, "cost_per_million_output": 0.40,  "tier": {"free": 40_000, "1": 200_000, "2": 2_000_000, "3": 4_000_000, "4": 10_000_000, "5": 150_000_000}},
    "gpt-4.1":      {"max_input_tokens": 1_047_576, "max_output_tokens": 32_768,  "cost_per_million_input": 1.00, "cost_per_million_output": 8.00,  "tier": {"free": None,   "1": 30_000,  "2": 450_000,   "3": 800_000,   "4": 2_000_000,  "5": 30_000_000}},
    "gpt-5-mini":   {"max_input_tokens": 272_000,   "max_output_tokens": 128_000, "cost_per_million_input": 0.25, "cost_per_million_output": 2.00,  "tier": {"free": None,   "1": 200_000, "2": 2_000_000, "3": 4_000_000, "4": 10_000_000, "5": 180_000_000}},
    "gpt-5":        {"max_input_tokens": 272_000,   "max_output_tokens": 128_000, "cost_per_million_input": 1.25, "cost_per_million_output": 10.00, "tier": {"free": None,   "1": 30_000,  "2": 450_000,   "3": 800_000,   "4": 2_000_000,  "5": 40_000_000}},
    "local-mix":    {"max_input_tokens": 128_000,   "max_output_tokens": 32_768,  "cost_per_million_input": 0.00, "cost_per_million_output": 0.00, "tier": {"free": None,   "1": None,    "2": None,      "3": None,      "4": None,       "5": None}},
    "qwen":         {"max_input_tokens": 128_000,   "max_output_tokens": 32_768,  "cost_per_million_input": 0.00, "cost_per_million_output": 0.00, "tier": {"free": None,   "1": None,    "2": None,      "3": None,      "4": None,       "5": None}},
    "gpt-oss:20b":  {"max_input_tokens": 32_000,    "max_output_tokens": 4_096,   "cost_per_million_input": 0.00, "cost_per_million_output": 0.00, "tier": {"free": None,   "1": None,    "2": None,      "3": None,      "4": None,       "5": None}}
}

def validate_tables_and_fields(table, fields, model_name=None):

    print(f"{Fore.LIGHTGREEN_EX}Validating Tables and Fields...")
    print(f"{Fore.LIGHTBLACK_EX}[DEBUG] Table: {table}{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}[DEBUG] Fields requested: {fields}{Fore.RESET}")
    print(f"{Fore.LIGHTBLACK_EX}[DEBUG] Allowed fields for this table: {ALLOWED_TABLES.get(table, 'TABLE NOT FOUND')}{Fore.RESET}")
    
    # If model specified, show optimal fields
    if model_name:
        optimal_fields = get_optimal_fields_for_model(table, model_name)
        if optimal_fields != ALLOWED_TABLES.get(table, set()):
            print(f"{Fore.LIGHTBLACK_EX}[DEBUG] Optimal fields for {model_name}: {sorted(optimal_fields)}{Fore.RESET}")
    
    if table not in ALLOWED_TABLES:
        print(f"{Fore.RED}{Style.BRIGHT}ERROR:{Style.RESET_ALL} "f"Table '{table}' is not in allowed list.")
        raise ValueError(f"Disallowed table: {table}")
    
    # Normalize fields to a list
    if isinstance(fields, str):
        fields = fields.replace(' ', '').split(',') if fields else []
    elif isinstance(fields, (list, tuple, set)):
        fields = list(fields)
    else:
        raise TypeError("fields must be a string or a sequence of field names")

    for field in fields:
        if ALLOWED_TABLES[table] and (field not in ALLOWED_TABLES[table]):
            print(f"\n{Fore.RED}{Style.BRIGHT}=" * 70)
            print(f"ERROR: FIELD VALIDATION FAILED")
            print(f"=" * 70)
            print(f"{Style.RESET_ALL}")
            print(f"{Fore.RED}Field '{field}' is NOT ALLOWED for Table '{table}'{Fore.RESET}")
            print(f"\n{Fore.YELLOW}Available fields for {table}:{Fore.RESET}")
            for allowed_field in sorted(ALLOWED_TABLES[table]):
                print(f"  ✓ {allowed_field}")
            raise ValueError(f"Disallowed field '{field}' for table '{table}'")
    
    print(f"{Fore.WHITE}Fields and tables have been validated and comply with the allowed guidelines.\n")

def validate_model(model):
    if model not in ALLOWED_MODELS:
        print(f"{Fore.RED}{Style.BRIGHT}ERROR:{Style.RESET_ALL} Model '{model}' is not allowed — {Fore.RED}{Style.BRIGHT}exiting.{Style.RESET_ALL}")
        raise SystemExit(1)
    else:
        print(f"{Fore.LIGHTGREEN_EX}Selected model is valid: {Fore.CYAN}{model}\n{Style.RESET_ALL}")


