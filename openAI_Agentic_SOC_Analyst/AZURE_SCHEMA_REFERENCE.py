"""
Azure Log Analytics Table Schema Reference
Complete field definitions with types, descriptions, and common values
"""

# Comprehensive schema for Azure tables
AZURE_TABLE_SCHEMAS = {
    "DeviceLogonEvents": {
        "description": "Logon events on Windows devices",
        "fields": {
            "TimeGenerated": {
                "type": "datetime",
                "description": "Timestamp when event was generated",
                "required": True,
                "example": "datetime(2025-09-14T03:45:12Z)"
            },
            "DeviceName": {
                "type": "string",
                "description": "Name of the device/computer",
                "required": True,
                "example": "flare-vm-01"
            },
            "AccountName": {
                "type": "string", 
                "description": "Username of the account",
                "required": True,
                "example": "slflare"
            },
            "ActionType": {
                "type": "string",
                "description": "Type of logon action",
                "required": True,
                "allowed_values": ["LogonSuccess", "LogonFailed"],
                "example": "LogonSuccess"
            },
            "RemoteIP": {
                "type": "string",
                "description": "Source IP address of the logon attempt",
                "required": False,
                "example": "159.26.106.84"
            },
            "RemoteDeviceName": {
                "type": "string",
                "description": "Name of the remote device",
                "required": False,
                "example": "attacker-machine"
            }
        },
        "common_queries": [
            "Filter by ActionType: | where ActionType == \"LogonSuccess\"",
            "Filter by device: | where DeviceName contains \"hostname\"",
            "Filter by IP: | where RemoteIP == \"x.x.x.x\"",
            "Time range: | where TimeGenerated between (datetime(...) .. datetime(...))"
        ]
    },
    
    "DeviceEvents": {
        "description": "Miscellaneous MDE device events (named pipes, scheduled tasks, LSASS access, PowerShell commands, AMSI, etc.)",
        "fields": {
            "TimeGenerated": {"type": "datetime", "description": "Timestamp when event was generated", "required": True, "example": "datetime(2026-03-15T10:00:00Z)"},
            "DeviceName": {"type": "string", "description": "Name of the device/computer", "required": True, "example": "azuki-adminpc"},
            "ActionType": {"type": "string", "description": "Event type, e.g. NamedPipeEvent, ScheduledTaskCreated, PowerShellCommand, LdapSearch", "required": True, "example": "NamedPipeEvent"},
            "FileName": {"type": "string", "description": "File involved in the event (if any)", "required": False, "example": "beacon.exe"},
            "FolderPath": {"type": "string", "description": "Folder of the file involved", "required": False, "example": "C:\\Windows\\Temp"},
            "AccountName": {"type": "string", "description": "Account that triggered the event", "required": False, "example": "svc_admin"},
            "InitiatingProcessCommandLine": {"type": "string", "description": "Command line of the process that caused the event", "required": False, "example": "beacon.exe"},
            "InitiatingProcessFileName": {"type": "string", "description": "Process that caused the event", "required": False, "example": "powershell.exe"},
            "AdditionalFields": {"type": "dynamic (JSON)", "description": "Event-specific JSON, e.g. {\"PipeName\":\"\\\\.\\pipe\\...\"} for NamedPipeEvent - parse with parse_json() / tostring(AdditionalFields.PipeName)", "required": False, "example": "{\"PipeName\":\"\\\\device\\namedpipe\\msagent_ab\"}"}
        },
        "common_queries": [
            "Named pipes: | where ActionType == \"NamedPipeEvent\" | extend PipeName = tostring(parse_json(AdditionalFields).PipeName)",
            "Filter by device: | where DeviceName contains \"hostname\"",
            "Time range: | where TimeGenerated between (datetime(...) .. datetime(...))"
        ]
    },

    "DeviceProcessEvents": {
        "description": "Process execution events on Windows devices",
        "fields": {
            "TimeGenerated": {
                "type": "datetime",
                "description": "Timestamp when event was generated",
                "required": True
            },
            "DeviceName": {
                "type": "string",
                "description": "Name of the device",
                "required": True
            },
            "AccountName": {
                "type": "string",
                "description": "User account that ran the process",
                "required": True
            },
            "ActionType": {
                "type": "string",
                "description": "Type of process action",
                "required": True,
                "allowed_values": ["ProcessCreated", "ProcessTerminated"]
            },
            "ProcessCommandLine": {
                "type": "string",
                "description": "Full command line of the process",
                "required": False,
                "example": "powershell.exe -enc ZwBlAHQA..."
            },
            "InitiatingProcessCommandLine": {
                "type": "string",
                "description": "Command line of parent process",
                "required": False
            }
        },
        "common_queries": [
            "Filter by process: | where ProcessCommandLine contains \"powershell\"",
            "Filter by action: | where ActionType == \"ProcessCreated\""
        ]
    },
    
    "DeviceNetworkEvents": {
        "description": "Network connection events",
        "fields": {
            "TimeGenerated": {
                "type": "datetime",
                "description": "Timestamp when event was generated",
                "required": True
            },
            "DeviceName": {
                "type": "string",
                "description": "Name of the device",
                "required": True
            },
            "ActionType": {
                "type": "string",
                "description": "Type of network action",
                "required": True,
                "allowed_values": ["ConnectionSuccess", "ConnectionFailed", "ConnectionRequest"]
            },
            "RemoteIP": {
                "type": "string",
                "description": "Destination IP address",
                "required": False
            },
            "RemotePort": {
                "type": "int",
                "description": "Destination port number",
                "required": False,
                "example": "443"
            }
        },
        "common_queries": [
            "Filter by IP: | where RemoteIP == \"x.x.x.x\"",
            "Filter by port: | where RemotePort == 443"
        ]
    },
    
    "DeviceFileEvents": {
        "description": "File operation events",
        "fields": {
            "TimeGenerated": {
                "type": "datetime",
                "description": "Timestamp when event was generated",
                "required": True
            },
            "DeviceName": {
                "type": "string",
                "description": "Name of the device",
                "required": True
            },
            "ActionType": {
                "type": "string",
                "description": "Type of file action",
                "required": True,
                "allowed_values": ["FileCreated", "FileModified", "FileDeleted", "FileRenamed"]
            },
            "FileName": {
                "type": "string",
                "description": "Name of the file",
                "required": False,
                "example": "malware.exe"
            },
            "FolderPath": {
                "type": "string",
                "description": "Full path to the file",
                "required": False,
                "example": "C:\\Users\\Admin\\Downloads\\malware.exe"
            },
            "InitiatingProcessAccountName": {
                "type": "string",
                "description": "Account that initiated the file operation",
                "required": False
            },
            "SHA256": {
                "type": "string",
                "description": "SHA256 hash of the file",
                "required": False,
                "example": "a3f2b1c4d5..."
            }
        },
        "common_queries": [
            "Filter by filename: | where FileName == \"file.exe\"",
            "Filter by path: | where FolderPath contains \"Downloads\""
        ]
    },
    
    "DeviceRegistryEvents": {
        "description": "Windows Registry modification events",
        "fields": {
            "TimeGenerated": {
                "type": "datetime",
                "description": "Timestamp when event was generated",
                "required": True
            },
            "DeviceName": {
                "type": "string",
                "description": "Name of the device",
                "required": True
            },
            "ActionType": {
                "type": "string",
                "description": "Type of registry action",
                "required": True,
                "allowed_values": ["RegistryKeyCreated", "RegistryValueSet", "RegistryKeyDeleted"]
            },
            "RegistryKey": {
                "type": "string",
                "description": "Full registry key path",
                "required": False,
                "example": "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            },
            "InitiatingProcessAccountName": {
                "type": "string",
                "description": "Account name of the process that initiated the registry change",
                "required": False,
                "example": "administrator"
            }
        },
        "common_queries": [
            "Filter by key: | where RegistryKey contains \"Run\"",
            "Filter by account: | where InitiatingProcessAccountName == \"username\""
        ]
    }
}


# KQL syntax rules and best practices
KQL_RULES = {
    "filtering": {
        "description": "Use 'where' to filter rows",
        "correct": [
            "| where DeviceName == \"hostname\"",
            "| where ActionType == \"LogonSuccess\"",
            "| where RemoteIP != \"\"",
            "| where TimeGenerated > ago(24h)"
        ],
        "incorrect": [
            "| where Computer == \"hostname\"  // Wrong field name",
            "| where LogonSuccess == true  // Wrong field name",
            "| where IPAddress != \"\"  // Wrong field name"
        ]
    },
    "time_filtering": {
        "description": "Use TimeGenerated for time-based filtering",
        "correct": [
            "| where TimeGenerated between (datetime(2025-09-13) .. datetime(2025-09-14))",
            "| where TimeGenerated > ago(24h)",
            "| where TimeGenerated >= datetime(2025-09-13T00:00:00Z)"
        ],
        "incorrect": [
            "| where Timestamp > ago(24h)  // Use TimeGenerated, not Timestamp"
        ]
    },
    "aggregation": {
        "description": "Use summarize for aggregations",
        "correct": [
            "| summarize count() by DeviceName",
            "| summarize FailedCount = countif(ActionType == \"LogonFailed\") by RemoteIP",
            "| summarize FirstTime = min(TimeGenerated) by RemoteIP"
        ],
        "tips": [
            "After summarize, only aggregated fields are available",
            "Use 'by' clause to group results",
            "Use min(), max(), count(), countif() for aggregations"
        ]
    },
    "joins": {
        "description": "Be careful with field ambiguity after joins",
        "correct": [
            "| join kind=inner (table2) on $left.Field == $right.Field"
        ],
        "warning": "After join, specify table prefix if field exists in both tables"
    },
    "projection": {
        "description": "Use project to select specific fields",
        "correct": [
            "| project TimeGenerated, DeviceName, RemoteIP",
            "| project-away SensitiveField"
        ]
    }
}


def get_table_schema(table_name):
    """Get comprehensive schema for a table"""
    return AZURE_TABLE_SCHEMAS.get(table_name, {})


def get_field_list(table_name):
    """Get list of allowed field names for a table"""
    schema = AZURE_TABLE_SCHEMAS.get(table_name, {})
    return list(schema.get("fields", {}).keys())


def get_field_info(table_name, field_name):
    """Get detailed info about a specific field"""
    schema = AZURE_TABLE_SCHEMAS.get(table_name, {})
    return schema.get("fields", {}).get(field_name, {})


def generate_schema_prompt(table_name):
    """Generate detailed schema prompt for LLM"""
    schema = AZURE_TABLE_SCHEMAS.get(table_name, {})
    
    if not schema:
        return f"Table: {table_name}\nNo schema available."
    
    prompt = f"""
**Table: {table_name}**
Description: {schema.get('description', 'N/A')}

**Available Fields:**
"""
    
    for field_name, field_info in schema.get("fields", {}).items():
        prompt += f"\n• **{field_name}** ({field_info.get('type', 'string')})"
        prompt += f"\n  - {field_info.get('description', 'No description')}"
        
        if field_info.get('allowed_values'):
            prompt += f"\n  - Allowed values: {', '.join(field_info['allowed_values'])}"
        
        if field_info.get('example'):
            prompt += f"\n  - Example: {field_info['example']}"
    
    prompt += "\n\n**Common Query Patterns:**\n"
    for query in schema.get("common_queries", []):
        prompt += f"  {query}\n"
    
    return prompt


def generate_kql_rules_prompt():
    """Generate KQL syntax rules for LLM"""
    prompt = "\n**KQL SYNTAX RULES:**\n\n"
    
    for rule_name, rule_info in KQL_RULES.items():
        prompt += f"**{rule_name.upper()}:**\n"
        prompt += f"{rule_info.get('description', '')}\n\n"
        
        if rule_info.get('correct'):
            prompt += "✅ CORRECT Examples:\n"
            for example in rule_info['correct']:
                prompt += f"  {example}\n"
            prompt += "\n"
        
        if rule_info.get('incorrect'):
            prompt += "❌ INCORRECT Examples:\n"
            for example in rule_info['incorrect']:
                prompt += f"  {example}\n"
            prompt += "\n"
        
        if rule_info.get('tips'):
            prompt += "💡 Tips:\n"
            for tip in rule_info['tips']:
                prompt += f"  • {tip}\n"
            prompt += "\n"
        
        if rule_info.get('warning'):
            prompt += f"⚠️ {rule_info['warning']}\n\n"
    
    return prompt



# ═══════════════════════════════════════════════════════════════════════
# COMPACT TABLE DIRECTORY (for prompts - a few hundred tokens, not a schema dump)
# ═══════════════════════════════════════════════════════════════════════

TABLE_DIRECTORY = {
    "DeviceLogonEvents":    "logons (RDP/RemoteInteractive, network, interactive) - AccountName, DeviceName, ActionType, LogonType, RemoteIP, RemoteDeviceName",
    "DeviceProcessEvents":  "process starts - DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, SHA256",
    "DeviceNetworkEvents":  "network connections - DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine, ActionType",
    "DeviceFileEvents":     "file create/modify/delete - DeviceName, FileName, FolderPath, ActionType, SHA256, InitiatingProcessAccountName, InitiatingProcessCommandLine",
    "DeviceRegistryEvents": "registry changes - DeviceName, RegistryKey, RegistryValueName, RegistryValueData, ActionType, InitiatingProcessAccountName",
    "DeviceEvents":         "other MDE events (NamedPipeEvent, ScheduledTaskCreated, PowerShellCommand...) - ActionType, AdditionalFields (JSON, e.g. PipeName)",
    "AlertInfo":            "Defender alerts - AlertId, Title, Severity, Category, DetectionSource",
    "AlertEvidence":        "alert entities - AlertId, EntityType, EvidenceRole, FileName, RemoteIP, AccountName",
    "SigninLogs":           "Entra ID sign-ins (cloud, NOT RDP) - UserPrincipalName, AppDisplayName, IPAddress, ResultType",
    "AuditLogs":            "Entra ID directory changes - OperationName, InitiatedBy, TargetResources",
    "AzureActivity":        "Azure control-plane operations - OperationNameValue, Caller, CallerIpAddress, ResourceGroup",
    "AzureNetworkAnalytics_CL": "NSG flow logs - FlowType_s, SrcPublicIPs_s, DestIP_s, DestPort_d, VM_s",
}


def table_directory_prompt():
    """One line per table: which table holds what, with its key fields. ~350 tokens."""
    lines = ["AVAILABLE LOG TABLES (Microsoft Defender for Endpoint / Sentinel, all have TimeGenerated):"]
    for t, d in TABLE_DIRECTORY.items():
        lines.append(f"- {t}: {d}")
    lines.append("Note: RDP logons are DeviceLogonEvents with LogonType == 'RemoteInteractive' - not SigninLogs.")
    return "\n".join(lines)
