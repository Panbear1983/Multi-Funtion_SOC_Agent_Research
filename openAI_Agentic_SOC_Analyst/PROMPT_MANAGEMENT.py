from color_support import Fore

# Streamlined formatting instructions - reduced from 65 lines to 25 lines
FORMATTING_INSTRUCTIONS = """
Return findings in this JSON format:
{
  "findings": [
    {
      "title": "Brief suspicious activity title",
      "description": "Detailed explanation with log context",
      "mitre": {
        "tactic": "e.g., Execution",
        "technique": "e.g., T1059",
        "sub_technique": "e.g., T1059.001",
        "id": "e.g., T1059, T1059.001",
        "description": "MITRE technique description"
      },
      "log_lines": ["Relevant log lines that triggered suspicion"],
      "confidence": "Low | Medium | High",
      "recommendations": ["pivot", "create incident", "monitor", "ignore"],
      "indicators_of_compromise": ["IOCs: IP, domain, hash, filename, etc."],
      "tags": ["privilege escalation", "persistence", "data exfiltration", "C2", "credential access", "unusual command", "reconnaissance", "malware", "suspicious login"],
      "notes": "Optional analyst notes"
    }
  ]
}

If no findings: {"findings": []}
———————————
logs below:
"""

THREAT_HUNT_PROMPTS = {
"GeneralThreatHunter": """
Expert Threat Hunting AI for Microsoft Defender for Endpoint (MDE) data.

CORE DETECTION FOCUS:
- Lateral movement (wmic, PsExec, RDP)
- Privilege escalation & credential dumping
- Command & control (beaconing, encoded PowerShell)
- Persistence (registry, services)
- Data exfiltration patterns

OUTPUT: MITRE mapping, IOCs extraction, confidence levels, actionable recommendations.
""",

"DeviceProcessEvents": """
Expert AI analyzing MDE DeviceProcessEvents for process execution threats.

DETECT:
- LOLBins used maliciously
- Abnormal parent-child relationships
- Command-line obfuscation/encoding
- Scripting engines (PowerShell, wscript, mshta)
- Suspicious system tool usage

EXTRACT: Process names, hashes, command-line args, user accounts, process paths.
""",

"DeviceNetworkEvents": """
Expert AI analyzing MDE DeviceNetworkEvents for network-based threats.

DETECT:
- Beaconing behavior & rare external IPs
- Suspicious ports/protocols (TOR: 9050, 9150, 9051, 9151, 9001, 9030)
- DNS tunneling & encoded queries
- Rare domain/IP contacts
- Known malicious infrastructure

EXTRACT: Remote IPs/domains, ports, protocols, device names, process initiators.
""",

"DeviceLogonEvents": """
Expert AI analyzing MDE DeviceLogonEvents for authentication anomalies.

DETECT:
- Unusual logon types/hours
- Remote local logons
- Repeated failed attempts
- New service account usage
- Suspicious device logons

EXTRACT: Usernames, device names, logon types, timestamps, IPs.
""",

"DeviceRegistryEvents": """
Expert AI analyzing MDE DeviceRegistryEvents for persistence & evasion.

DETECT:
- Run/RunOnce persistence keys
- Security tool setting modifications
- UAC bypass methods
- Registry tampering by unusual processes

EXTRACT: Registry paths, process names, command-line args, user accounts.
""",

"AlertEvidence": """
Expert AI analyzing MDE AlertEvidence for threat correlation.

INTERPRET:
- Process chains & execution context
- File, IP, and user artifacts
- Alert titles vs MITRE ATT&CK

EXTRACT: IOCs and assess evidence confirmation/contradiction.
""",

"DeviceFileEvents": """
Expert AI analyzing MDE DeviceFileEvents for file-based threats.

DETECT:
- Executable/script creation in temp dirs
- File drops by suspicious processes
- Known malicious filenames/hashes
- System/config file tampering

EXTRACT: Filenames, hashes, paths, process relationships.
""",

"AzureActivity": """
Expert AI analyzing AzureActivity for control-plane threats.

DETECT:
- Role assignment changes & privilege escalations
- Resource deployments outside baseline
- Failed operations & suspicious caller IPs
- Elevated operations (NSG rules, RBAC)

EXTRACT: OperationName, caller IP, UPN, ResourceType/ID, subscription/resource group.
""",

"SigninLogs": """
Expert AI analyzing SigninLogs for authentication anomalies.

DETECT:
- Atypical locations/IPs
- Impossible travel patterns
- Repeated failures & password spray
- Rare device/account usage
- High risk sign-ins

EXTRACT: Username, IP, DeviceID, Timestamp, risk details, TenantId, App ID.
""",

"AuditLogs": """
Expert AI analyzing AuditLogs for directory/identity threats.

DETECT:
- User/group creation/deletion & role changes
- App registration & consent grants
- Admin password resets
- Privileged role modifications
- Conditional access policy changes

EXTRACT: Initiating user/app, TargetResource types, operation names, timestamps, correlationId.
""",

"AzureNetworkAnalytics_CL": """
Expert AI analyzing AzureNetworkAnalytics_CL for network flow threats.

CRITICAL PATTERNS:
- External/malicious flows (FlowType_s = MaliciousFlow, ExternalPublic, ExternalPrivate)
- Unusual ports/protocols & high-volume outbound
- Suspicious IP ranges & rare subnets
- High frequency external connections
- Unusual traffic patterns

IOCs: SrcPublicIPs_s, DestIP_s, FlowType_s, DestPort_d, VM_s, flow counts
MITRE: C2 (T1071, T1090, T1104), Exfiltration (T1041, T1048, T1059)
""",

"AlertInfo": """
Expert AI analyzing AlertInfo for threat intelligence patterns.

CRITICAL PATTERNS:
- High-severity alerts (Critical, High)
- Multiple alerts from same source
- Suspicious titles/descriptions
- Security product alerts
- Specific threat names/techniques

IOCs: AlertId, Title, Severity, Status, ProductName, ProviderName, ThreatName
MITRE: Based on alert content and attack techniques
""",

"AzureNetworkAnalyticsIPDetails_CL": """
Expert AI analyzing AzureNetworkAnalyticsIPDetails_CL for IP threat intelligence.

CRITICAL PATTERNS:
- Suspicious geolocations (high-risk countries)
- Known threat actor/APT IPs
- Unusual organizations (cloud providers, VPNs, proxies)
- Threat intelligence flagged IPs
- High-risk IP categories

IOCs: PublicIPAddress_s, PublicIPDetails_s, Country_s, City_s, Organization_s
MITRE: C2 (T1071, T1090), Exfiltration (T1041, T1048), Initial Access (T1078, T1190)
"""
}

SYSTEM_PROMPT_THREAT_HUNT = {
    "role": "system",
    "content": (
        "Cybersecurity threat hunting AI for SOC analysts analyzing Microsoft Defender for Endpoint (MDE), Azure AD, and Azure resource logs.\n\n"
        "CAPABILITIES:\n"
        "- Interpret logs from: DeviceProcessEvents, DeviceNetworkEvents, DeviceLogonEvents, DeviceRegistryEvents, DeviceFileEvents, AlertEvidence, AlertInfo, AzureActivity, SigninLogs, AuditLogs, AzureNetworkAnalytics_CL, AzureNetworkAnalyticsIPDetails_CL\n"
        "- Map to MITRE ATT&CK tactics/techniques with confidence levels\n"
        "- Extract IOCs: IPs, domains, hashes, file paths, registry keys\n"
        "- Detect: PowerShell obfuscation, lateral movement, persistence, fileless attacks\n"
        "- Recommend: Investigate, Monitor, Escalate, or Ignore\n\n"
        "TONE: Concise, evidence-based, structured. Avoid hallucination and vague summaries.\n"
        "AUDIENCE: Skilled analysts, not end users. Focus on real threat detection using log evidence."
    )}

SYSTEM_PROMPT_TOOL_SELECTION = {
    "role": "system",
    "content": (
        "Tool selection AI for threat hunting. Convert natural language to structured KQL queries.\n\n"
        "CONTRACT:\n"
        "- Call exactly one tool: query_log_analytics\n"
        "- Return JSON with ALL required parameters\n"
        "- Use empty string \"\" for unknown text, false for booleans, [] for arrays\n"
        "- Default timeframe: 4 days (96 hours) if unspecified\n"
        "- Only request fields listed in tool description\n"
    )
}

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "query_log_analytics",
            "description": (
                "Query a Log Analytics table using KQL. "
                "Available tables include:\n"
                "- DeviceProcessEvents: Process creation and command-line info\n"
                "- DeviceNetworkEvents: Network connection on the host/server/vm/computer etc. \n"
                "- DeviceLogonEvents: Logon activity against one or more servers or workstations\n"
                "- DeviceFileEvents: File and filesystem / file system activities and operations\n"
                "- DeviceRegistryEvents: Registry modifications and persistence mechanisms\n"
                "- AlertInfo: Alert metadata and information\n"
                "- AlertEvidence: Alert-related details and evidence\n"
                "- AzureActivity: Control plane operations (resource changes, role assignments, etc.)\n"
                "- SigninLogs: Azure AD sign-in activity including user, app, result, and IP info\n"
                "- AuditLogs: Azure AD audit events and directory changes\n"
                "- AzureNetworkAnalytics_CL: Network Security Group (NSG) flow logs via Azure Traffic Analytics\n"
                "- AzureNetworkAnalyticsIPDetails_CL: IP details and geolocation from NSG flow logs\n"

                "Fields (array/list) to include for the selected table (All Log Analytics tables use 'TimeGenerated'):\n"
                "- DeviceProcessEvents Fields: TimeGenerated, AccountName, ActionType, DeviceName, InitiatingProcessCommandLine, ProcessCommandLine\n"
                "- DeviceFileEvents Fields: TimeGenerated, ActionType, DeviceName, FileName, FolderPath, InitiatingProcessAccountName, SHA256\n"
                "- DeviceLogonEvents Fields: TimeGenerated, AccountName, DeviceName, ActionType, RemoteIP, RemoteDeviceName\n"
                "- DeviceNetworkEvents Fields: TimeGenerated, ActionType, DeviceName, RemoteIP, RemotePort\n"
                "- DeviceRegistryEvents Fields: TimeGenerated, ActionType, DeviceName, RegistryKey, InitiatingProcessAccountName\n"
                "- AlertInfo Fields: TimeGenerated, AlertId, Title, Severity, Status, ProductName, ProviderName\n"
                "- AlertEvidence Fields: TimeGenerated, AlertId, EvidenceType, EvidenceValue, DeviceName, AccountName\n"
                "- AzureActivity Fields: TimeGenerated, OperationNameValue, ActivityStatusValue, ResourceGroup, Caller, CallerIpAddress, Category\n"
                "- SigninLogs Fields: TimeGenerated, UserPrincipalName, OperationName, Category, ResultSignature, ResultDescription, AppDisplayName, IPAddress, LocationDetails\n"
                "- AuditLogs Fields: TimeGenerated, OperationName, Category, Result, TargetResourceType, InitiatedBy\n"
                "- AzureNetworkAnalytics_CL Fields: TimeGenerated, FlowType_s, SrcPublicIPs_s, DestIP_s, DestPort_d, VM_s, AllowedInFlows_d, AllowedOutFlows_d, DeniedInFlows_d, DeniedOutFlows_d\n"
                "- AzureNetworkAnalyticsIPDetails_CL Fields: TimeGenerated, PublicIPAddress_s, PublicIPDetails_s, IPDetails_s, Country_s, City_s, Organization_s\n"

                "If a user, username, or AccountName is mentioned, capture it in the 'user_principal_name' field.\n"
                "- Tables with account filtering: DeviceLogonEvents (AccountName), DeviceProcessEvents (AccountName), DeviceFileEvents (InitiatingProcessAccountName), DeviceRegistryEvents (InitiatingProcessAccountName), AlertEvidence (AccountName), SigninLogs (UserPrincipalName), AuditLogs (InitiatedBy), AzureActivity (Caller)\n"
                "- Tables WITHOUT account filtering: DeviceNetworkEvents, AlertInfo, AzureNetworkAnalytics_CL, AzureNetworkAnalyticsIPDetails_CL (use DeviceName or IP fields instead)\n"
                "- If user requests account filtering, prefer tables that support it (DeviceLogonEvents or DeviceProcessEvents)\n"
                "If network activity is being questioned for a specific host, this is likely to be found on the DeviceNetworkEvents table.\n"
                "If general firewall or NSG activity is being asked about (not for a specific host/device), this is likely to be found in the AzureNetworkAnalytics_CL table.\n"
                "If the Azure Portal, Activity log, or Azure resource creation/deletion events are being asked about, these logs are likely to be found in the AzureActivity table. The Username in the AzureActivity table is the 'Caller' field"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "table_name": {
                        "type": "string",
                        "description": (
                            "Log Analytics table to query. Examples: DeviceProcessEvents, DeviceNetworkEvents, "
                            "DeviceLogonEvents, AzureNetworkAnalytics_CL"
                        )
                    },
                    "device_name": {
                        "type": "string",
                        "description": "The DeviceName to filter by (e.g., \"userpc-1\".)",
                    },
                    "caller": {
                        "type": "string",
                        "description": "This is a field that exists in some tables that represents the user. It is the email address of the user who has performed the operation, UPN, username or SPN claim based on availability."
                    },
                    "user_principal_name": {
                        "type": "string",
                        "description": "The 'user', 'username', 'account', or 'AccountName' mentioned in the query. For Device tables (DeviceLogonEvents, DeviceProcessEvents, etc.) this filters by AccountName field. For SigninLogs this is UserPrincipalName. For AzureActivity, use the 'caller' field instead. Examples: 'flare', 'admin', 'john@company.com'"
                    },
                    "time_range_hours": {
                        "type": "integer",
                        "description": "How far back to search (e.g., 24 for 1 day)"
                    },
                    "fields": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of fields to return"
                    },
                    "about_individual_user": {
                        "type": "boolean",
                        "description": "The query was about an individual user or user account"
                    },
                    "about_individual_host": {
                        "type": "boolean",
                        "description": "The query was about an individual host, server, client, or endpoint"
                    },
                    "about_network_security_group": {
                        "type": "boolean",
                        "description": "The query was about a firewall or network security group (NSG)"
                    },
                    "rationale": {
                        "type": "string",
                        "description": "Your rational for choosing the properties that you did, for each property. (For example, time period selection, table selection, fields, user and/or device selection etc.)"
                    }
                },
                "required": [
                    "table_name",
                    "device_name",
                    "time_range_hours",
                    "fields",
                    "caller",
                    "user_principal_name",
                    "about_individual_user",
                    "about_individual_host",
                    "about_network_security_group",
                    "rationale"
                ]
            }
        }
    }
]

def get_user_message():
    prompt = ""
    
    print("\n"*20)

    # Prompt the user for input, showing the current prompt as the default
    #user_input = input(f"Enter your prompt (or press Enter to keep the current one):\n[{prompt}]\n> ").strip()
    user_input = input(f"{Fore.LIGHTBLUE_EX}Agentic SOC Analyst at your service! What would you like to do?\n\n{Fore.RESET}").strip()

    # If user_input is empty, use the existing prompt
    if user_input:
        prompt = user_input

    user_message = {
        "role": "user",
        "content": prompt
    }

    return user_message

def build_threat_hunt_prompt(user_prompt: str, table_name: str, log_data: str, investigation_context: str = "", guidance_on: bool = False, known_killchain: str = "") -> dict:
    
    print(f"{Fore.LIGHTGREEN_EX}Building threat hunt prompt/instructions...\n")

    # Build the prompt, specifically for hunting in table: table_name
    instructions = THREAT_HUNT_PROMPTS.get(table_name, "")
    
    # Add investigation context section if provided (IOCs, hints, etc.)
    context_section = ""
    if investigation_context:
        context_section = (
            f"🎯 INVESTIGATION CONTEXT / HINTS:\n"
            f"{investigation_context}\n\n"
            f"IMPORTANT: Pay special attention to the context above. Look for patterns, IOCs, "
            f"or behaviors related to the hints. Prioritize findings that match the investigation context.\n\n"
        )
    
    # Optional exemplar/evidence requirements (flag-gated)
    exemplar_section = ""
    if guidance_on:
        try:
            import RETRIEVAL_MEMORY
            exemplar = RETRIEVAL_MEMORY.get_killchain_exemplar(known_killchain)
        except Exception:
            exemplar = ""
        if exemplar:
            exemplar_section = (
                f"KNOWN PATTERN (Small Exemplar):\n{exemplar}\n"
                f"EVIDENCE REQUIREMENTS:\n"
                f"- Include findings[].evidence_rows (row indexes) and findings[].evidence_fields (column names)\n"
                f"- Provide findings[].confidence_rationale referencing concrete log evidence\n\n"
            )

    # Combine all the user request, hunt instructions for the table, formatting instructions, and log data.
    # This giant prompt will be sent to that ChatGPT API for analysis
    full_prompt = (
        f"User request:\n{user_prompt}\n\n"
        f"{context_section}"  # Insert investigation context here
        f"Threat Hunt Instructions:\n{instructions}\n\n"
        f"{exemplar_section}"
        f"Formatting Instructions: \n{FORMATTING_INSTRUCTIONS}\n\n"
        f"Log Data:\n{log_data}"
    )

    return {"role": "user", "content": full_prompt}