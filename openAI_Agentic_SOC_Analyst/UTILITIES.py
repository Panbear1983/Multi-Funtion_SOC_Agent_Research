import json
import re
from color_support import Fore, Style, init
import FEEDBACK_MANAGER


def display_query_context(query_context):
    print(f"{Fore.LIGHTGREEN_EX}{'='*70}")
    print(f"{Fore.LIGHTGREEN_EX}QUERY CONTEXT & INVESTIGATION TRAIL")
    print(f"{Fore.LIGHTGREEN_EX}{'='*70}")
    
    # Calculate time range for display
    from datetime import datetime, timedelta, timezone
    
    # Use provided dates if available, otherwise calculate from hours
    if 'start_date' in query_context and 'end_date' in query_context and query_context['start_date']:
        start_time = query_context['start_date']
        end_time = query_context['end_date']
    else:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=query_context['time_range_hours'])
    
    print(f"\n{Fore.LIGHTCYAN_EX}TARGET INFORMATION:")
    print(f"{Fore.WHITE}  Table Name:   {Fore.LIGHTYELLOW_EX}{query_context['table_name']}")
    print(f"{Fore.WHITE}  Time Range:   {Fore.LIGHTYELLOW_EX}{query_context['time_range_hours']} hour(s)")
    print(f"{Fore.LIGHTBLACK_EX}    From: {start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{Fore.LIGHTBLACK_EX}    To:   {end_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{Fore.WHITE}  Fields:       {Fore.LIGHTBLACK_EX}{query_context['fields']}")
    
    # Display applied filters with field mapping
    print(f"\n{Fore.LIGHTCYAN_EX}APPLIED FILTERS:")
    table_name = query_context['table_name']
    filters_applied = []
    
    # Device filter
    if query_context['device_name'] != "":
        print(f"{Fore.WHITE}  ✓ DeviceName contains: {Fore.LIGHTGREEN_EX}'{query_context['device_name']}'")
        filters_applied.append(f"DeviceName contains \"{query_context['device_name']}\"")
    
    # User/Account filter - show the actual field name that will be used
    if query_context['user_principal_name'] != "":
        # Determine which field this maps to based on table
        if table_name == 'SigninLogs':
            field_name = 'UserPrincipalName'
            print(f"{Fore.WHITE}  ✓ {field_name} contains: {Fore.LIGHTGREEN_EX}'{query_context['user_principal_name']}'")
            filters_applied.append(f"{field_name} contains \"{query_context['user_principal_name']}\"")
        elif table_name in ['DeviceLogonEvents', 'DeviceProcessEvents']:
            field_name = 'AccountName'
            print(f"{Fore.WHITE}  ✓ {field_name} contains: {Fore.LIGHTGREEN_EX}'{query_context['user_principal_name']}'")
            filters_applied.append(f"{field_name} contains \"{query_context['user_principal_name']}\"")
        elif table_name == 'DeviceFileEvents':
            field_name = 'InitiatingProcessAccountName'
            print(f"{Fore.WHITE}  ✓ {field_name} contains: {Fore.LIGHTGREEN_EX}'{query_context['user_principal_name']}'")
            filters_applied.append(f"{field_name} contains \"{query_context['user_principal_name']}\"")
        elif table_name == 'AzureActivity':
            field_name = 'Caller'
            print(f"{Fore.WHITE}  ✓ {field_name} contains: {Fore.LIGHTGREEN_EX}'{query_context['user_principal_name']}'")
            filters_applied.append(f"{field_name} contains \"{query_context['user_principal_name']}\"")
        elif table_name in ['DeviceNetworkEvents', 'DeviceRegistryEvents']:
            # These tables don't have user/account fields
            print(f"{Fore.LIGHTYELLOW_EX}  ⚠ Account filter '{query_context['user_principal_name']}' requested but {table_name} has no account field")
            print(f"{Fore.LIGHTBLACK_EX}    (Table only has: DeviceName, RemoteIP, RemotePort for DeviceNetworkEvents)")
            print(f"{Fore.LIGHTBLACK_EX}    (Filter will be skipped - querying all records for device)")
        else:
            field_name = 'UserPrincipalName/AccountName'
            print(f"{Fore.WHITE}  ✓ {field_name} contains: {Fore.LIGHTGREEN_EX}'{query_context['user_principal_name']}'")
            filters_applied.append(f"{field_name} contains \"{query_context['user_principal_name']}\"")
    
    # Caller filter (Azure Activity)
    if query_context['caller'] != "" and table_name == 'AzureActivity':
        print(f"{Fore.WHITE}  ✓ Caller contains: {Fore.LIGHTGREEN_EX}'{query_context['caller']}'")
        filters_applied.append(f"Caller contains \"{query_context['caller']}\"")
    
    # Show if no filters
    if not filters_applied:
        print(f"{Fore.LIGHTBLACK_EX}  (No filters applied - querying all records)")
    
    # Show KQL WHERE clause
    print(f"\n{Fore.LIGHTCYAN_EX}KQL WHERE CLAUSE:")
    # All Log Analytics tables use 'TimeGenerated' (not 'Timestamp')
    time_field = 'TimeGenerated'
    time_filter = f"{time_field} between (datetime({start_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}) .. datetime({end_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}))"
    print(f"{Fore.LIGHTYELLOW_EX}  | where {time_filter}")
    
    if filters_applied:
        for filter_clause in filters_applied:
            print(f"{Fore.LIGHTYELLOW_EX}  | where {filter_clause}")
    
    # Investigation focus
    print(f"\n{Fore.LIGHTCYAN_EX}INVESTIGATION FOCUS:")
    print(f"{Fore.WHITE}  User-Focused:    {Fore.LIGHTGREEN_EX if query_context['about_individual_user'] else Fore.LIGHTBLACK_EX}{query_context['about_individual_user']}")
    print(f"{Fore.WHITE}  Host-Focused:    {Fore.LIGHTGREEN_EX if query_context['about_individual_host'] else Fore.LIGHTBLACK_EX}{query_context['about_individual_host']}")
    print(f"{Fore.WHITE}  Network-Focused: {Fore.LIGHTGREEN_EX if query_context['about_network_security_group'] else Fore.LIGHTBLACK_EX}{query_context['about_network_security_group']}")
    
    print(f"\n{Fore.LIGHTCYAN_EX}RATIONALE:")
    print(f"{Fore.WHITE}  {query_context['rationale']}")
    
    print(f"\n{Fore.LIGHTGREEN_EX}{'='*70}\n")

def display_threats(threat_list):
    # Initialize feedback manager
    feedback_mgr = FEEDBACK_MANAGER.FeedbackManager()
    
    # Show learning history before displaying results
    feedback_mgr.display_learning_summary()
    
    count = 0
    for threat in threat_list:
        count += 1
        
        # Record finding for feedback (exclude INVESTIGATIVE CONCLUSION)
        feedback_mgr.record_finding(threat)
        
        print(f"\n=============== Potential Threat #{count} ===============\n")
        print(f"{Fore.LIGHTCYAN_EX}Title: {threat.get('title')}{Fore.RESET}\n")
        print(f"Description: {threat.get('description')}\n")

        init(autoreset=True)  # Automatically resets to default after each print

        confidence = threat.get('confidence', '').lower()

        if confidence == 'high':
            color = Fore.LIGHTRED_EX
        elif confidence == 'medium':
            color = Fore.LIGHTYELLOW_EX
        elif confidence == 'low':
            color = Fore.LIGHTBLUE_EX
        else:
            color = Style.RESET_ALL  # Default/no color

        print(f"{color}Confidence Level: {threat.get('confidence')}")
        print("\nMITRE ATT&CK Info:")
        mitre = threat.get('mitre', {})
        print(f"  Tactic: {mitre.get('tactic')}")
        print(f"  Technique: {mitre.get('technique')}")
        print(f"  Sub-technique: {mitre.get('sub_technique')}")
        print(f"  ID: {mitre.get('id')}")
        print(f"  Description: {mitre.get('description')}")

        print("\nLog Lines:")
        for log in threat.get('log_lines', []):
            print(f"  - {log}")

        print("\nIndicators of Compromise:")
        for ioc in threat.get('indicators_of_compromise', []):
            print(f"  - {ioc}")

        print("\nTags:")
        for tag in threat.get('tags', []):
            print(f"  - {tag}")

        print("\nRecommendations:")
        for rec in threat.get('recommendations', []):
            print(f"  - {rec}")

        print(f"\nNotes: {threat.get('notes')}")

        print("=" * 51)
    
    # Add investigative analysis (without "INVESTIGATIVE CONCLUSION" title)
    if threat_list:
        # Extract key investigative details with relationships
        usernames = set()
        source_ips = set()
        target_devices = set()
        attack_sequence = []
        
        # Track relationships: device -> IPs, device -> accounts
        device_to_ips = {}  # {device: [ips]}
        device_to_accounts = {}  # {device: [accounts]}
        ip_to_device = {}  # {ip: device}
        
        for threat in threat_list:
            # Extract structured metadata from threat (added by QWEN_ENHANCER)
            device_name = threat.get('device_name')
            device_names_list = threat.get('device_names', [])  # For IOC findings with multiple devices
            account_name = threat.get('account_name')
            remote_ip = threat.get('remote_ip')
            
            # Add device name if present (singular)
            if device_name and not re.match(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', device_name):
                target_devices.add(device_name)
            
            # Add device names if present (plural, for IOC findings)
            for dev in device_names_list:
                if dev and not re.match(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', dev):
                    target_devices.add(dev)
            
            # Add account name if present
            if account_name and not re.match(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', account_name):
                usernames.add(account_name)
            
            # Add remote IP if present
            if remote_ip:
                source_ips.add(remote_ip)
            
            # Link IP to device (singular)
            if device_name and remote_ip:
                if device_name not in device_to_ips:
                    device_to_ips[device_name] = set()
                device_to_ips[device_name].add(remote_ip)
                ip_to_device[remote_ip] = device_name
            
            # Link IPs to devices (plural, for IOC findings)
            iocs = threat.get('indicators_of_compromise', [])
            for ioc in iocs:
                if re.match(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', str(ioc)):
                    # This is an IP IOC, link it to all devices in the finding
                    for dev in device_names_list:
                        if dev:
                            if dev not in device_to_ips:
                                device_to_ips[dev] = set()
                            device_to_ips[dev].add(str(ioc))
                            ip_to_device[str(ioc)] = dev
            
            # Link account to device
            if device_name and account_name:
                if device_name not in device_to_accounts:
                    device_to_accounts[device_name] = set()
                device_to_accounts[device_name].add(account_name)
            
            # Also extract from IOCs
            iocs = threat.get('indicators_of_compromise', [])
            for ioc in iocs:
                ioc_str = str(ioc).strip()
                if 'username:' in ioc_str.lower() or 'user:' in ioc_str.lower():
                    usernames.add(ioc_str.split(':')[-1].strip())
                # Extract IP addresses from IOCs
                elif re.match(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', ioc_str):
                    source_ips.add(ioc_str)
                # Extract potential usernames (email-like or domain\user format)
                elif '@' in ioc_str or '\\' in ioc_str:
                    usernames.add(ioc_str)
            
            # Also parse log_lines for additional context (these now have structured metadata)
            log_lines = threat.get('log_lines', [])
            for line in log_lines:
                # Parse structured metadata lines
                if line.startswith('DeviceName:'):
                    dev = line.split(':', 1)[1].strip()
                    if dev and not re.match(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', dev):
                        target_devices.add(dev)
                elif line.startswith('AccountName:'):
                    acc = line.split(':', 1)[1].strip()
                    if acc and not re.match(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', acc):
                        usernames.add(acc)
                elif line.startswith('RemoteIP:'):
                    ip = line.split(':', 1)[1].strip()
                    if re.match(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', ip):
                        source_ips.add(ip)
                # Also extract from raw text as fallback
                elif not line.startswith('IOC:'):
                    ip_matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                    for ip in ip_matches:
                        source_ips.add(ip)
                    
                    email_matches = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', line)
                    for email in email_matches:
                        usernames.add(email)
            
            # Build attack sequence
            mitre = threat.get('mitre', {})
            tactic = mitre.get('tactic', 'Unknown')
            technique = mitre.get('technique', 'Unknown')
            attack_sequence.append(f"{tactic} via {technique}")
        
        # Build narrative without the "INVESTIGATIVE CONCLUSION" header
        print(f"\n{Fore.WHITE}{'='*60}")
        print(f"{Fore.WHITE}INVESTIGATIVE NARRATIVE:")
        print(f"{Fore.WHITE}{'─'*50}")
        
        # Display compromised devices with their associated IPs and accounts
        if target_devices:
            device_list = [d for d in target_devices if d and d.strip()]
            if device_list:
                print(f"\n{Fore.LIGHTCYAN_EX}COMPROMISED DEVICES & ACTIVITY:")
                for device in sorted(device_list):
                    print(f"\n{Fore.LIGHTCYAN_EX}  Device: {Fore.WHITE}{device}")
                    
                    # Show IPs associated with this device
                    if device in device_to_ips and device_to_ips[device]:
                        ips = sorted(device_to_ips[device])
                        print(f"{Fore.LIGHTRED_EX}    ↳ Source IPs: {Fore.WHITE}{', '.join(ips)}")
                    else:
                        print(f"{Fore.LIGHTBLACK_EX}    ↳ Source IPs: (none detected)")
                    
                    # Show accounts that manipulated this device
                    if device in device_to_accounts and device_to_accounts[device]:
                        accounts = sorted(device_to_accounts[device])
                        print(f"{Fore.LIGHTYELLOW_EX}    ↳ Suspicious Accounts: {Fore.WHITE}{', '.join(accounts)}")
                    else:
                        print(f"{Fore.LIGHTBLACK_EX}    ↳ Suspicious Accounts: (none detected)")
        
        # Show any orphaned IPs (not linked to a device)
        orphaned_ips = [ip for ip in source_ips if ip not in ip_to_device]
        if orphaned_ips:
            print(f"\n{Fore.LIGHTRED_EX}Additional Source IPs (no device mapping): {Fore.WHITE}{', '.join(sorted(orphaned_ips))}")
        
        # Show any orphaned accounts (not linked to a device)
        linked_accounts = set()
        for accounts in device_to_accounts.values():
            linked_accounts.update(accounts)
        orphaned_accounts = usernames - linked_accounts
        if orphaned_accounts:
            orphaned_list = [u for u in orphaned_accounts if u and u.strip()]
            if orphaned_list:
                print(f"\n{Fore.LIGHTYELLOW_EX}Additional Target Accounts (no device mapping): {Fore.WHITE}{', '.join(sorted(orphaned_list))}")
        
        # Attack progression
        unique_attacks = list(set(attack_sequence))
        if unique_attacks:
            print(f"{Fore.LIGHTGREEN_EX}Attack Progression: {Fore.WHITE}{' → '.join(unique_attacks)}")
        
        # Lateral movement analysis
        lateral_movement_indicators = []
        for threat in threat_list:
            mitre = threat.get('mitre', {})
            tactic = mitre.get('tactic', '')
            if 'Lateral Movement' in tactic:
                lateral_movement_indicators.append(threat.get('title', ''))
        
        if lateral_movement_indicators:
            print(f"\n{Fore.LIGHTRED_EX}LATERAL MOVEMENT DETECTED:")
            for indicator in lateral_movement_indicators:
                print(f"{Fore.WHITE}• {indicator}")
        
        # Account compromise analysis
        privileged_accounts = []
        for username in usernames:
            if any(priv in username.lower() for priv in ['admin', 'administrator', 'root', 'system']):
                privileged_accounts.append(username)
        
        if privileged_accounts:
            print(f"\n{Fore.LIGHTRED_EX}PRIVILEGED ACCOUNT TARGETING:")
            print(f"{Fore.WHITE}The attacker specifically targeted privileged accounts: {', '.join(privileged_accounts)}")
            print(f"{Fore.WHITE}This suggests an attempt to gain elevated privileges for persistence or lateral movement.")
        
        # IOC aggregation and classification
        def _classify_ioc(ioc: str) -> str:
            """Classify IOC type"""
            s = str(ioc).strip()
            if re.match(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', s):
                return 'ip'
            if re.match(r'^[A-Fa-f0-9]{64}$', s) or re.match(r'^[A-Fa-f0-9]{32}$', s):
                return 'hash'
            if '@' in s and re.match(r'^[A-Za-z0-9._%+-]+@', s):
                return 'email'
            if '.' in s and not s.lower().startswith(('device', 'account', 'ip address', 'domain')):
                return 'domain'
            return 'other'
        
        def _is_private_ip(ip: str) -> bool:
            """Check if IP is private/internal"""
            try:
                octs = [int(x) for x in ip.split('.')]
                return (
                    octs[0] == 10 or
                    (octs[0] == 172 and 16 <= octs[1] <= 31) or
                    (octs[0] == 192 and octs[1] == 168)
                )
            except Exception:
                return False
        
        # Aggregate IOCs from all findings
        ioc_summary = {
            'ip': set(),
            'domain': set(),
            'hash': set(),
            'email': set(),
            'other': set()
        }
        
        for threat in threat_list:
            for ioc in threat.get('indicators_of_compromise', []) or []:
                # Strip any "Field: " labels
                val = str(ioc).split(':', 1)[-1].strip() if ':' in str(ioc) else str(ioc).strip()
                bucket = _classify_ioc(val)
                ioc_summary[bucket].add(val)
        
        # Print IOC SUMMARY (before ASSESSMENT)
        if any(ioc_summary.values()):
            print(f"\n{Fore.LIGHTCYAN_EX}IOC SUMMARY (deduplicated):")
            if ioc_summary['ip']:
                private = sorted([ip for ip in ioc_summary['ip'] if _is_private_ip(ip)])
                public = sorted([ip for ip in ioc_summary['ip'] if not _is_private_ip(ip)])
                print(f"{Fore.WHITE}  IPs: {len(ioc_summary['ip'])} total | Public: {len(public)} | Private: {len(private)}")
                if public:
                    print(f"{Fore.LIGHTRED_EX}    ↳ Public sample: {Fore.WHITE}{', '.join(public[:5])}")
                if private:
                    print(f"{Fore.LIGHTBLACK_EX}    ↳ Private sample: {Fore.WHITE}{', '.join(private[:5])}")
            if ioc_summary['domain']:
                print(f"{Fore.WHITE}  Domains: {len(ioc_summary['domain'])}")
                print(f"{Fore.LIGHTBLACK_EX}    ↳ Sample: {Fore.WHITE}{', '.join(sorted(list(ioc_summary['domain']))[:5])}")
            if ioc_summary['hash']:
                print(f"{Fore.WHITE}  Hashes: {len(ioc_summary['hash'])}")
                print(f"{Fore.LIGHTBLACK_EX}    ↳ Sample: {Fore.WHITE}{', '.join(sorted(list(ioc_summary['hash']))[:5])}")
            if ioc_summary['email']:
                print(f"{Fore.WHITE}  Emails: {len(ioc_summary['email'])}")
                print(f"{Fore.LIGHTBLACK_EX}    ↳ Sample: {Fore.WHITE}{', '.join(sorted(list(ioc_summary['email']))[:5])}")
        
        # Calculate assessment stats
        confidence_counts = {'High': 0, 'Medium': 0, 'Low': 0}
        tables_touched = set()
        mitre_tactics = set()
        for threat in threat_list:
            conf = str(threat.get('confidence', 'Unknown')).strip()
            if 'High' in conf:
                confidence_counts['High'] += 1
            elif 'Medium' in conf:
                confidence_counts['Medium'] += 1
            else:
                confidence_counts['Low'] += 1
            # Extract table name from tags or notes if available
            if '_table_name' in threat:
                tables_touched.add(threat['_table_name'])
            # Extract MITRE tactics for context
            mitre = threat.get('mitre', {})
            if mitre.get('tactic'):
                mitre_tactics.add(mitre.get('tactic'))
        
        # Calculate additional context metrics
        total_findings = len(threat_list)
        public_ip_count = len([ip for ip in ioc_summary.get('ip', []) if not _is_private_ip(ip)])
        
        # Build comprehensive paragraph-style assessment
        print(f"\n{Fore.LIGHTCYAN_EX}ASSESSMENT:")
        
        # Build assessment sentence components
        assessment_sentences = []
        
        # Opening: Volume and campaign assessment
        if total_findings > 5:
            assessment_sentences.append(f"Analysis reveals {total_findings} distinct findings indicating a coordinated multi-vector attack campaign")
        elif total_findings > 2:
            assessment_sentences.append(f"Multiple related findings ({total_findings} total) suggest an organized attack sequence")
        else:
            assessment_sentences.append(f"Analysis identified {total_findings} suspicious finding{'s' if total_findings > 1 else ''}")
        
        # Confidence quality assessment
        if confidence_counts['High'] >= 3:
            assessment_sentences.append(f"with {confidence_counts['High']} high-confidence detections indicating strong evidence of compromise")
        elif confidence_counts['High'] > 0:
            assessment_sentences.append(f"including {confidence_counts['High']} high-confidence threat{'s' if confidence_counts['High'] > 1 else ''} requiring immediate attention")
        elif confidence_counts['Medium'] > 0:
            assessment_sentences.append(f"predominantly medium-confidence findings requiring verification")
        else:
            assessment_sentences.append(f"comprised of lower-confidence indicators needing further validation")
        
        # Entity scope assessment
        entity_scope_parts = []
        if len(target_devices) > 3:
            entity_scope_parts.append(f"widespread device compromise ({len(target_devices)} devices)")
        elif len(target_devices) > 1:
            entity_scope_parts.append(f"multiple device compromise ({len(target_devices)} devices)")
        elif len(target_devices) == 1:
            entity_scope_parts.append("single device compromise")
        
        if len(usernames) > 3:
            entity_scope_parts.append(f"large-scale account targeting ({len(usernames)} accounts)")
        elif len(usernames) > 1:
            entity_scope_parts.append(f"multiple account targeting ({len(usernames)} accounts)")
        elif len(usernames) == 1:
            entity_scope_parts.append("single account targeting")
        
        if privileged_accounts:
            entity_scope_parts.append(f"privileged account focus ({len(privileged_accounts)} admin/privileged accounts)")
        
        if public_ip_count > 5:
            entity_scope_parts.append(f"extensive external C2 infrastructure ({public_ip_count} public IPs)")
        elif public_ip_count > 0:
            entity_scope_parts.append(f"external C2 infrastructure ({public_ip_count} public IP{'s' if public_ip_count > 1 else ''})")
        
        if entity_scope_parts:
            assessment_sentences.append(f"Observed scope includes {', '.join(entity_scope_parts)}")
        
        # Lateral movement assessment
        if lateral_movement_indicators:
            if len(lateral_movement_indicators) > 2:
                assessment_sentences.append("Multiple lateral movement indicators detected, suggesting post-compromise expansion across the network")
            else:
                assessment_sentences.append("Lateral movement activity detected, indicating potential spread beyond initial entry point")
        
        # MITRE attack chain assessment
        if len(mitre_tactics) >= 4:
            tactics_list = sorted(list(mitre_tactics))[:4]
            assessment_sentences.append(f"Attack progression spans {len(mitre_tactics)} MITRE tactics ({', '.join(tactics_list)}), indicating advancement through multiple killchain stages")
        elif len(mitre_tactics) >= 2:
            tactics_list = sorted(list(mitre_tactics))
            assessment_sentences.append(f"Attack progression across {len(mitre_tactics)} MITRE tactics ({', '.join(tactics_list)}) suggests structured campaign")
        
        # Table coverage assessment
        if len(tables_touched) >= 4:
            tables_list = sorted(list(tables_touched))[:4]
            assessment_sentences.append(f"Activity spans {len(tables_touched)} data sources ({', '.join(tables_list)}), indicating broad attack surface coverage")
        elif len(tables_touched) >= 2:
            tables_list = sorted(list(tables_touched))
            assessment_sentences.append(f"Multi-source evidence from {len(tables_touched)} log sources ({', '.join(tables_list)}) reinforces threat validity")
        
        # Severity and urgency determination
        if confidence_counts['High'] >= 3:
            severity_level = "CRITICAL"
            urgency = "immediate containment and investigation"
        elif confidence_counts['High'] > 0 or total_findings > 5:
            severity_level = "HIGH"
            urgency = "prompt investigation and containment"
        elif total_findings > 3 or lateral_movement_indicators:
            severity_level = "MEDIUM-HIGH"
            urgency = "thorough investigation recommended"
        else:
            severity_level = "MODERATE"
            urgency = "investigation and monitoring"
        
        # Final severity statement
        assessment_sentences.append(f"Overall severity assessment: {severity_level} - {urgency} required")
        
        # Combine all sentences into flowing paragraph
        assessment_text = ". ".join(assessment_sentences) + "."
        print(f"{Fore.WHITE}{assessment_text}")
        
        # Print stats
        stats_parts = [f"{len(threat_list)} findings"]
        if confidence_counts['High'] > 0:
            stats_parts.append(f"High: {confidence_counts['High']}")
        if confidence_counts['Medium'] > 0:
            stats_parts.append(f"Medium: {confidence_counts['Medium']}")
        if confidence_counts['Low'] > 0:
            stats_parts.append(f"Low: {confidence_counts['Low']}")
        if tables_touched:
            stats_parts.append(f"Tables: {', '.join(sorted(tables_touched))}")
        entity_parts = []
        if target_devices:
            entity_parts.append(f"{len(target_devices)} device{'s' if len(target_devices) > 1 else ''}")
        if usernames:
            entity_parts.append(f"{len(usernames)} account{'s' if len(usernames) > 1 else ''}")
        if source_ips:
            entity_parts.append(f"{len(source_ips)} IP{'s' if len(source_ips) > 1 else ''}")
        if entity_parts:
            stats_parts.append(f"Entities: {', '.join(entity_parts)}")
        
        if stats_parts:
            print(f"{Fore.LIGHTBLACK_EX}Stats: {Fore.WHITE}{' | '.join(stats_parts)}")
        
        # CORRELATED ACTIONS (based on observed IOCs/entities)
        public_ips = [ip for ip in ioc_summary.get('ip', []) if not _is_private_ip(ip)]
        has_domains = len(ioc_summary.get('domain', [])) > 0
        has_hashes = len(ioc_summary.get('hash', [])) > 0
        has_accounts = len(usernames) > 0
        has_devices = len(target_devices) > 0
        
        if public_ips or has_domains or has_hashes or has_accounts or has_devices or source_ips:
            print(f"\n{Fore.LIGHTGREEN_EX}CORRELATED ACTIONS:")
            # Network perimeter
            if public_ips:
                print(f"{Fore.WHITE}• Block public IPs at perimeter (sample): {', '.join(sorted(public_ips)[:5])}")
            # DNS
            if has_domains:
                domain_sample = sorted(list(ioc_summary['domain']))[:5]
                print(f"{Fore.WHITE}• Add suspicious domains to DNS blocklist/sinkhole (sample): {', '.join(domain_sample)}")
            # Endpoint
            if has_hashes:
                print(f"{Fore.WHITE}• Push EDR scan/isolation; search for file hashes; deploy YARA rules")
            # Identity
            if has_accounts:
                account_sample = sorted(list(usernames))[:3]
                print(f"{Fore.WHITE}• Reset creds and revoke sessions for impacted accounts (sample): {', '.join(account_sample)}")
            # Host containment
            if has_devices:
                device_sample = sorted(list(target_devices))[:3]
                print(f"{Fore.WHITE}• Isolate high-risk devices pending triage (sample): {', '.join(device_sample)}")
            # Hunting pivots
            if source_ips:
                print(f"{Fore.WHITE}• Pivot hunt: peer devices and same-source IP activity across SigninLogs/DeviceNetworkEvents (last 24–72h)")
        
        print(f"\n{Fore.LIGHTYELLOW_EX}RECOMMENDED IMMEDIATE ACTIONS:")
        print(f"{Fore.WHITE}1. Isolate affected devices and accounts")
        print(f"{Fore.WHITE}2. Reset passwords for targeted accounts")
        print(f"{Fore.WHITE}3. Block source IPs at network perimeter")
        print(f"{Fore.WHITE}4. Review authentication logs for successful compromises")
        print(f"{Fore.WHITE}5. Scan for additional persistence mechanisms")
        print(f"{Fore.WHITE}{'='*60}\n")
        
    else:
        print(f"\n{Fore.LIGHTGREEN_EX}INVESTIGATIVE ASSESSMENT:")
        print(f"{Fore.WHITE}No suspicious activity patterns detected in the analyzed timeframe.")
        print(f"{Fore.WHITE}The environment appears to be operating within normal baseline parameters.")
        print(f"{Fore.WHITE}Continue routine monitoring and consider expanding detection coverage if needed.\n")
    
    # Check if human review is needed based on confidence
    if threat_list:
        confidence_scores = []
        for threat in threat_list:
            conf = threat.get('confidence', 'Low').lower()
            score = {'low': 3, 'medium': 5, 'high': 8}.get(conf, 5)
            confidence_scores.append(score)
        
        avg_conf = sum(confidence_scores) / len(confidence_scores)
        needs_review, reason = feedback_mgr.should_escalate_to_human('Medium', avg_conf)
        
        if needs_review:
            print(f"{Fore.LIGHTYELLOW_EX}⚠ HUMAN CHECK RECOMMENDED: {reason}{Fore.RESET}\n")
    
    # Get tuning recommendations
    tuning = feedback_mgr.get_tuning_recommendations()
    if tuning:
        print(f"{Fore.LIGHTCYAN_EX}{'─'*60}")
        print(f"{Fore.LIGHTCYAN_EX}DETECTION TUNING SUGGESTIONS (from past feedback)")
        print(f"{Fore.LIGHTCYAN_EX}{'─'*60}")
        for rec in tuning:
            print(f"{Fore.YELLOW}• {rec}{Fore.RESET}")
        print(f"{Fore.LIGHTCYAN_EX}{'─'*60}\n")
    
    # Prompt for user feedback (AFTER INVESTIGATIVE CONCLUSION)
    feedback_mgr.prompt_user_feedback()
    
    # Update learning based on feedback (for local models only)
    import LEARNING_ENGINE
    learning_engine = LEARNING_ENGINE.get_learning_engine()
    learning_engine.update_from_feedback()
    
    append_threats_to_jsonl(threat_list=threat_list)

def append_threats_to_jsonl(threat_list, filename="_threats.jsonl"):
    count = 0
    with open(filename, "a", encoding="utf-8") as f:
        for threat in threat_list:
            json_line = json.dumps(threat, ensure_ascii=False)
            f.write(json_line + "\n")
            count += 1
        print(f"{Fore.LIGHTBLUE_EX}\nLogged {count} threats to {filename}.\n")

def sanitize_literal(s: str) -> str:
    return str(s).replace("|", " ").replace("\n", " ").replace(";", " ")

def sanitize_query_context(query_context):
    if 'caller' not in query_context:
        query_context['caller'] = ''
    
    if 'device_name' not in query_context:
        query_context['device_name'] = ''

    if 'user_principal_name' not in query_context:
        query_context['user_principal_name'] = ''
    
    if 'start_date' not in query_context:
        query_context['start_date'] = None
    
    if 'end_date' not in query_context:
        query_context['end_date'] = None

    if 'device_name' in query_context:
        query_context['device_name'] = sanitize_literal(query_context['device_name'])

    if 'caller' in query_context:
        query_context['caller'] = sanitize_literal(query_context['caller'])

    if "user_principal_name" in query_context:
        query_context['user_principal_name'] = sanitize_literal(query_context['user_principal_name'])

    query_context["fields"] = ', '.join(query_context["fields"])
    
    return query_context


def enrich_findings_with_entities_and_vectors(findings):
    """Add inferred attack_vector and summarize top devices/accounts.

    - Preserves existing fields
    - Adds per-finding 'attack_vector'
    - Returns (enriched_findings, summary_dict)
    """
    device_counts = {}
    account_counts = {}

    def infer_vector(f):
        tags = set((f.get('tags') or []))
        desc = (f.get('description') or '').lower()
        tech = ((f.get('mitre') or {}).get('technique') or '').lower()

        if 'impossible_travel' in tags or 't1078' in tech:
            return 'Credential misuse / Account takeover'
        if 'powershell_obfuscation' in tags or 't1059' in tech:
            return 'Scripted execution / Living-off-the-land'
        if 'lateral_movement' in tags or 't1021' in tech:
            return 'Lateral movement'
        if 'defense_evasion' in tags or 't1562' in tech:
            return 'Defense evasion'
        if 'data_exfiltration' in tags or 't1041' in tech:
            return 'Data exfiltration'
        if 'lolbins' in tags or 't1218' in tech:
            return 'Signed binary proxy execution'
        if 'ransomware' in tags or 't1486' in tech:
            return 'Impact: Data encrypted'
        if 'network_suspicious' in tags or 't1071' in tech:
            return 'C2 or suspicious egress'
        if 'reconnaissance' in tags or 't1046' in tech:
            return 'Reconnaissance'
        if 'credential' in desc:
            return 'Credential access/misuse'
        return 'Uncategorized'

    enriched = []
    for f in findings or []:
        if f.get('device_name'):
            device_counts[f['device_name']] = device_counts.get(f['device_name'], 0) + 1
        if f.get('account_name'):
            account_counts[f['account_name']] = account_counts.get(f['account_name'], 0) + 1

        if not f.get('attack_vector'):
            f['attack_vector'] = infer_vector(f)
        enriched.append(f)

    summary = {
        'top_devices': sorted(device_counts.items(), key=lambda x: x[1], reverse=True)[:5],
        'top_accounts': sorted(account_counts.items(), key=lambda x: x[1], reverse=True)[:5],
    }

    return enriched, summary
