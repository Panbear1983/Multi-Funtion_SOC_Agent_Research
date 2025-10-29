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
        
        # Summary assessment
        print(f"\n{Fore.LIGHTCYAN_EX}ASSESSMENT:")
        if len(threat_list) > 3:
            print(f"{Fore.WHITE}This appears to be a coordinated attack campaign with multiple attack vectors.")
        elif any('High' in str(t.get('confidence', '')) for t in threat_list):
            print(f"{Fore.WHITE}High-confidence threats indicate active compromise requiring immediate response.")
        else:
            print(f"{Fore.WHITE}Suspicious activity detected that warrants further investigation and monitoring.")
        
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
