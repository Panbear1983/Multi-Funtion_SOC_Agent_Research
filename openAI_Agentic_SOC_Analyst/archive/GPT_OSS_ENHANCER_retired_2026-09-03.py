import re
import json
from color_support import Fore
import OLLAMA_CLIENT
import LEARNING_ENGINE
import GUARDRAILS

class GptOssEnhancer:
    def __init__(self, severity_multiplier=1.0, openai_client=None, 
                 use_gpt_refinement=False, refinement_model="gpt-4o"):
        """
        GPT-OSS Enhancer optimized for 32K token limit.
        Focuses on high-confidence patterns with self-learning.
        """
        self.severity_multiplier = severity_multiplier
        
        # Load learning engine for pattern weight adjustment (cached globally)
        self.learning_engine = LEARNING_ENGINE.get_learning_engine()
        self.pattern_weights = self.learning_engine.weights if self.learning_engine else {}
        
        # GUARDRAILS integration for defense-in-depth security
        self.allowed_tables = GUARDRAILS.ALLOWED_TABLES
        self.guardrails_enabled = True  # Can be disabled if needed
        self.validation_log = []  # Track validation events
        
        # GPT refinement configuration (hybrid mode)
        self.openai_client = openai_client
        self.use_gpt_refinement = use_gpt_refinement
        self.refinement_model = refinement_model
        
        # Expanded patterns for better detection coverage
        self.suspicious_patterns = {
            'credential_dumping': [
                r'lsass\.exe',
                r'procdump.*lsass',
                r'mimikatz',
                r'sekurlsa::',
                r'pwdump',
                r'wdigest::',
                r'kerberos::',
                r'cachedump'
            ],
            'powershell_obfuscation': [
                r'powershell.*-enc',
                r'powershell.*-e\s+',
                r'iex\s*\(',
                r'invoke-expression',
                r'base64.*decode',
                r'powershell.*-windowstyle.*hidden',
                r'powershell.*-nop'
            ],
            'lateral_movement': [
                r'wmic.*/node:',
                r'psexec.*\\\\',
                r'at.*\\\\',
                r'schtasks.*/s.*\\\\',
                r'net\s+use.*\\\\',
                r'smbclient',
                r'crackmapexec'
            ],
            'privilege_escalation': [
                r'uac.*bypass',
                r'getsystem',
                r'steal_token',
                r'whoami.*/priv',
                r'impersonate_token',
                r'getprivs'
            ],
            'persistence_registry': [
                r'reg.*add.*HKLM.*Run',
                r'reg.*add.*HKCU.*Run',
                r'reg.*add.*HKLM.*Services',
                r'reg.*add.*HKLM.*RunOnce',
                r'reg.*add.*HKCU.*RunOnce'
            ],
            'defense_evasion': [
                r'disable.*firewall',
                r'disable.*defender',
                r'disable.*antivirus',
                r'reg.*add.*HKLM.*DisableAntiSpyware',
                r'netsh.*firewall.*off',
                r'reg.*add.*HKLM.*DisableRealtimeMonitoring'
            ],
            'suspicious_commands': [
                r'net\s+user.*\/add',
                r'net\s+localgroup.*administrators.*\/add',
                r'schtasks.*\/create',
                r'wmic.*process.*call.*create',
                r'net\s+share.*\/add',
                r'sc\s+create'
            ],
            'data_exfiltration': [
                r'ftp.*put',
                r'7z.*a.*archive',
                r'winrar.*a.*archive',
                r'zip.*-r.*archive',
                r'scp.*-r',
                r'rsync.*-av'
            ],
            'lolbins': [
                r'rundll32\.exe',
                r'regsvr32\.exe',
                r'mshta\.exe',
                r'certutil\.exe',
                r'bitsadmin\.exe',
                r'wscript\.exe',
                r'cscript\.exe'
            ],
            'ransomware': [
                r'encrypt.*files',
                r'ransomware',
                r'delete.*files',
                r'\.locked$',
                r'\.encrypted$',
                r'format.*disk'
            ],
            'network_suspicious': [
                r'port\s+(4444|8080|9999|31337)',
                r'nc\s+-l',
                r'netcat',
                r'ssh.*-R',
                r'tor.*proxy'
            ],
            'reconnaissance': [
                r'nmap.*-sS',
                r'nmap.*-sV',
                r'netstat.*-an',
                r'net.*view',
                r'net.*user',
                r'net.*group'
            ],
            'file_operations': [
                r'\.exe.*temp',
                r'\.bat.*temp',
                r'\.ps1.*temp',
                r'copy.*\.exe',
                r'move.*\.exe'
            ],
            'impossible_travel': [
                r'impossible.*travel',
                r'geographically.*distant',
                r'atypical.*location',
                r'unusual.*location',
                r'risky.*sign.*in',
                r'suspicious.*location'
            ]
        }
        
        # IOC patterns - Only extract device and account names (most useful for investigation)
        self.ioc_patterns = {
            # ENABLED: Extract all IOC types for threat hunting
            'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'hash': r'\b[a-fA-F0-9]{32,64}\b',
            'domain': r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'device_name': None,  # Extracted via CSV parsing
            'account_name': None  # Extracted via CSV parsing
        }
        
        # Core MITRE mappings - most critical techniques
        self.mitre_mappings = {
            'credential_dumping': {
                'tactic': 'Credential Access',
                'technique': 'T1003.001',
                'description': 'OS Credential Dumping: LSASS Memory'
            },
            'powershell_obfuscation': {
                'tactic': 'Execution',
                'technique': 'T1059.001',
                'description': 'PowerShell'
            },
            'lateral_movement': {
                'tactic': 'Lateral Movement',
                'technique': 'T1021',
                'description': 'Remote Services'
            },
            'privilege_escalation': {
                'tactic': 'Privilege Escalation',
                'technique': 'T1548.002',
                'description': 'Bypass User Account Control'
            },
            'persistence_registry': {
                'tactic': 'Persistence',
                'technique': 'T1547.001',
                'description': 'Registry Run Keys'
            },
            'defense_evasion': {
                'tactic': 'Defense Evasion',
                'technique': 'T1562.001',
                'description': 'Disable Security Tools'
            },
            'suspicious_commands': {
                'tactic': 'Persistence',
                'technique': 'T1053.005',
                'description': 'Scheduled Task'
            },
            'data_exfiltration': {
                'tactic': 'Exfiltration',
                'technique': 'T1041',
                'description': 'Exfiltration Over C2'
            },
            'lolbins': {
                'tactic': 'Defense Evasion',
                'technique': 'T1218',
                'description': 'Signed Binary Proxy Execution'
            },
            'ransomware': {
                'tactic': 'Impact',
                'technique': 'T1486',
                'description': 'Data Encrypted for Impact'
            },
            'network_suspicious': {
                'tactic': 'Command and Control',
                'technique': 'T1071',
                'description': 'Application Layer Protocol'
            },
            'reconnaissance': {
                'tactic': 'Discovery',
                'technique': 'T1046',
                'description': 'Network Service Scanning'
            },
            'file_operations': {
                'tactic': 'Persistence',
                'technique': 'T1547.001',
                'description': 'Boot or Logon Autostart Execution'
            },
            'impossible_travel': {
                'tactic': 'Initial Access',
                'technique': 'T1078.004',
                'description': 'Valid Accounts: Cloud Accounts'
            }
        }

    def analyze_logs_with_rules(self, log_data, table_name):
        """Balanced filtering for 8K token limit"""
        findings = []
        log_lines = log_data.split('\n')[:100]  # Increased to 100 lines
        
        print(f"{Fore.LIGHTGREEN_EX}Applying rule-based threat detection (GPT-OSS optimized)...")
        
        high_priority_findings = []
        medium_priority_findings = []
        
        # Detect impossible travel from SigninLogs
        if table_name in ['SigninLogs', 'Unknown']:
            impossible_travel_findings = self._detect_impossible_travel(log_lines)
            high_priority_findings.extend(impossible_travel_findings)
        
        for line_num, line in enumerate(log_lines, 1):
            if not line.strip():
                continue
                
            for category, patterns in self.suspicious_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        finding = self._create_finding(line, line_num, category, pattern, table_name)
                        # Prioritize by severity
                        if category in ['credential_dumping', 'lateral_movement', 'ransomware', 'privilege_escalation', 'impossible_travel']:
                            high_priority_findings.append(finding)
                        elif category in ['powershell_obfuscation', 'defense_evasion', 'data_exfiltration']:
                            medium_priority_findings.append(finding)
                        else:
                            findings.append(finding)
                        break
        
        # Prioritize findings by severity
        all_findings = high_priority_findings + medium_priority_findings + findings
        
        # Apply severity multiplier
        if self.severity_multiplier > 1.0:
            all_findings = all_findings[:int(len(all_findings) * self.severity_multiplier)]
        
        # Extract IOCs
        iocs = self._extract_iocs(log_data[:10000])  # Increased to 10000 chars
        
        # Create IOC findings if no pattern matches
        if len(all_findings) == 0 and iocs:
            ioc_findings = self._create_ioc_findings(iocs, table_name)
            all_findings.extend(ioc_findings)
        
        print(f"{Fore.WHITE}Rule-based analysis found {len(all_findings)} suspicious patterns and {len(iocs)} IOCs")
        
        return all_findings[:20], iocs  # Increased to max 20 findings

    def _create_finding(self, line, line_num, category, pattern, table_name):
        """Create compact finding structure with learned weight adjustment"""
        mitre_info = self.mitre_mappings.get(category, {
            'tactic': 'Unknown',
            'technique': 'T0000',
            'description': 'Unknown technique'
        })
        
        # Set base confidence based on category
        base_confidence = 'High' if category in ['credential_dumping', 'lateral_movement', 'ransomware'] else 'Medium'
        
        # Apply learned weight to adjust confidence
        learned_weight = self.pattern_weights.get(category, 1.0)
        
        # Adjust confidence based on learned weight
        if learned_weight >= 1.5 and base_confidence == 'Medium':
            confidence = 'High'  # Boost to High if pattern has proven valuable
        elif learned_weight <= 0.5:
            confidence = 'Low'  # Downgrade if pattern often wrong
        else:
            confidence = base_confidence
        
        return {
            'title': f"Suspicious {category.replace('_', ' ').title()}",
            'description': f"Detected pattern '{pattern}' indicating {category.replace('_', ' ')}.",
            'mitre': {
                'tactic': mitre_info['tactic'],
                'technique': mitre_info['technique'],
                'sub_technique': mitre_info['technique'],
                'id': mitre_info['technique'],
                'description': mitre_info['description']
            },
            'log_lines': [line.strip()[:200]],  # Truncate long lines
            'confidence': confidence,
            'recommendations': ['investigate', 'escalate'] if confidence == 'High' else ['monitor'],
            'indicators_of_compromise': self._extract_iocs_from_line(line)[:5],  # Max 5 IOCs
            'tags': [category],
            'notes': f"Pattern: {pattern}"
        }

    def _extract_iocs(self, log_data):
        """Lightweight IOC extraction with device/account parsing"""
        iocs = {}
        
        # Extract pattern-based IOCs (IPs, hashes)
        for ioc_type, pattern in self.ioc_patterns.items():
            if pattern is None:
                continue
            matches = re.findall(pattern, log_data)
            if matches:
                clean_matches = []
                for match in matches[:20]:  # Max 20 per type
                    if isinstance(match, tuple):
                        clean_matches.extend([m for m in match if m])
                    else:
                        clean_matches.append(match)
                iocs[ioc_type] = list(set(clean_matches))[:10]  # Max 10 unique
        
        # Extract device names and account names from CSV log lines
        device_names = set()
        account_names = set()
        
        log_lines = log_data.split('\n')
        for line in log_lines[:50]:  # Parse first 50 lines
            parts = line.split(',')
            if len(parts) >= 3:
                # CSV format: timestamp, accountname, devicename, ...
                account = parts[1].strip() if len(parts) > 1 else ''
                device = parts[2].strip() if len(parts) > 2 else ''
                
                if account and account not in ['AccountName']:
                    account_names.add(account)
                
                if device and device not in ['DeviceName']:
                    device_names.add(device)
        
        if device_names:
            iocs['device_name'] = list(device_names)[:10]
        if account_names:
            iocs['account_name'] = list(account_names)[:10]
        
        return iocs

    def _extract_iocs_from_line(self, line):
        """Extract IOCs from single line including device/account names"""
        iocs = []
        
        # Extract pattern-based IOCs
        for ioc_type, pattern in self.ioc_patterns.items():
            if pattern is None:
                continue
            matches = re.findall(pattern, line)
            for match in matches[:3]:  # Max 3
                if isinstance(match, tuple):
                    iocs.extend([m for m in match if m])
                else:
                    iocs.append(match)
        
        # Parse CSV format to extract device and account names
        parts = line.split(',')
        if len(parts) >= 3:
            account = parts[1].strip() if len(parts) > 1 else ''
            device = parts[2].strip() if len(parts) > 2 else ''
            
            if account and account not in ['AccountName']:
                iocs.append(f"Account: {account}")
            
            if device and device not in ['DeviceName']:
                iocs.append(f"Device: {device}")
        
        return list(set(iocs))[:8]  # Increased to 8 to include device/account


    def _parse_structured_fields_from_csv_line(self, line, csv_col_indices=None):
        """Extract device/account/ip from CSV line using common column names."""
        device_name = None
        account_name = None
        remote_ip = None

        parts = line.split(',') if isinstance(line, str) else []

        if csv_col_indices:
            for col_name in ['DeviceName', 'VM_s', 'Computer']:
                if col_name in csv_col_indices:
                    idx = csv_col_indices[col_name]
                    if idx < len(parts):
                        value = parts[idx].strip()
                        if value:
                            device_name = value
                            break
            for col_name in ['AccountName', 'Caller', 'UserPrincipalName']:
                if col_name in csv_col_indices:
                    idx = csv_col_indices[col_name]
                    if idx < len(parts):
                        value = parts[idx].strip()
                        if value:
                            account_name = value
                            break
            for col_name in ['RemoteIP', 'SrcPublicIPs_s', 'DestIP_s', 'IPAddress', 'CallerIpAddress']:
                if col_name in csv_col_indices:
                    idx = csv_col_indices[col_name]
                    if idx < len(parts):
                        ip_val = parts[idx].strip()
                        if re.match(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', ip_val):
                            remote_ip = ip_val
                            break

        return device_name, account_name, remote_ip


    def _detect_impossible_travel(self, log_lines):
        """Detect impossible travel patterns in authentication logs"""
        findings = []
        login_events = []
        
        # Parse login events with timestamps, users, and IPs/locations
        for line in log_lines:
            # Look for patterns indicating authentication with location info
            # Common formats: timestamp, user, IP, location, result
            parts = line.split(',')
            if len(parts) >= 5:
                try:
                    timestamp = parts[0].strip()
                    user = parts[1].strip() if len(parts) > 1 else ''
                    ip = parts[4].strip() if len(parts) > 4 else ''
                    
                    # Check if this looks like a login event
                    if user and ip and ('logon' in line.lower() or 'signin' in line.lower() or 'login' in line.lower()):
                        login_events.append({
                            'timestamp': timestamp,
                            'user': user,
                            'ip': ip,
                            'line': line
                        })
                except:
                    continue
        
        # Analyze for impossible travel (same user, different IPs in short timeframe)
        user_logins = {}
        for event in login_events:
            user = event['user']
            if user not in user_logins:
                user_logins[user] = []
            user_logins[user].append(event)
        
        # Check each user for suspicious patterns
        for user, events in user_logins.items():
            if len(events) < 2:
                continue
            
            # Look for different IPs within short timeframe
            for i in range(len(events) - 1):
                event1 = events[i]
                event2 = events[i + 1]
                
                # Check if IPs are different
                if event1['ip'] != event2['ip'] and event1['ip'] and event2['ip']:
                    # Check if IPs are from different geographic regions (simple heuristic)
                    ip1_parts = event1['ip'].split('.')
                    ip2_parts = event2['ip'].split('.')
                    
                    # If first two octets differ significantly, might be different regions
                    if len(ip1_parts) >= 2 and len(ip2_parts) >= 2:
                        try:
                            if abs(int(ip1_parts[0]) - int(ip2_parts[0])) > 10:
                                finding = {
                                    'title': f"Potential Impossible Travel for User: {user}",
                                    'description': f"User '{user}' authenticated from two different IP addresses ({event1['ip']} and {event2['ip']}) in rapid succession, suggesting account compromise or credential sharing.",
                                    'mitre': {
                                        'tactic': 'Initial Access',
                                        'technique': 'T1078.004',
                                        'sub_technique': 'T1078.004',
                                        'id': 'T1078.004',
                                        'description': 'Valid Accounts: Cloud Accounts'
                                    },
                                    'log_lines': [event1['line'][:200], event2['line'][:200]],
                                    'confidence': 'High',
                                    'recommendations': ['investigate', 'escalate', 'reset password'],
                                    'indicators_of_compromise': [event1['ip'], event2['ip'], user],
                                    'tags': ['impossible_travel', 'credential_compromise'],
                                    'notes': f"Detected geographically distant logins: {event1['ip']} → {event2['ip']}"
                                }
                                findings.append(finding)
                        except:
                            continue
        
        return findings[:5]  # Limit to 5 impossible travel findings

    def _create_ioc_findings(self, iocs, table_name):
        """Create findings from IOCs (prioritize actionable IOCs)"""
        findings = []
        
        # Only show device names and account names - most contextual and useful
        # EXPANDED: Report all IOC types, not just device/account
        ioc_priority = ['ip_address', 'hash', 'domain', 'email', 'device_name', 'account_name']
        
        for ioc_type in ioc_priority:
            if ioc_type not in iocs or not iocs[ioc_type]:
                continue
                
            values = iocs[ioc_type]
            display_values = values
            hash_note = ""
            
            # Format IOCs with field name labels
            if ioc_type == 'device_name':
                labeled_iocs = [f"DeviceName: {v}" for v in display_values]
            elif ioc_type == 'account_name':
                labeled_iocs = [f"AccountName: {v}" for v in display_values]
            else:
                labeled_iocs = [f"{ioc_type.replace('_', ' ').title()}: {v}" for v in display_values]
                
            finding = {
                'title': f"Potential {ioc_type.replace('_', ' ').title()} Indicators Detected",
                'description': f"Found {len(values)} {ioc_type.replace('_', ' ')} indicators in logs{hash_note}.",
                'mitre': {
                    'tactic': 'Reconnaissance',
                    'technique': 'T1590',
                    'sub_technique': 'T1590.001',
                    'id': 'T1590.001',
                    'description': 'Gather Victim Host Information'
                },
                'log_lines': [f"Found {ioc_type}: {', '.join(str(v) for v in display_values[:3])}"],  # Show first 3
                'confidence': 'Low',
                'recommendations': ['monitor', 'investigate'],
                'indicators_of_compromise': labeled_iocs,  # Display with field name labels
                'tags': ['ioc-detection', ioc_type],
                'notes': f"Detected {len(values)} {ioc_type.replace('_', ' ')} indicators{hash_note}."
            }
            findings.append(finding)
        
        return findings
    
    def _detect_table_from_csv(self, csv_text):
        """
        Detect which table the CSV data came from based on column headers
        """
        # Extract first line (headers)
        lines = csv_text.strip().split('\n')
        if len(lines) < 2:
            return "Unknown"
        
        headers = lines[0].lower()
        
        # Table signatures (unique field combinations)
        table_signatures = {
            'DeviceProcessEvents': ['processcommandline', 'initiatingprocesscommandline'],
            'DeviceNetworkEvents': ['remoteip', 'remoteport'],
            'DeviceLogonEvents': ['logontype', 'accountname', 'remoteip'],
            'DeviceFileEvents': ['filename', 'folderpath', 'sha256'],
            'DeviceRegistryEvents': ['registrykey', 'registryvaluename'],
            'AlertInfo': ['alertid', 'title', 'severity', 'status'],
            'AlertEvidence': ['alertid', 'evidencetype', 'evidencevalue'],
            'SigninLogs': ['userprincipalname', 'appdisplayname'],
            'AuditLogs': ['operationname', 'category', 'result', 'initiatedby'],
            'AzureActivity': ['operationnamevalue', 'caller'],
            'AzureNetworkAnalytics_CL': ['flowtype_s', 'srcpublicips_s'],
            'AzureNetworkAnalyticsIPDetails_CL': ['publicipaddress_s', 'publicipdetails_s', 'organization_s']
        }
        
        # Find best match
        for table_name, signature_fields in table_signatures.items():
            matches = sum(1 for field in signature_fields if field in headers)
            if matches >= len(signature_fields) - 1:  # Allow 1 missing field
                return table_name
        
        return "Unknown"
    
    def _validate_and_filter_fields(self, csv_text, table_name):
        """
        Validate CSV fields against GUARDRAILS and filter out unauthorized fields
        """
        if table_name == "Unknown":
            print(f"{Fore.YELLOW}[GPT_OSS_ENHANCER] Could not detect table - proceeding with caution{Fore.RESET}")
            return csv_text, True  # Allow but warn
        
        if table_name not in self.allowed_tables:
            print(f"{Fore.RED}[GPT_OSS_ENHANCER] ⚠️  BLOCKED: Table '{table_name}' not in GUARDRAILS.ALLOWED_TABLES{Fore.RESET}")
            self.validation_log.append({'table': table_name, 'action': 'BLOCKED', 'reason': 'Not in ALLOWED_TABLES'})
            return "", False  # Reject
        
        # Parse CSV headers
        lines = csv_text.strip().split('\n')
        if len(lines) < 2:
            return csv_text, True
        
        headers = lines[0].split(',')
        allowed_fields = self.allowed_tables[table_name]
        
        # Check each field
        unauthorized_fields = []
        authorized_indices = []
        
        for idx, header in enumerate(headers):
            header_clean = header.strip()
            if header_clean in allowed_fields:
                authorized_indices.append(idx)
            else:
                unauthorized_fields.append(header_clean)
        
        # Log unauthorized fields
        if unauthorized_fields:
            print(f"{Fore.YELLOW}[GPT_OSS_ENHANCER] Filtering out {len(unauthorized_fields)} unauthorized fields: {', '.join(unauthorized_fields[:3])}{'...' if len(unauthorized_fields) > 3 else ''}{Fore.RESET}")
        
        # If all fields unauthorized, reject
        if not authorized_indices:
            print(f"{Fore.RED}[GPT_OSS_ENHANCER] ⚠️  BLOCKED: No authorized fields in data{Fore.RESET}")
            return "", False
        
        # Filter CSV to only include authorized fields
        filtered_lines = []
        for line in lines:
            parts = line.split(',')
            filtered_parts = [parts[i] for i in authorized_indices if i < len(parts)]
            filtered_lines.append(','.join(filtered_parts))
        
        filtered_csv = '\n'.join(filtered_lines)
        
        print(f"{Fore.LIGHTGREEN_EX}[GPT_OSS_ENHANCER] ✓ Validated: {table_name} with {len(authorized_indices)} authorized fields{Fore.RESET}")
        return filtered_csv, True

    def enhanced_hunt(self, messages, model_name="gpt-oss:20b", max_lines=30, investigation_context=None):
        """Optimized hunt for 32K token limit with aggressive slicing"""
        print(f"{Fore.LIGHTGREEN_EX}Starting GPT-OSS enhanced threat hunt (32K token optimized)...")
        
        # Check if CTF mode
        is_ctf_mode = investigation_context and investigation_context.get('mode') == 'ctf'
        
        # Extract and truncate log data VERY aggressively for GPT-OSS
        log_data = ""
        for msg in messages:
            if "Log Data:" in msg.get("content", ""):
                full_log = msg["content"].split("Log Data:")[-1].strip()
                # CRITICAL: GPT-OSS can only handle ~25 lines max to stay under 32K tokens
                # Adjust max_lines to be very conservative
                safe_max_lines = min(max_lines, 20)  # Never exceed 20 lines for GPT-OSS
                log_lines = full_log.split('\n')[:safe_max_lines]
                log_data = '\n'.join(log_lines)
                print(f"{Fore.YELLOW}⚠️  Sliced logs to {safe_max_lines} lines to fit 32K token limit")
                break
        
        if not log_data:
            print(f"{Fore.YELLOW}No log data found, using standard LLM analysis")
            return self._standard_llm_analysis(messages, model_name)
        
        # GUARDRAILS VALIDATION: Validate table and filter fields
        if self.guardrails_enabled:
            # Detect table from CSV
            detected_table = self._detect_table_from_csv(log_data)
            
            # Validate and filter
            filtered_log_data, is_valid = self._validate_and_filter_fields(log_data, detected_table)
            
            if not is_valid:
                # Data rejected by GUARDRAILS - create violation finding
                print(f"{Fore.RED}[GPT_OSS_ENHANCER] GUARDRAILS blocked unauthorized data access{Fore.RESET}")
                return {
                    "findings": [{
                        "title": "GUARDRAILS Security Violation - GPT-OSS Enhancer",
                        "description": f"Attempted to process unauthorized data from table: {detected_table}. GUARDRAILS enforcement prevented this security violation.",
                        "confidence": "High",
                        "mitre": {
                            "tactic": "Defense Evasion",
                            "technique": "T1562",
                            "sub_technique": "T1562.001",
                            "id": "T1562.001",
                            "description": "Impair Defenses: Disable or Modify Tools - GUARDRAILS bypass attempt blocked"
                        },
                        "log_lines": [
                            "SECURITY ALERT: Unauthorized data access attempt",
                            f"Attempted table: {detected_table}",
                            f"Status: BLOCKED by GUARDRAILS"
                        ],
                        "indicators_of_compromise": [
                            f"Unauthorized table access: {detected_table}",
                            "Violation logged to validation log"
                        ],
                        "tags": ["security_violation", "guardrails_enforcement", "unauthorized_access", "defense_evasion"],
                        "recommendations": [
                            "Investigate who/what initiated this unauthorized query",
                            "Review access logs for suspicious patterns",
                            "Verify GUARDRAILS configuration is up to date",
                            "Consider implementing additional access controls"
                        ],
                        "notes": f"GPT_OSS_ENHANCER GUARDRAILS enforcement blocked unauthorized table: {detected_table}. This is a defense-in-depth security measure."
                    }]
                }
            
            # Use filtered data for analysis
            log_data = filtered_log_data
        
        # Apply rule-based analysis
        rule_findings, iocs = self.analyze_logs_with_rules(log_data, "Unknown")
        
        # Build compact prompt (preserve system message guardrail like OpenAI/Qwen)
        compact_messages = self._build_compact_prompt(messages, rule_findings, iocs, log_data, investigation_context, model_name)
        
        # Get LLM analysis with streaming; salvage partial on cancel/error
        print(f"{Fore.LIGHTGREEN_EX}Analyzing with {model_name} (streaming)...")
        buffer = ""
        llm_findings = []
        try:
            for chunk in OLLAMA_CLIENT.chat_stream(messages=compact_messages, model_name=model_name):
                try:
                    obj = json.loads(chunk)
                    msg = (obj.get("message") or {}).get("content", "") or obj.get("response", "")
                    if msg:
                        buffer += msg
                except Exception:
                    buffer += chunk if isinstance(chunk, str) else ""
        except KeyboardInterrupt:
            print(f"{Fore.YELLOW}Cancelled by user. Returning partial results if possible.{Fore.RESET}")
        except Exception as e:
            print(f"{Fore.YELLOW}⚠️  LLM analysis timed out or failed: {e}")
            print(f"{Fore.WHITE}Falling back to rule-based findings + partial text if any...")

        if buffer.strip():
            # GPT-OSS specific: Validate and extract JSON before parsing
            validated_buffer = self._validate_gpt_oss_response(buffer, "ctf" if is_ctf_mode else "threat_hunt")
            retry_attempted = False
            
            try:
                # CTF mode: Use CTF parser
                if is_ctf_mode:
                    import RESPONSE_PARSER
                    ctf_result = RESPONSE_PARSER.parse_response(validated_buffer, "ctf")
                    # Convert CTF format to findings format for compatibility
                    llm_findings = []
                    if ctf_result.get("suggested_answer"):
                        llm_findings = [{
                            "title": f"CTF Answer: {ctf_result.get('suggested_answer', 'N/A')}",
                            "description": ctf_result.get("explanation", ""),
                            "confidence": ctf_result.get("confidence", "Low"),
                            "log_lines": [],
                            "indicators_of_compromise": [ctf_result.get("suggested_answer", "")],
                            "tags": ["ctf", "flag-answer"],
                            "notes": f"Evidence rows: {ctf_result.get('evidence_rows', [])}, Fields: {ctf_result.get('evidence_fields', [])}",
                            "_ctf_analysis": ctf_result  # Store full CTF result for later use
                        }]
                    else:
                        llm_findings = []
                else:
                    # Default threat hunt format
                    llm_results = json.loads(validated_buffer)
                    llm_findings = llm_results.get("findings", [])
            except json.JSONDecodeError as e:
                # GPT-OSS specific: Retry with stricter prompt (max 1 retry)
                if not retry_attempted:
                    retry_buffer = self._retry_with_stricter_prompt(compact_messages, model_name, str(e), investigation_context)
                    if retry_buffer:
                        retry_attempted = True
                        try:
                            if is_ctf_mode:
                                import RESPONSE_PARSER
                                ctf_result = RESPONSE_PARSER.parse_response(retry_buffer, "ctf")
                                llm_findings = []
                                if ctf_result.get("suggested_answer"):
                                    llm_findings = [{
                                        "title": f"CTF Answer: {ctf_result.get('suggested_answer', 'N/A')}",
                                        "description": ctf_result.get("explanation", ""),
                                        "confidence": ctf_result.get("confidence", "Low"),
                                        "log_lines": [],
                                        "indicators_of_compromise": [ctf_result.get("suggested_answer", "")],
                                        "tags": ["ctf", "flag-answer"],
                                        "notes": f"Evidence rows: {ctf_result.get('evidence_rows', [])}, Fields: {ctf_result.get('evidence_fields', [])}",
                                        "_ctf_analysis": ctf_result
                                    }]
                            else:
                                llm_results = json.loads(retry_buffer)
                                llm_findings = llm_results.get("findings", [])
                        except json.JSONDecodeError:
                            # Retry also failed, fall through to extraction
                            pass
                
                # GPT-OSS specific: Enhanced extraction fallback
                if not llm_findings:
                    if is_ctf_mode:
                        # Use GPT-OSS specific CTF extraction
                        ctf_result = self._extract_ctf_answer_from_text(buffer)
                        llm_findings = []
                        if ctf_result.get("suggested_answer"):
                            llm_findings = [{
                                "title": f"CTF Answer (extracted): {ctf_result.get('suggested_answer', 'N/A')}",
                                "description": ctf_result.get("explanation", ""),
                                "confidence": ctf_result.get("confidence", "Low"),
                                "log_lines": [],
                                "indicators_of_compromise": [ctf_result.get("suggested_answer", "")],
                                "tags": ["ctf", "flag-answer", "extracted"],
                                "notes": "Answer extracted from natural language response using pattern matching",
                                "_ctf_analysis": ctf_result
                            }]
                    else:
                        # Threat hunt fallback: extract entities
                        partial_text = buffer[-4000:]
                        devices = re.findall(r'(?:DeviceName|Computer)\s*[:=]\s*([A-Za-z0-9._-]{2,})', partial_text)
                        accounts = re.findall(r'(?:AccountName|User|UPN|UserPrincipalName)\s*[:=]\s*([A-Za-z0-9._@-]{3,})', partial_text)
                        finding = {
                            "title": "Partial LLM Analysis (incomplete)",
                            "description": "LLM response was interrupted. Partial text captured.",
                            "confidence": "Low",
                            "log_lines": [],
                            "indicators_of_compromise": [],
                            "tags": ["partial", "llm-analysis"],
                            "notes": partial_text
                        }
                        if devices:
                            finding["device_name"] = devices[0]
                        if accounts:
                            finding["account_name"] = accounts[0]
                        llm_findings = [finding]
        
        # For CTF mode, return CTF format directly
        if is_ctf_mode and llm_findings and llm_findings[0].get("_ctf_analysis"):
            ctf_result = llm_findings[0]["_ctf_analysis"]
            print(f"{Fore.WHITE}CTF analysis complete: Answer={ctf_result.get('suggested_answer', 'None')}, Confidence={ctf_result.get('confidence', 'Low')}")
            return ctf_result
        
        # Combine findings (prioritize rule-based for GPT-OSS)
        combined_findings = rule_findings + llm_findings
        
        # Deduplicate and limit
        final_findings = self._deduplicate_findings(combined_findings)[:25]  # Increased to max 25 total
        
        # Post-process: Boost confidence when evidence is strong (no token cost)
        final_findings = self._boost_confidence_if_evidence_strong(final_findings)
        
        # Optionally refine with GPT-4/5 for better quality (hybrid mode)
        if self.use_gpt_refinement and self.openai_client and final_findings:
            final_findings = self.refine_findings_with_gpt(final_findings)
        
        print(f"{Fore.WHITE}Enhanced analysis complete: {len(final_findings)} findings")
        
        return {"findings": final_findings}

    def apply_rule_based_patterns_to_csv(self, csv_text):
        """Apply rule-based patterns to CSV text and return findings and IOCs"""
        try:
            # Detect table name from CSV content
            table_name = self._detect_table_from_csv(csv_text)
            
            # Analyze logs with rules
            rule_findings = self.analyze_logs_with_rules(csv_text, table_name)
            
            # Extract IOCs from findings
            iocs = []
            for finding in rule_findings:
                if 'ioc' in finding and finding['ioc']:
                    iocs.append(finding['ioc'])
            
            return rule_findings, iocs
            
        except Exception as e:
            print(f"{Fore.YELLOW}Rule-based pattern analysis error: {e}{Fore.RESET}")
            return [], []

    def _build_compact_prompt(self, messages, rule_findings, iocs, log_data, investigation_context=None, model_name="gpt-oss:20b"):
        """
        Build token-efficient prompt while preserving system message guardrail.
        Follows same pattern as OpenAI/Qwen models - preserves role definition.
        """
        compact_messages = []
        
        # GUARDRAIL: Preserve original system message (same pattern as OpenAI/Qwen)
        # This maintains cybersecurity analyst role definition and CTF instructions
        original_system_msg = None
        original_user_msg = None
        
        for msg in messages:
            if msg.get("role") == "system":
                original_system_msg = msg
            elif msg.get("role") == "user":
                original_user_msg = msg
        
        # Preserve system message if it exists (contains role guardrail)
        if original_system_msg:
            # Check if we can add authority enhancement (token-aware)
            if self._can_add_authority_enhancement(compact_messages, model_name):
                enhanced_system_msg = self._enhance_system_prompt_authority(original_system_msg, model_name)
                compact_messages.append(enhanced_system_msg)
                print(f"{Fore.LIGHTGREEN_EX}[GPT_OSS] ✓ Preserved system message + authority enhancement{Fore.RESET}")
            else:
                compact_messages.append(original_system_msg)  # Use original if token budget tight
                print(f"{Fore.LIGHTGREEN_EX}[GPT_OSS] ✓ Preserved system message guardrail (token budget preserved){Fore.RESET}")
        else:
            # Fallback: Ultra-compact for GPT-OSS (32K limit - every token counts)
            fallback_msg = {
                "role": "system",
                "content": "Senior SOC Analyst. Confident threat assessments. Return JSON: {\"findings\": [{\"title\":\"\", \"description\":\"\", \"confidence\":\"\"}]}"
            }
            compact_messages.append(fallback_msg)
            print(f"{Fore.YELLOW}[GPT_OSS] ⚠️  No system message found, using ultra-compact fallback{Fore.RESET}")
        
        # Extract CTF context from original user message if available
        ctf_context = ""
        if investigation_context and investigation_context.get('mode') == 'ctf':
            flag_objective = investigation_context.get('flag_objective', '')
            expected_format = investigation_context.get('expected_format', 'any')
            if flag_objective:
                ctf_context = f"""
🎯 CTF FLAG OBJECTIVE: {flag_objective}
📋 EXPECTED FORMAT: {expected_format}

CRITICAL JSON FORMAT REQUIREMENT:
You MUST return ONLY valid JSON. No natural language explanations outside JSON.

REQUIRED JSON FORMAT:
{{
  "suggested_answer": "exact flag value matching expected format",
  "confidence": "High|Medium|Low",
  "evidence_rows": [0, 1],
  "evidence_fields": ["FieldName1", "FieldName2"],
  "explanation": "brief explanation of reasoning",
  "correlation": ""
}}

EXAMPLE VALID RESPONSE:
{{
  "suggested_answer": "192.168.1.100",
  "confidence": "High",
  "evidence_rows": [0],
  "evidence_fields": ["RemoteIP"],
  "explanation": "Most recent outbound connection to external IP",
  "correlation": ""
}}

IMPORTANT:
- Return ONLY the JSON object. No markdown, no code blocks, no explanations.
- Work with the AVAILABLE log data. Do NOT ask for more data.
- Extract the exact answer from the provided logs.
"""
        
        # Build optimized user message (preserve CTF context, optimize log data)
        context = ""
        
        # Preserve CTF context if present
        if ctf_context:
            context += ctf_context
        
        # Add rule findings summary (minimal to save tokens)
        if rule_findings:
            context += f"Rule-based analysis: {len(rule_findings)} patterns detected.\n"
        
        # Add IOC summary (minimal)
        if iocs:
            context += "IOCs: "
            ioc_summary = []
            for ioc_type, values in iocs.items():
                if values:
                    ioc_summary.append(f"{len(values)} {ioc_type}")
            if ioc_summary:
                context += ", ".join(ioc_summary) + "\n"
        
        # Optimize log data - preserve more for CTF mode (needs evidence)
        if investigation_context and investigation_context.get('mode') == 'ctf':
            # CTF mode: preserve more log data (up to 2000 chars) for flag inference
            max_log_chars = min(2000, len(log_data))
            context += f"\nLog Data ({len(log_data.split(chr(10)))} lines, showing first {max_log_chars} chars):\n{log_data[:max_log_chars]}"
            if len(log_data) > max_log_chars:
                context += f"\n... (truncated, {len(log_data)} total chars)"
        else:
            # Threat hunt mode: aggressive truncation (800 chars)
            context += f"\nLog Data ({len(log_data.split(chr(10)))} lines):\n{log_data[:800]}"
            if len(log_data) > 800:
                context += f"\n... (truncated for token optimization)"
        
        compact_messages.append({
            "role": "user",
            "content": context
        })
        
        return compact_messages

    def _can_add_authority_enhancement(self, messages, model_name):
        """Check if GPT-OSS has token budget for authority enhancement"""
        import MODEL_SELECTOR
        import TIME_ESTIMATOR
        
        if not MODEL_SELECTOR.AUTHORITY_ENHANCEMENT_ENABLED:
            return False
        
        # Only check for GPT-OSS (Qwen has 128K, no check needed)
        if model_name != "gpt-oss:20b":
            return True  # Qwen can always add
        
        # Estimate current token usage
        current_tokens = TIME_ESTIMATOR.estimate_tokens(messages, model_name)
        model_limit = TIME_ESTIMATOR.get_model_context_limit(model_name)
        
        # GPT-OSS: Need >5K headroom (conservative - 85% threshold)
        # Authority enhancement adds ~50 tokens
        threshold = model_limit * 0.85
        can_add = (current_tokens + 50) < threshold
        
        if not can_add:
            print(f"{Fore.YELLOW}[GPT_OSS] Skipping authority enhancement - token budget tight ({current_tokens:,}/{model_limit:,} tokens){Fore.RESET}")
        
        return can_add

    def _enhance_system_prompt_authority(self, system_msg, model_name):
        """Add authority framing - GPT-OSS uses ultra-compact version"""
        import MODEL_SELECTOR
        
        if not MODEL_SELECTOR.AUTHORITY_ENHANCEMENT_ENABLED:
            return system_msg
        
        # GPT-OSS: Ultra-compact (32K limit - every token counts)
        if model_name == "gpt-oss:20b":
            authority_header = "Senior SOC Analyst. Confident assessments based on evidence."
            # ~10 tokens - minimal but authoritative
        
        # Qwen: Full authority header (128K limit - can afford more)
        elif model_name in ["qwen", "qwen3:8b"]:
            authority_header = """You are a Senior SOC Analyst with 10+ years of threat hunting experience.
Provide confident, authoritative assessments based on evidence.
Take ownership of your findings."""
            # ~30 tokens - full authority framing
        
        else:
            return system_msg  # Unknown model, skip
        
        # Append to existing content (preserve original)
        original_content = system_msg.get('content', '')
        enhanced_content = authority_header + "\n\n" + original_content
        
        return {"role": "system", "content": enhanced_content}

    def _boost_confidence_if_evidence_strong(self, findings):
        """Post-process: Boost confidence when evidence supports it (GPT-OSS optimized)"""
        import MODEL_SELECTOR
        
        if not MODEL_SELECTOR.CONFIDENCE_BOOSTING_ENABLED:
            return findings
        
        boosted_count = 0
        for finding in findings:
            iocs = finding.get('indicators_of_compromise', [])
            log_lines = finding.get('log_lines', [])
            current_confidence = finding.get('confidence', 'Medium')
            
            # GPT-OSS: More conservative boosting (fewer false positives)
            # Require stronger evidence than Qwen
            ioc_count = len(iocs) if isinstance(iocs, list) else 0
            log_count = len(log_lines) if isinstance(log_lines, list) else 0
            
            # Strong evidence: 3+ IOCs AND 2+ log lines
            if ioc_count >= 3 and log_count >= 2:
                if current_confidence in ['Low', 'Medium']:
                    finding['confidence'] = 'High'
                    existing_notes = finding.get('notes', '')
                    finding['notes'] = (existing_notes + 
                                      " [Confidence boosted: Strong evidence present]").strip()
                    boosted_count += 1
        
        if boosted_count > 0:
            print(f"{Fore.LIGHTGREEN_EX}[GPT_OSS] ✓ Boosted confidence for {boosted_count} findings{Fore.RESET}")
        
        return findings

    def _deduplicate_findings(self, findings):
        """Simple deduplication"""
        seen_titles = set()
        deduplicated = []
        
        for finding in findings:
            title = finding.get('title', '').lower()
            if title not in seen_titles:
                seen_titles.add(title)
                deduplicated.append(finding)
        
        return deduplicated

    # ========== GPT-OSS SPECIFIC: JSON Validation & Extraction Methods ==========
    
    def _extract_json_from_markdown(self, buffer):
        """GPT-OSS specific: Extract JSON from markdown code blocks"""
        # Try to find JSON in markdown code blocks
        json_pattern = r'```(?:json)?\s*(\{.*?\})\s*```'
        matches = re.findall(json_pattern, buffer, re.DOTALL)
        if matches:
            return matches[0]  # Return first JSON match
        
        # Try without language tag
        json_pattern2 = r'```\s*(\{.*?\})\s*```'
        matches2 = re.findall(json_pattern2, buffer, re.DOTALL)
        if matches2:
            return matches2[0]
        
        return None
    
    def _strip_non_json_text(self, buffer):
        """GPT-OSS specific: Remove leading/trailing non-JSON text"""
        buffer = buffer.strip()
        
        # Find first { and last }
        first_brace = buffer.find('{')
        last_brace = buffer.rfind('}')
        
        if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
            return buffer[first_brace:last_brace + 1]
        
        return buffer
    
    def _validate_gpt_oss_response(self, buffer, mode="ctf"):
        """
        GPT-OSS specific: Validate and extract JSON from response buffer
        Returns validated JSON string ready for parsing
        """
        if not buffer or not buffer.strip():
            return buffer
        
        # Step 1: Try direct JSON parse
        try:
            json.loads(buffer.strip())
            return buffer.strip()  # Already valid JSON
        except json.JSONDecodeError:
            pass
        
        # Step 2: Extract from markdown code blocks
        extracted = self._extract_json_from_markdown(buffer)
        if extracted:
            try:
                json.loads(extracted)
                print(f"{Fore.LIGHTGREEN_EX}[GPT_OSS] ✓ Extracted JSON from markdown code block{Fore.RESET}")
                return extracted
            except json.JSONDecodeError:
                pass
        
        # Step 3: Strip leading/trailing text
        stripped = self._strip_non_json_text(buffer)
        try:
            json.loads(stripped)
            print(f"{Fore.LIGHTGREEN_EX}[GPT_OSS] ✓ Extracted JSON by stripping non-JSON text{Fore.RESET}")
            return stripped
        except json.JSONDecodeError:
            pass
        
        # Step 4: Return original buffer (will be handled by fallback parser)
        print(f"{Fore.YELLOW}[GPT_OSS] ⚠️  Could not extract valid JSON, using original buffer{Fore.RESET}")
        return buffer
    
    def _extract_ctf_answer_from_text(self, buffer):
        """
        GPT-OSS specific: Enhanced CTF answer extraction from natural language
        Extracts IP addresses, filenames, usernames, and other flag-like values
        """
        import base64
        import binascii
        
        content_str = str(buffer)
        suggested_answer = ""
        confidence = "Low"
        explanation = content_str[:1000] if len(content_str) > 1000 else content_str
        
        # Pattern 1: IP addresses (IPv4)
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ip_matches = re.findall(ip_pattern, content_str)
        if ip_matches:
            # Take the most recent/last IP mentioned (often the answer)
            suggested_answer = ip_matches[-1]
            confidence = "Medium"
            explanation = f"Extracted IP address from natural language response: {suggested_answer}"
        
        # Pattern 2: Filenames with extensions
        if not suggested_answer:
            filename_pattern = r'[\w\-_]+\.(txt|exe|dll|bat|ps1|sh|log|json|xml|yaml|yml|conf|config|ini)'
            filename_matches = re.findall(filename_pattern, content_str, re.IGNORECASE)
            if filename_matches:
                # Find the actual filename (not just extension)
                full_filename_pattern = r'[\w\-_/\\]+\.(?:txt|exe|dll|bat|ps1|sh|log|json|xml|yaml|yml|conf|config|ini)'
                full_matches = re.findall(full_filename_pattern, content_str, re.IGNORECASE)
                if full_matches:
                    suggested_answer = full_matches[-1].split('/')[-1].split('\\')[-1]  # Get just filename
                    confidence = "Medium"
                    explanation = f"Extracted filename from natural language response: {suggested_answer}"
        
        # Pattern 3: Usernames/Account names
        if not suggested_answer:
            username_pattern = r'(?:username|account|user|accountname)\s*[:=]\s*([A-Za-z0-9._@-]{3,})'
            username_matches = re.findall(username_pattern, content_str, re.IGNORECASE)
            if username_matches:
                suggested_answer = username_matches[-1]
                confidence = "Medium"
                explanation = f"Extracted username/account from natural language response: {suggested_answer}"
        
        # Pattern 4: Extract from KQL queries if present
        if not suggested_answer:
            kql_pattern = r'(?:RemoteIP|AccountName|FileName|ProcessCommandLine)\s*[:=]\s*["\']?([^"\'\s]+)["\']?'
            kql_matches = re.findall(kql_pattern, content_str, re.IGNORECASE)
            if kql_matches:
                suggested_answer = kql_matches[-1]
                confidence = "Low"
                explanation = f"Extracted value from KQL query pattern: {suggested_answer}"
        
        # Pattern 5: Base64/Hex encoded strings (potential flags)
        if not suggested_answer:
            # Look for base64-like strings
            base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
            base64_matches = re.findall(base64_pattern, content_str)
            if base64_matches:
                # Try to decode
                for match in base64_matches[-3:]:  # Check last 3 matches
                    try:
                        decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                        if decoded and len(decoded) < 100:  # Reasonable length
                            suggested_answer = decoded
                            confidence = "Low"
                            explanation = f"Decoded base64 string: {suggested_answer}"
                            break
                    except:
                        pass
        
        return {
            "suggested_answer": suggested_answer,
            "confidence": confidence,
            "evidence_rows": [],
            "evidence_fields": [],
            "explanation": explanation,
            "correlation": ""
        }
    
    def _retry_with_stricter_prompt(self, compact_messages, model_name, original_error, investigation_context=None):
        """
        GPT-OSS specific: Retry with stricter JSON enforcement prompt
        Returns retried response or None if retry fails
        """
        print(f"{Fore.YELLOW}[GPT_OSS] ⚠️  Retrying with stricter JSON enforcement...{Fore.RESET}")
        
        # Create stricter system message
        stricter_system_msg = None
        for msg in compact_messages:
            if msg.get("role") == "system":
                original_content = msg.get("content", "")
                # Add strict JSON enforcement
                stricter_content = original_content + "\n\n" + """
CRITICAL JSON FORMAT REQUIREMENT:
- You MUST return ONLY valid JSON. No natural language outside JSON.
- No explanations, no markdown, no code blocks.
- Return raw JSON starting with { and ending with }.
- For CTF mode: {"suggested_answer": "...", "confidence": "...", "explanation": "...", "evidence_rows": [], "evidence_fields": [], "correlation": ""}
- For threat hunt: {"findings": [...]}
"""
                stricter_system_msg = {"role": "system", "content": stricter_content}
                break
        
        # Build retry messages
        retry_messages = []
        if stricter_system_msg:
            retry_messages.append(stricter_system_msg)
        else:
            # Fallback: create new strict system message
            is_ctf = investigation_context and investigation_context.get('mode') == 'ctf'
            if is_ctf:
                retry_messages.append({
                    "role": "system",
                    "content": """Senior SOC Analyst. CTF Flag Hunter.

CRITICAL: Return ONLY valid JSON in this exact format:
{"suggested_answer": "flag value", "confidence": "High|Medium|Low", "explanation": "brief explanation", "evidence_rows": [], "evidence_fields": [], "correlation": ""}

NO natural language. NO markdown. NO explanations outside JSON."""
                })
            else:
                retry_messages.append({
                    "role": "system",
                    "content": """Senior SOC Analyst. Return ONLY valid JSON: {"findings": [...]}

NO natural language. NO markdown. NO explanations outside JSON."""
                })
        
        # Add user messages
        for msg in compact_messages:
            if msg.get("role") == "user":
                retry_messages.append(msg)
        
        # Retry with lower temperature for more deterministic output
        try:
            buffer = ""
            for chunk in OLLAMA_CLIENT.chat_stream(messages=retry_messages, model_name=model_name):
                try:
                    obj = json.loads(chunk)
                    msg = (obj.get("message") or {}).get("content", "") or obj.get("response", "")
                    if msg:
                        buffer += msg
                except Exception:
                    buffer += chunk if isinstance(chunk, str) else ""
            
            if buffer.strip():
                # Validate the retried response
                validated = self._validate_gpt_oss_response(buffer, "ctf" if (investigation_context and investigation_context.get('mode') == 'ctf') else "threat_hunt")
                try:
                    json.loads(validated)
                    print(f"{Fore.LIGHTGREEN_EX}[GPT_OSS] ✓ Retry successful - received valid JSON{Fore.RESET}")
                    return validated
                except json.JSONDecodeError:
                    print(f"{Fore.YELLOW}[GPT_OSS] ⚠️  Retry still returned invalid JSON{Fore.RESET}")
                    return None
        except Exception as e:
            print(f"{Fore.YELLOW}[GPT_OSS] ⚠️  Retry failed: {e}{Fore.RESET}")
            return None
        
        return None

    def _standard_llm_analysis(self, messages, model_name):
        """Fallback to standard analysis"""
        content = OLLAMA_CLIENT.chat(messages=messages, model_name=model_name, timeout=180)
        try:
            results = json.loads(content)
            return results
        except json.JSONDecodeError:
            return {"findings": []}
    
    def refine_findings_with_gpt(self, raw_findings, gpt_model=None):
        """
        Use GPT-4/5 to refine and enhance findings from local SLM
        This runs AFTER data crunching is complete (small payload)
        Includes anti-hallucination validation
        """
        if not self.openai_client or not self.use_gpt_refinement:
            return raw_findings
        
        if not raw_findings:
            return raw_findings
        
        model = gpt_model or self.refinement_model
        
        print(f"{Fore.LIGHTCYAN_EX}Refining {len(raw_findings)} findings with {model}...{Fore.RESET}")
        
        # Build concise summary of findings
        findings_summary = {
            "total_findings": len(raw_findings),
            "findings": raw_findings
        }
        
        refinement_prompt = f"""You are an expert SOC analyst reviewing preliminary threat detection findings.

⚠️ CRITICAL RULES - VIOLATION WILL INVALIDATE THE REPORT:
1. NEVER invent or add IOCs (IPs, hashes, accounts, devices) not in the original findings
2. NEVER create timestamps or log lines that don't exist in the source data
3. NEVER add attack techniques or MITRE mappings not already identified
4. DO NOT speculate about data not provided
5. ONLY enhance clarity, structure, and recommendations based on EXISTING data
6. If you add context, CLEARLY mark it as "[CONTEXT]"

YOUR JOB:
- Improve descriptions (clearer, more professional)
- Better MITRE technique explanations (use official ATT&CK descriptions)
- More actionable recommendations (specific steps based on actual findings)
- Organize information better
- Fix grammar/structure

YOU MUST PRESERVE:
- All original IOCs exactly as provided
- All log lines exactly as provided
- All confidence levels (unless lowering due to false positive)
- All timestamps and factual data

ORIGINAL FINDINGS (YOUR ONLY SOURCE OF TRUTH):
{json.dumps(findings_summary, indent=2)}

Return refined findings in same JSON format."""

        try:
            response = self.openai_client.chat.completions.create(
                model=model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security analyst editor. Refine and clarify findings WITHOUT adding factual data not in the source. Hallucinating IOCs or log data is a critical failure."
                    },
                    {
                        "role": "user",
                        "content": refinement_prompt
                    }
                ],
                response_format={"type": "json_object"},
                temperature=0.1,  # Very low temp = less creativity = less hallucination
                seed=42           # Deterministic output
            )
            
            refined = json.loads(response.choices[0].message.content)
            
            # Validate before returning
            validated = self._validate_refined_findings(raw_findings, refined.get("findings", []))
            
            print(f"{Fore.LIGHTGREEN_EX}✓ Refinement complete{Fore.RESET}")
            return validated
        
        except Exception as e:
            print(f"{Fore.YELLOW}GPT refinement failed: {e}. Using original findings.{Fore.RESET}")
            return raw_findings
    
    def _validate_refined_findings(self, original_findings, refined_findings):
        """
        Verify GPT didn't hallucinate data
        Cross-reference all IOCs, log lines, and facts against originals
        """
        print(f"{Fore.LIGHTYELLOW_EX}  Validating for hallucinations...{Fore.RESET}", end='')
        
        # Extract all IOCs from originals (ground truth)
        original_iocs = set()
        original_log_lines = set()
        
        for finding in original_findings:
            original_iocs.update(finding.get('indicators_of_compromise', []))
            original_log_lines.update(finding.get('log_lines', []))
        
        # Validate each refined finding
        validated_findings = []
        hallucination_detected = False
        
        for idx, finding in enumerate(refined_findings):
            if idx >= len(original_findings):
                # GPT added extra findings - reject
                print(f"\n{Fore.RED}  ⚠️  Extra finding detected, rejecting{Fore.RESET}")
                hallucination_detected = True
                continue
            
            validation_passed = True
            
            # Check IOCs
            refined_iocs = set(finding.get('indicators_of_compromise', []))
            new_iocs = refined_iocs - original_iocs
            
            if new_iocs:
                # Check if they're just reformatted
                suspicious_iocs = []
                for ioc in new_iocs:
                    if not any(orig in ioc or ioc in orig for orig in original_iocs):
                        suspicious_iocs.append(ioc)
                
                if suspicious_iocs:
                    print(f"\n{Fore.RED}  ⚠️  Finding #{idx+1}: Added IOCs {suspicious_iocs}{Fore.RESET}")
                    validation_passed = False
                    hallucination_detected = True
            
            # Check confidence didn't increase
            orig_confidence = original_findings[idx].get('confidence', 'Medium')
            refined_confidence = finding.get('confidence', 'Medium')
            
            confidence_order = {'Low': 0, 'Medium': 1, 'High': 2}
            if confidence_order.get(refined_confidence, 1) > confidence_order.get(orig_confidence, 1):
                finding['confidence'] = orig_confidence  # Reset
            
            # If validation failed, use original
            if not validation_passed:
                validated_findings.append(original_findings[idx])
            else:
                validated_findings.append(finding)
        
        if hallucination_detected:
            print(f" {Fore.YELLOW}Some reverted{Fore.RESET}")
        else:
            print(f" {Fore.LIGHTGREEN_EX}Passed{Fore.RESET}")
        
        return validated_findings

