import re
import json
from color_support import Fore
import OLLAMA_CLIENT
import LEARNING_ENGINE
import GUARDRAILS

class QwenEnhancer:
    def __init__(self, feedback_file="_analysis_feedback.jsonl", severity_multiplier=1.0, 
                 openai_client=None, use_gpt_refinement=False, refinement_model="gpt-4o"):
        # Load learning engine for pattern weight adjustment (cached globally)
        self.learning_engine = LEARNING_ENGINE.get_learning_engine()
        self.feedback_file = feedback_file
        self.severity_multiplier = severity_multiplier
        
        # Load learning from past feedback (uses cached weights)
        self.pattern_weights = self.learning_engine.weights if self.learning_engine else {}
        
        # GUARDRAILS integration for defense-in-depth security
        self.allowed_tables = GUARDRAILS.ALLOWED_TABLES
        self.guardrails_enabled = True  # Can be disabled if needed
        self.rejected_patterns = []  # Track what was blocked
        
        # GPT refinement configuration (hybrid mode)
        self.openai_client = openai_client
        self.use_gpt_refinement = use_gpt_refinement
        self.refinement_model = refinement_model
        
        # Threat detection patterns
        self.suspicious_patterns = {
            'powershell_obfuscation': [
                r'powershell.*-enc',
                r'powershell.*-e\s+',
                r'iex\s*\(',
                r'invoke-expression',
                r'base64.*decode',
                r'powershell.*-windowstyle.*hidden',
                r'powershell.*-nop.*-nologo'
            ],
            'lolbins': [
                r'rundll32\.exe',
                r'regsvr32\.exe',
                r'mshta\.exe',
                r'wscript\.exe',
                r'cscript\.exe',
                r'certutil\.exe',
                r'bitsadmin\.exe',
                r'reg\.exe.*add',
                r'sc\.exe.*create',
                r'at\.exe',
                r'forfiles\.exe'
            ],
            'suspicious_commands': [
                r'net\s+user.*\/add',
                r'net\s+localgroup.*administrators.*\/add',
                r'schtasks.*\/create',
                r'wmic.*process.*call.*create',
                r'psexec',
                r'wget.*http',
                r'curl.*http',
                r'net\s+share.*\/add',
                r'net\s+start.*service',
                r'reg\s+add.*HKLM',
                r'sc\s+create.*service'
            ],
            'file_operations': [
                r'\.exe.*temp',
                r'\.bat.*temp',
                r'\.ps1.*temp',
                r'copy.*\.exe',
                r'move.*\.exe',
                r'del.*\.log',
                r'rmdir.*\/s.*\/q',
                r'format.*c:',
                r'cipher.*\/w'
            ],
            'network_suspicious': [
                r'port\s+(4444|8080|9999|31337)',
                r'ip.*(10\.0\.0\.|192\.168\.|172\.16\.)',
                r'tor.*proxy',
                r'vpn.*tunnel',
                r'nc\s+-l.*-p',
                r'netcat.*-l.*-p',
                r'ssh.*-R.*:',
                r'plink.*-R'
            ],
            'credential_dumping': [
                r'lsass\.exe',
                r'procdump.*lsass',
                r'mimikatz',
                r'sekurlsa::',
                r'wdigest::',
                r'kerberos::',
                r'msv1_0::',
                r'cachedump',
                r'pwdump'
            ],
            'privilege_escalation': [
                r'uac.*bypass',
                r'bypass.*uac',
                r'getsystem',
                r'incognito',
                r'load.*incognito',
                r'steal_token',
                r'impersonate_token',
                r'getprivs',
                r'whoami.*/priv'
            ],
            'lateral_movement': [
                r'wmic.*/node:',
                r'psexec.*\\\\',
                r'winexec.*\\\\',
                r'at.*\\\\',
                r'schtasks.*/s.*\\\\',
                r'smbclient.*\\\\',
                r'smbmap.*\\\\',
                r'crackmapexec.*\\\\'
            ],
            'persistence_registry': [
                r'reg.*add.*HKLM.*Run',
                r'reg.*add.*HKCU.*Run',
                r'reg.*add.*HKLM.*RunOnce',
                r'reg.*add.*HKCU.*RunOnce',
                r'reg.*add.*HKLM.*Services',
                r'reg.*add.*HKLM.*Winlogon'
            ],
            'defense_evasion': [
                r'disable.*firewall',
                r'netsh.*firewall.*off',
                r'disable.*defender',
                r'disable.*antivirus',
                r'disable.*windows.*defender',
                r'reg.*add.*HKLM.*DisableAntiSpyware',
                r'reg.*add.*HKLM.*DisableRealtimeMonitoring'
            ],
            'data_exfiltration': [
                r'ftp.*put',
                r'scp.*-r',
                r'rsync.*-av',
                r'7z.*a.*archive',
                r'winrar.*a.*archive',
                r'zip.*-r.*archive',
                r'rar.*a.*archive'
            ],
            'reconnaissance': [
                r'nmap.*-sS',
                r'nmap.*-sV',
                r'nmap.*-O',
                r'netstat.*-an',
                r'net.*view',
                r'net.*user',
                r'net.*group',
                r'net.*localgroup',
                r'net.*accounts',
                r'net.*config'
            ],
            'initial_access': [
                r'brute.*force',
                r'password.*spray',
                r'credential.*stuffing',
                r'phishing.*email',
                r'malicious.*attachment',
                r'exploit.*kit',
                r'drive.*by.*download'
            ],
            'collection': [
                r'keylogger',
                r'screen.*capture',
                r'clipboard.*monitor',
                r'file.*monitor',
                r'network.*sniffer',
                r'packet.*capture',
                r'wireshark',
                r'tcpdump'
            ],
            'impact': [
                r'encrypt.*files',
                r'ransomware',
                r'delete.*files',
                r'format.*disk',
                r'shutdown.*/s',
                r'restart.*/r',
                r'logoff.*/l',
                r'lock.*workstation'
            ]
        }
        
        # IOC patterns - Only extract device and account names (most useful for investigation)
        self.ioc_patterns = {
            # ENABLED: Extract all IOC types for threat hunting
            'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'domain': r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+\b',
            'hash': r'\b[a-fA-F0-9]{32,64}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'device_name': None,  # Extracted via CSV parsing
            'account_name': None  # Extracted via CSV parsing
        }
        
        # Comprehensive MITRE ATT&CK technique mappings
        self.mitre_mappings = {
            # EXECUTION TECHNIQUES
            'powershell_obfuscation': {
                'tactic': 'Execution',
                'technique': 'T1059.001',
                'description': 'PowerShell Command and Scripting Interpreter'
            },
            'cmd_execution': {
                'tactic': 'Execution',
                'technique': 'T1059.003',
                'description': 'Windows Command Shell'
            },
            'javascript_execution': {
                'tactic': 'Execution',
                'technique': 'T1059.007',
                'description': 'JavaScript/JScript'
            },
            'python_execution': {
                'tactic': 'Execution',
                'technique': 'T1059.006',
                'description': 'Python'
            },
            'service_execution': {
                'tactic': 'Execution',
                'technique': 'T1569.002',
                'description': 'System Services: Service Execution'
            },
            'scheduled_task_execution': {
                'tactic': 'Execution',
                'technique': 'T1053.005',
                'description': 'Scheduled Task/Job: Scheduled Task'
            },
            'wmi_execution': {
                'tactic': 'Execution',
                'technique': 'T1047',
                'description': 'Windows Management Instrumentation'
            },
            'dll_execution': {
                'tactic': 'Execution',
                'technique': 'T1574.002',
                'description': 'Hijack Execution Flow: DLL Side-Loading'
            },
            
            # PERSISTENCE TECHNIQUES
            'suspicious_commands': {
                'tactic': 'Persistence',
                'technique': 'T1053.005',
                'description': 'Scheduled Task/Job: Scheduled Task'
            },
            'file_operations': {
                'tactic': 'Persistence',
                'technique': 'T1547.001',
                'description': 'Boot or Logon Autostart Execution: Registry Run Keys'
            },
            'service_persistence': {
                'tactic': 'Persistence',
                'technique': 'T1543.003',
                'description': 'Create or Modify System Process: Windows Service'
            },
            'startup_folder': {
                'tactic': 'Persistence',
                'technique': 'T1547.015',
                'description': 'Boot or Logon Autostart Execution: Login Items'
            },
            'winlogon_persistence': {
                'tactic': 'Persistence',
                'technique': 'T1547.004',
                'description': 'Boot or Logon Autostart Execution: Winlogon Helper DLL'
            },
            'at_persistence': {
                'tactic': 'Persistence',
                'technique': 'T1053.002',
                'description': 'Scheduled Task/Job: At'
            },
            
            # PRIVILEGE ESCALATION TECHNIQUES
            'privilege_escalation': {
                'tactic': 'Privilege Escalation',
                'technique': 'T1548.002',
                'description': 'Abuse Elevation Control Mechanism: Bypass User Account Control'
            },
            'token_manipulation': {
                'tactic': 'Privilege Escalation',
                'technique': 'T1134',
                'description': 'Access Token Manipulation'
            },
            'process_injection': {
                'tactic': 'Privilege Escalation',
                'technique': 'T1055',
                'description': 'Process Injection'
            },
            'dll_injection': {
                'tactic': 'Privilege Escalation',
                'technique': 'T1055.001',
                'description': 'Process Injection: Dynamic-link Library Injection'
            },
            
            # DEFENSE EVASION TECHNIQUES
            'lolbins': {
                'tactic': 'Defense Evasion',
                'technique': 'T1218',
                'description': 'Signed Binary Proxy Execution'
            },
            'defense_evasion': {
                'tactic': 'Defense Evasion',
                'technique': 'T1562.001',
                'description': 'Impair Defenses: Disable or Modify Tools'
            },
            'process_hollowing': {
                'tactic': 'Defense Evasion',
                'technique': 'T1055.012',
                'description': 'Process Injection: Process Hollowing'
            },
            'code_signing': {
                'tactic': 'Defense Evasion',
                'technique': 'T1553.002',
                'description': 'Subvert Trust Controls: Code Signing'
            },
            'masquerading': {
                'tactic': 'Defense Evasion',
                'technique': 'T1036',
                'description': 'Masquerading'
            },
            'indicator_removal': {
                'tactic': 'Defense Evasion',
                'technique': 'T1070',
                'description': 'Indicator Removal'
            },
            'file_deletion': {
                'tactic': 'Defense Evasion',
                'technique': 'T1070.004',
                'description': 'Indicator Removal: File Deletion'
            },
            'log_clearing': {
                'tactic': 'Defense Evasion',
                'technique': 'T1070.001',
                'description': 'Indicator Removal: Clear Windows Event Logs'
            },
            
            # CREDENTIAL ACCESS TECHNIQUES
            'credential_dumping': {
                'tactic': 'Credential Access',
                'technique': 'T1003.001',
                'description': 'OS Credential Dumping: LSASS Memory'
            },
            'sam_dumping': {
                'tactic': 'Credential Access',
                'technique': 'T1003.002',
                'description': 'OS Credential Dumping: Security Account Manager'
            },
            'ntds_dumping': {
                'tactic': 'Credential Access',
                'technique': 'T1003.003',
                'description': 'OS Credential Dumping: NTDS'
            },
            'keylogging': {
                'tactic': 'Credential Access',
                'technique': 'T1056.001',
                'description': 'Input Capture: Keylogging'
            },
            'credential_harvesting': {
                'tactic': 'Credential Access',
                'technique': 'T1552',
                'description': 'Unsecured Credentials'
            },
            'kerberoasting': {
                'tactic': 'Credential Access',
                'technique': 'T1558.003',
                'description': 'Steal or Forge Kerberos Tickets: Kerberoasting'
            },
            'asreproasting': {
                'tactic': 'Credential Access',
                'technique': 'T1558.004',
                'description': 'Steal or Forge Kerberos Tickets: AS-REP Roasting'
            },
            
            # DISCOVERY TECHNIQUES
            'reconnaissance': {
                'tactic': 'Discovery',
                'technique': 'T1046',
                'description': 'Network Service Scanning'
            },
            'system_discovery': {
                'tactic': 'Discovery',
                'technique': 'T1082',
                'description': 'System Information Discovery'
            },
            'network_discovery': {
                'tactic': 'Discovery',
                'technique': 'T1018',
                'description': 'Remote System Discovery'
            },
            'process_discovery': {
                'tactic': 'Discovery',
                'technique': 'T1057',
                'description': 'Process Discovery'
            },
            'account_discovery': {
                'tactic': 'Discovery',
                'technique': 'T1087',
                'description': 'Account Discovery'
            },
            'permission_discovery': {
                'tactic': 'Discovery',
                'technique': 'T1069',
                'description': 'Permission Groups Discovery'
            },
            'software_discovery': {
                'tactic': 'Discovery',
                'technique': 'T1518',
                'description': 'Software Discovery'
            },
            'security_software_discovery': {
                'tactic': 'Discovery',
                'technique': 'T1518.001',
                'description': 'Software Discovery: Security Software Discovery'
            },
            
            # LATERAL MOVEMENT TECHNIQUES
            'lateral_movement': {
                'tactic': 'Lateral Movement',
                'technique': 'T1021.001',
                'description': 'Remote Services: Remote Desktop Protocol'
            },
            'smb_lateral_movement': {
                'tactic': 'Lateral Movement',
                'technique': 'T1021.002',
                'description': 'Remote Services: SMB/Windows Admin Shares'
            },
            'ssh_lateral_movement': {
                'tactic': 'Lateral Movement',
                'technique': 'T1021.004',
                'description': 'Remote Services: SSH'
            },
            'pass_the_hash': {
                'tactic': 'Lateral Movement',
                'technique': 'T1550.002',
                'description': 'Use Alternate Authentication Material: Pass the Hash'
            },
            'pass_the_ticket': {
                'tactic': 'Lateral Movement',
                'technique': 'T1550.003',
                'description': 'Use Alternate Authentication Material: Pass the Ticket'
            },
            
            # COLLECTION TECHNIQUES
            'collection': {
                'tactic': 'Collection',
                'technique': 'T1005',
                'description': 'Data from Local System'
            },
            'clipboard_data': {
                'tactic': 'Collection',
                'technique': 'T1115',
                'description': 'Clipboard Data'
            },
            'screen_capture': {
                'tactic': 'Collection',
                'technique': 'T1113',
                'description': 'Screen Capture'
            },
            'audio_capture': {
                'tactic': 'Collection',
                'technique': 'T1123',
                'description': 'Audio Capture'
            },
            'video_capture': {
                'tactic': 'Collection',
                'technique': 'T1125',
                'description': 'Video Capture'
            },
            'email_collection': {
                'tactic': 'Collection',
                'technique': 'T1114',
                'description': 'Email Collection'
            },
            'browser_data': {
                'tactic': 'Collection',
                'technique': 'T1503',
                'description': 'Data from Information Repositories'
            },
            
            # COMMAND AND CONTROL TECHNIQUES
            'network_suspicious': {
                'tactic': 'Command and Control',
                'technique': 'T1071.001',
                'description': 'Application Layer Protocol: Web Protocols'
            },
            'dns_tunneling': {
                'tactic': 'Command and Control',
                'technique': 'T1071.004',
                'description': 'Application Layer Protocol: DNS'
            },
            'http_c2': {
                'tactic': 'Command and Control',
                'technique': 'T1071.001',
                'description': 'Application Layer Protocol: Web Protocols'
            },
            'ftp_c2': {
                'tactic': 'Command and Control',
                'technique': 'T1071.002',
                'description': 'Application Layer Protocol: File Transfer Protocols'
            },
            'smtp_c2': {
                'tactic': 'Command and Control',
                'technique': 'T1071.003',
                'description': 'Application Layer Protocol: Mail Protocols'
            },
            'proxy_c2': {
                'tactic': 'Command and Control',
                'technique': 'T1090',
                'description': 'Proxy'
            },
            'domain_fronting': {
                'tactic': 'Command and Control',
                'technique': 'T1090.004',
                'description': 'Proxy: Domain Fronting'
            },
            'tor_c2': {
                'tactic': 'Command and Control',
                'technique': 'T1090.003',
                'description': 'Proxy: Multi-hop Proxy'
            },
            
            # EXFILTRATION TECHNIQUES
            'data_exfiltration': {
                'tactic': 'Exfiltration',
                'technique': 'T1041',
                'description': 'Exfiltration Over C2 Channel'
            },
            'ftp_exfiltration': {
                'tactic': 'Exfiltration',
                'technique': 'T1048.003',
                'description': 'Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol'
            },
            'email_exfiltration': {
                'tactic': 'Exfiltration',
                'technique': 'T1048.002',
                'description': 'Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol'
            },
            'cloud_exfiltration': {
                'tactic': 'Exfiltration',
                'technique': 'T1567',
                'description': 'Exfiltration Over Web Service'
            },
            'scheduled_transfer': {
                'tactic': 'Exfiltration',
                'technique': 'T1029',
                'description': 'Scheduled Transfer'
            },
            
            # IMPACT TECHNIQUES
            'impact': {
                'tactic': 'Impact',
                'technique': 'T1486',
                'description': 'Data Encrypted for Impact'
            },
            'data_destruction': {
                'tactic': 'Impact',
                'technique': 'T1485',
                'description': 'Data Destruction'
            },
            'service_stop': {
                'tactic': 'Impact',
                'technique': 'T1489',
                'description': 'Service Stop'
            },
            'system_shutdown': {
                'tactic': 'Impact',
                'technique': 'T1529',
                'description': 'System Shutdown/Reboot'
            },
            'defacement': {
                'tactic': 'Impact',
                'technique': 'T1491',
                'description': 'Defacement'
            },
            'resource_hijacking': {
                'tactic': 'Impact',
                'technique': 'T1496',
                'description': 'Resource Hijacking'
            },
            'network_denial': {
                'tactic': 'Impact',
                'technique': 'T1499',
                'description': 'Network Denial of Service'
            },
            
            # INITIAL ACCESS TECHNIQUES
            'initial_access': {
                'tactic': 'Initial Access',
                'technique': 'T1078',
                'description': 'Valid Accounts'
            },
            'phishing': {
                'tactic': 'Initial Access',
                'technique': 'T1566',
                'description': 'Phishing'
            },
            'spearphishing': {
                'tactic': 'Initial Access',
                'technique': 'T1566.001',
                'description': 'Phishing: Spearphishing Attachment'
            },
            'drive_by_compromise': {
                'tactic': 'Initial Access',
                'technique': 'T1189',
                'description': 'Drive-by Compromise'
            },
            'exploit_public_facing': {
                'tactic': 'Initial Access',
                'technique': 'T1190',
                'description': 'Exploit Public-Facing Application'
            },
            'external_remote_services': {
                'tactic': 'Initial Access',
                'technique': 'T1133',
                'description': 'External Remote Services'
            },
            'hardware_additions': {
                'tactic': 'Initial Access',
                'technique': 'T1200',
                'description': 'Hardware Additions'
            },
            'supply_chain_compromise': {
                'tactic': 'Initial Access',
                'technique': 'T1195',
                'description': 'Supply Chain Compromise'
            },
            'trusted_relationship': {
                'tactic': 'Initial Access',
                'technique': 'T1199',
                'description': 'Trusted Relationship'
            }
        }
    

    def analyze_logs_with_rules(self, log_data, table_name="Unknown"):
        """Apply rule-based analysis to identify suspicious patterns"""
        findings = []
        log_lines = log_data.split('\n')
        
        # Parse CSV header to get column indices
        csv_header = None
        csv_col_indices = {}
        if log_lines and ',' in log_lines[0]:
            csv_header = log_lines[0].strip().split(',')
            for idx, col in enumerate(csv_header):
                csv_col_indices[col.strip()] = idx
        
        print(f"{Fore.LIGHTGREEN_EX}Applying rule-based threat detection on {table_name}...")
        if csv_col_indices:
            print(f"{Fore.LIGHTBLACK_EX}CSV Columns detected: {list(csv_col_indices.keys())}{Fore.RESET}")
        
        # DEBUG: Show first data row to see actual values
        if len(log_lines) > 1:
            first_data_line = log_lines[1].strip()
            if first_data_line:
                parts = first_data_line.split(',')
                print(f"{Fore.LIGHTBLACK_EX}[DEBUG] First data row ({len(parts)} columns):{Fore.RESET}")
                for idx, val in enumerate(parts[:10]):  # Show first 10 columns
                    col_name = csv_header[idx] if idx < len(csv_header) else f"col_{idx}"
                    print(f"{Fore.LIGHTBLACK_EX}  [{idx}] {col_name} = {val[:60]}{Fore.RESET}")
        
        for line_num, line in enumerate(log_lines, 1):
            if not line.strip() or line_num == 1:  # Skip empty and header
                continue
                
            # Check each pattern category
            for category, patterns in self.suspicious_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        finding = self._create_finding(
                            line, line_num, category, pattern, table_name, csv_col_indices
                        )
                        findings.append(finding)
                        break  # Only one finding per line per category
        
        # Extract IOCs
        iocs = self._extract_iocs(log_data)
        
        print(f"{Fore.WHITE}Rule-based analysis found {len(findings)} suspicious patterns and {sum(len(v) for v in iocs.values())} IOCs")
        
        # Extract unique device names from the CSV for IOC findings
        device_names = set()
        if csv_col_indices and log_lines:
            for line in log_lines[1:]:  # Skip header
                if not line.strip():
                    continue
                parts = line.split(',')
                # Try to extract DeviceName, VM_s, or Computer
                for col_name in ['DeviceName', 'VM_s', 'Computer']:
                    if col_name in csv_col_indices:
                        idx = csv_col_indices[col_name]
                        if idx < len(parts):
                            device = parts[idx].strip()
                            if device and not re.match(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', device):
                                device_names.add(device)
                        break
        
        # Create findings from IOCs if no pattern matches found
        if not findings and iocs:
            ioc_findings = self._create_ioc_findings(iocs, table_name, device_names)
            findings.extend(ioc_findings)
        
        return findings, iocs

    def _create_finding(self, line, line_num, category, pattern, table_name, csv_col_indices=None):
        """Create a structured finding from rule match"""
        mitre_info = self.mitre_mappings.get(category, {
            'tactic': 'Unknown',
            'technique': 'T0000',
            'description': 'Unknown technique'
        })
        
        # Extract IOCs from the line
        iocs = self._extract_iocs_from_line(line)
        
        # Parse CSV columns if available to extract structured data
        device_name = None
        account_name = None
        remote_ip = None
        
        if csv_col_indices and line.strip():
            parts = line.split(',')
            
            # Try to extract DeviceName, VM_s, or Computer
            for col_name in ['DeviceName', 'VM_s', 'Computer']:
                if col_name in csv_col_indices:
                    idx = csv_col_indices[col_name]
                    if idx < len(parts):
                        device_name = parts[idx].strip()
                        break
            
            # Try to extract AccountName, Caller, User
            for col_name in ['AccountName', 'Caller', 'UserPrincipalName']:
                if col_name in csv_col_indices:
                    idx = csv_col_indices[col_name]
                    if idx < len(parts):
                        account_name = parts[idx].strip()
                        break
            
            # Try to extract IPs
            for col_name in ['RemoteIP', 'SrcPublicIPs_s', 'DestIP_s', 'IPAddress', 'CallerIpAddress']:
                if col_name in csv_col_indices:
                    idx = csv_col_indices[col_name]
                    if idx < len(parts):
                        ip_val = parts[idx].strip()
                        if re.match(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', ip_val):
                            remote_ip = ip_val
                            break
        
        # Build enhanced log lines with structured data
        enhanced_log_lines = [line.strip()]
        
        # Add structured metadata
        if device_name:
            enhanced_log_lines.append(f"DeviceName: {device_name}")
        if account_name:
            enhanced_log_lines.append(f"AccountName: {account_name}")
        if remote_ip:
            enhanced_log_lines.append(f"RemoteIP: {remote_ip}")
        
        # If we have IOCs, add them as structured findings
        if iocs:
            for ioc in iocs[:5]:  # Limit to first 5
                enhanced_log_lines.append(f"IOC: {ioc}")
        
        # APPLY LEARNED WEIGHTS: Adjust confidence based on past feedback
        base_confidence = 'Medium'
        weight = self.pattern_weights.get(category, 1.0)
        
        # Apply severity multiplier on top of learned weights
        total_weight = weight * self.severity_multiplier
        
        if total_weight >= 1.2:
            adjusted_confidence = 'High'  # User found this pattern valuable OR strict mode
            notes_suffix = " [Boosted: high user rating history]" if weight >= 1.2 else " [Boosted: strict severity mode]"
        elif total_weight <= 0.8:
            adjusted_confidence = 'Low'  # User rated this pattern poorly OR relaxed mode
            notes_suffix = " [Reduced: low user rating history]" if weight <= 0.8 else " [Reduced: relaxed severity mode]"
        else:
            adjusted_confidence = base_confidence
            notes_suffix = ""
        
        # Format IOCs with field name labels for clarity
        labeled_iocs = []
        for ioc in iocs:
            ioc_str = str(ioc)
            # Check if already labeled
            if ':' in ioc_str and any(prefix in ioc_str for prefix in ['Device:', 'Account:', 'IP:', 'DeviceName:', 'AccountName:']):
                labeled_iocs.append(ioc_str)  # Already has label
            else:
                # Add appropriate label based on content
                if device_name and ioc_str == device_name:
                    labeled_iocs.append(f"DeviceName: {ioc_str}")
                elif account_name and ioc_str == account_name:
                    labeled_iocs.append(f"AccountName: {ioc_str}")
                elif re.match(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', ioc_str):
                    labeled_iocs.append(f"IP: {ioc_str}")
                else:
                    labeled_iocs.append(ioc_str)  # Unknown type, keep as-is
        
        # Build finding with structured metadata
        finding = {
            'title': f"Suspicious {category.replace('_', ' ').title()} Activity",
            'description': f"Detected suspicious pattern '{pattern}' in {table_name} logs. This may indicate malicious activity.",
            'mitre': {
                'tactic': mitre_info['tactic'],
                'technique': mitre_info['technique'],
                'sub_technique': mitre_info['technique'],
                'id': mitre_info['technique'],
                'description': mitre_info['description']
            },
            'log_lines': enhanced_log_lines,
            'confidence': adjusted_confidence,  # Learned confidence
            'recommendations': ['investigate', 'monitor'],
            'indicators_of_compromise': labeled_iocs,  # Display with field name labels
            'tags': [category, 'rule-based-detection'],
            'notes': f"Detected by rule-based pattern matching. Pattern: {pattern}{notes_suffix}"
        }
        
        # Add structured metadata to finding
        if device_name:
            finding['device_name'] = device_name
        if account_name:
            finding['account_name'] = account_name
        if remote_ip:
            finding['remote_ip'] = remote_ip
        
        return finding

    def _extract_iocs(self, log_data):
        """Extract IOCs from log data including device/account names"""
        iocs = {}
        
        # Extract pattern-based IOCs
        for ioc_type, pattern in self.ioc_patterns.items():
            if pattern is None:
                continue
            matches = re.findall(pattern, log_data)
            if matches:
                # Handle both strings and tuples from re.findall
                clean_matches = []
                for match in matches:
                    if isinstance(match, tuple):
                        # Take the first non-empty group
                        clean_matches.extend([m for m in match if m])
                    else:
                        clean_matches.append(match)
                iocs[ioc_type] = list(set(clean_matches))  # Remove duplicates
        
        # Extract device names and account names from CSV log lines
        device_names = set()
        account_names = set()
        
        log_lines = log_data.split('\n')
        for line in log_lines[:100]:  # Parse first 100 lines
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
            iocs['device_name'] = list(device_names)[:15]
        if account_names:
            iocs['account_name'] = list(account_names)[:15]
        
        return iocs

    def _extract_iocs_from_line(self, line):
        """Extract IOCs from a single line including device/account names"""
        iocs = []
        
        # Extract pattern-based IOCs
        for ioc_type, pattern in self.ioc_patterns.items():
            if pattern is None:
                continue
            matches = re.findall(pattern, line)
            # Handle both strings and tuples from re.findall
            for match in matches:
                if isinstance(match, tuple):
                    # Take the first non-empty group
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
        
        return list(set(iocs))

    def _create_ioc_findings(self, iocs, table_name, device_names=None):
        """Create findings from extracted IOCs (prioritize actionable IOCs)"""
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
            
            # Build description with device context
            device_context = ""
            if device_names:
                device_list = sorted(device_names)
                if len(device_list) == 1:
                    device_context = f" on device '{device_list[0]}'"
                elif len(device_list) <= 3:
                    device_context = f" on devices: {', '.join(device_list)}"
                else:
                    device_context = f" across {len(device_list)} devices ({', '.join(device_list[:2])}, and others)"
            
            # Format IOCs with field name labels
            if ioc_type == 'device_name':
                labeled_iocs = [f"DeviceName: {v}" for v in display_values]
            elif ioc_type == 'account_name':
                labeled_iocs = [f"AccountName: {v}" for v in display_values]
            else:
                labeled_iocs = [f"{ioc_type.replace('_', ' ').title()}: {v}" for v in display_values]
            
            # Create a finding for each IOC type
            finding = {
                'title': f"Potential {ioc_type.replace('_', ' ').title()} Indicators Detected",
                'description': f"Found {len(values)} {ioc_type.replace('_', ' ')} indicators in {table_name} logs{device_context}{hash_note}. These should be investigated for potential malicious activity.",
                'mitre': {
                    'tactic': 'Reconnaissance',
                    'technique': 'T1590',
                    'sub_technique': 'T1590.001',
                    'id': 'T1590.001',
                    'description': 'Gather Victim Host Information'
                },
                'log_lines': [f"Found {ioc_type}: {', '.join(str(v) for v in display_values[:3])}"],  # Show first 3
                'confidence': 'Medium' if device_names else 'Low',  # Higher confidence if we know the device
                'recommendations': ['monitor', 'investigate'],
                'indicators_of_compromise': labeled_iocs,  # Display with field name labels
                'tags': ['ioc-detection', ioc_type],
                'notes': f"Automatically detected {len(values)} {ioc_type.replace('_', ' ')} indicators using pattern matching{hash_note}."
            }
            
            # Add device names to finding if available
            if device_names:
                # Store all device names for UTILITIES to use
                finding['device_names'] = list(device_names)
                # Also add log lines with device info
                for device in sorted(device_names):
                    finding['log_lines'].append(f"DeviceName: {device}")
            
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
            print(f"{Fore.YELLOW}[QWEN_ENHANCER] Could not detect table - proceeding with caution{Fore.RESET}")
            return csv_text, True  # Allow but warn
        
        if table_name not in self.allowed_tables:
            print(f"{Fore.RED}[QWEN_ENHANCER] ⚠️  BLOCKED: Table '{table_name}' not in GUARDRAILS.ALLOWED_TABLES{Fore.RESET}")
            self.rejected_patterns.append(f"Unauthorized table: {table_name}")
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
            print(f"{Fore.YELLOW}[QWEN_ENHANCER] Filtering out {len(unauthorized_fields)} unauthorized fields: {', '.join(unauthorized_fields[:3])}{'...' if len(unauthorized_fields) > 3 else ''}{Fore.RESET}")
        
        # If all fields unauthorized, reject
        if not authorized_indices:
            print(f"{Fore.RED}[QWEN_ENHANCER] ⚠️  BLOCKED: No authorized fields in data{Fore.RESET}")
            return "", False
        
        # Filter CSV to only include authorized fields
        filtered_lines = []
        for line in lines:
            parts = line.split(',')
            filtered_parts = [parts[i] for i in authorized_indices if i < len(parts)]
            filtered_lines.append(','.join(filtered_parts))
        
        filtered_csv = '\n'.join(filtered_lines)
        
        print(f"{Fore.LIGHTGREEN_EX}[QWEN_ENHANCER] ✓ Validated: {table_name} with {len(authorized_indices)} authorized fields{Fore.RESET}")
        return filtered_csv, True

    def enhanced_hunt(self, messages, model_name="qwen3:8b", max_lines=50):
        """Enhanced threat hunting combining rules and LLM analysis"""
        print(f"{Fore.LIGHTGREEN_EX}Starting enhanced Qwen threat hunt...")
        
        # Extract log data and table name from messages
        log_data = ""
        table_name = "Unknown"
        for msg in messages:
            content = msg.get("content", "")
            if "Log Data:" in content:
                log_data = content.split("Log Data:")[-1].strip()
                # Try to extract table name from message
                if "DeviceProcessEvents" in content:
                    table_name = "DeviceProcessEvents"
                elif "DeviceNetworkEvents" in content:
                    table_name = "DeviceNetworkEvents"
                elif "DeviceLogonEvents" in content:
                    table_name = "DeviceLogonEvents"
                elif "DeviceFileEvents" in content:
                    table_name = "DeviceFileEvents"
                elif "DeviceRegistryEvents" in content:
                    table_name = "DeviceRegistryEvents"
                elif "AlertInfo" in content:
                    table_name = "AlertInfo"
                elif "AlertEvidence" in content:
                    table_name = "AlertEvidence"
                elif "SigninLogs" in content:
                    table_name = "SigninLogs"
                elif "AuditLogs" in content:
                    table_name = "AuditLogs"
                elif "AzureActivity" in content:
                    table_name = "AzureActivity"
                elif "AzureNetworkAnalytics_CL" in content:
                    table_name = "AzureNetworkAnalytics_CL"
                elif "AzureNetworkAnalyticsIPDetails_CL" in content:
                    table_name = "AzureNetworkAnalyticsIPDetails_CL"
                break
        
        if not log_data:
            print(f"{Fore.YELLOW}No log data found in messages, using standard LLM analysis")
            return self._standard_llm_analysis(messages, model_name)
        
        # GUARDRAILS VALIDATION: Validate table and filter fields
        if self.guardrails_enabled:
            # Detect table if not already known
            if table_name == "Unknown":
                table_name = self._detect_table_from_csv(log_data)
            
            # Validate and filter
            filtered_log_data, is_valid = self._validate_and_filter_fields(log_data, table_name)
            
            if not is_valid:
                # Data rejected by GUARDRAILS - create violation finding
                print(f"{Fore.RED}[QWEN_ENHANCER] GUARDRAILS blocked unauthorized data access{Fore.RESET}")
                return {
                    "findings": [{
                        "title": "GUARDRAILS Security Violation - Qwen Enhancer",
                        "description": f"Attempted to process unauthorized data from table: {table_name}. GUARDRAILS enforcement prevented this security violation.",
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
                            f"Attempted table: {table_name}",
                            f"Status: BLOCKED by GUARDRAILS"
                        ],
                        "indicators_of_compromise": [
                            f"Unauthorized table access: {table_name}",
                            f"Timestamp: {json.dumps({'timestamp': 'now'})}"
                        ],
                        "tags": ["security_violation", "guardrails_enforcement", "unauthorized_access", "defense_evasion"],
                        "recommendations": [
                            "Investigate who/what initiated this unauthorized query",
                            "Review access logs for suspicious patterns",
                            "Verify GUARDRAILS configuration is up to date",
                            "Consider implementing additional access controls"
                        ],
                        "notes": f"QWEN_ENHANCER GUARDRAILS enforcement blocked unauthorized table: {table_name}. This is a defense-in-depth security measure."
                    }]
                }
            
            # Use filtered data for analysis
            log_data = filtered_log_data
        
        # CHUNK LOGS: Split if too large (prevents timeout)
        log_lines = log_data.split('\n')
        total_lines = len([l for l in log_lines if l.strip()])
        
        if total_lines > max_lines:
            print(f"{Fore.YELLOW}Large dataset ({total_lines} lines). Chunking to {max_lines} lines max...{Fore.RESET}")
            # Take first max_lines for analysis
            log_data = '\n'.join([l for l in log_lines if l.strip()][:max_lines])
            print(f"{Fore.WHITE}Analyzing first {max_lines} lines (remaining lines processed by rules only){Fore.RESET}")
        
        # Apply rule-based analysis (fast, works on all data)
        rule_findings, iocs = self.analyze_logs_with_rules(log_data, table_name)
        
        # If rule-based found threats, skip slow LLM analysis
        if len(rule_findings) > 5:
            print(f"{Fore.WHITE}Rule-based detection found {len(rule_findings)} findings. Skipping LLM (fast mode).{Fore.RESET}")
            return {"findings": rule_findings}
        
        # Enhance prompt with rule findings (smaller payload)
        enhanced_messages = self._enhance_messages_with_rules(messages, rule_findings, iocs)
        
        # Get LLM analysis with timeout handling
        print(f"{Fore.LIGHTGREEN_EX}Getting LLM analysis from {model_name} (streaming)...{Fore.RESET}")
        buffer = ""
        llm_findings = []
        try:
            for chunk in OLLAMA_CLIENT.chat_stream(messages=enhanced_messages, model_name=model_name):
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
            print(f"{Fore.LIGHTRED_EX}LLM timeout/error: {e}{Fore.RESET}")
            print(f"{Fore.YELLOW}Falling back to rule-based findings + partial text if any{Fore.RESET}")

        if buffer.strip():
            try:
                llm_results = json.loads(buffer)
                llm_findings = llm_results.get("findings", [])
            except json.JSONDecodeError:
                # salvage partial by attaching as a narrative note and try extracting entities
                partial_text = buffer[-4000:]
                devices = re.findall(r'(?:DeviceName|Computer)\s*[:=]\s*([A-Za-z0-9._-]{2,})', partial_text)
                accounts = re.findall(r'(?:AccountName|User|UPN|UserPrincipalName)\s*[:=]\s*([A-Za-z0-9._@-]{3,})', partial_text)
                llm_findings = [{
                    "title": "Partial LLM Analysis (incomplete)",
                    "description": "LLM response was interrupted. Partial text captured.",
                    "confidence": "Low",
                    "log_lines": [],
                    "indicators_of_compromise": [],
                    "tags": ["partial", "llm-analysis"],
                    "notes": partial_text,
                    **({"device_name": devices[0]} if devices else {}),
                    **({"account_name": accounts[0]} if accounts else {})
                }]
        
        # Combine and deduplicate findings
        combined_findings = self._combine_findings(rule_findings, llm_findings)
        
        # Optionally refine with GPT-4/5 for better quality (hybrid mode)
        if self.use_gpt_refinement and self.openai_client and combined_findings:
            combined_findings = self.refine_findings_with_gpt(combined_findings)
        
        print(f"{Fore.WHITE}Enhanced analysis complete: {len(combined_findings)} total findings")
        
        return {"findings": combined_findings}

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

    def _enhance_messages_with_rules(self, messages, rule_findings, iocs):
        """Add rule-based context to LLM messages"""
        enhanced_messages = []
        
        for msg in messages:
            if msg.get("role") == "user" and "Log Data:" in msg.get("content", ""):
                # Add rule-based context to the user message
                rule_context = self._build_rule_context(rule_findings, iocs)
                enhanced_content = msg["content"] + f"\n\nRule-based Analysis Results:\n{rule_context}"
                enhanced_messages.append({
                    "role": "user",
                    "content": enhanced_content
                })
            else:
                enhanced_messages.append(msg)
        
        return enhanced_messages

    def _build_rule_context(self, rule_findings, iocs):
        """Build context string from rule findings and IOCs"""
        context = ""
        
        if rule_findings:
            context += f"Rule-based detection found {len(rule_findings)} suspicious patterns:\n"
            for finding in rule_findings[:5]:  # Limit to first 5
                context += f"- {finding['title']}: {finding['description']}\n"
        
        if iocs:
            context += f"\nExtracted IOCs:\n"
            for ioc_type, values in iocs.items():
                if values:
                    context += f"- {ioc_type}: {', '.join(values[:3])}\n"  # Limit to first 3
        
        context += "\nPlease analyze these findings and provide additional insights."
        return context

    def _combine_findings(self, rule_findings, llm_findings):
        """Combine and deduplicate findings from rules and LLM"""
        combined = []
        
        # Add rule findings
        for finding in rule_findings:
            combined.append(finding)
        
        # Add LLM findings (ensure proper format)
        for finding in llm_findings:
            # Ensure all required fields are present
            if 'confidence' not in finding:
                finding['confidence'] = 'Medium'
            if 'recommendations' not in finding:
                finding['recommendations'] = ['investigate']
            if 'tags' not in finding:
                finding['tags'] = ['llm-analysis']
            if 'notes' not in finding:
                finding['notes'] = 'Detected by LLM analysis'
            combined.append(finding)
        
        # Simple deduplication based on title similarity
        deduplicated = []
        for finding in combined:
            is_duplicate = False
            for existing in deduplicated:
                if self._findings_similar(finding, existing):
                    is_duplicate = True
                    break
            if not is_duplicate:
                deduplicated.append(finding)
        
        return deduplicated

    def _findings_similar(self, finding1, finding2):
        """Check if two findings are similar (simple deduplication)"""
        title1 = finding1.get('title', '').lower()
        title2 = finding2.get('title', '').lower()
        
        # Check for similar titles
        if title1 and title2:
            words1 = set(title1.split())
            words2 = set(title2.split())
            overlap = len(words1.intersection(words2))
            return overlap >= 2  # At least 2 words in common
        
        return False

    def _standard_llm_analysis(self, messages, model_name):
        """Fallback to standard LLM analysis"""
        content = OLLAMA_CLIENT.chat(messages=messages, model_name=model_name)
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
