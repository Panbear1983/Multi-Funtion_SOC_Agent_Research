"""
Local Query Parser - Offline Query Planning
Parses user queries without LLM using keyword matching and regex
Enables 100% offline operation
"""

import re
from color_support import Fore

class LocalQueryParser:
    def __init__(self):
        # Table selection keywords
        self.table_keywords = {
            'DeviceLogonEvents': ['login', 'logon', 'auth', 'authentication', 'sign in', 'signin'],
            'DeviceProcessEvents': ['process', 'command', 'execution', 'exec', 'cmd', 'powershell', 'script'],
            'DeviceNetworkEvents': ['network', 'connection', 'traffic', 'ip', 'port', 'c2', 'beacon'],
            'DeviceFileEvents': ['file', 'folder', 'path', 'download', 'upload', 'create', 'delete'],
            'DeviceRegistryEvents': ['registry', 'reg', 'hive', 'key', 'persistence'],
            'SigninLogs': ['azure', 'cloud', 'signin', 'sign-in', 'aad', 'entra'],
            'AzureActivity': ['azure', 'resource', 'subscription', 'portal', 'rbac', 'role'],
            'AzureNetworkAnalytics_CL': ['nsg', 'firewall', 'flow', 'network security']
        }
        
        # Default fields per table (All Log Analytics tables use 'TimeGenerated')
        # Note: MDE Advanced Hunting uses 'Timestamp', but Log Analytics export uses 'TimeGenerated'
        self.default_fields = {
            'DeviceProcessEvents': ['TimeGenerated', 'AccountName', 'ActionType', 'DeviceName', 'InitiatingProcessCommandLine', 'ProcessCommandLine'],
            'DeviceFileEvents': ['TimeGenerated', 'ActionType', 'DeviceName', 'FileName', 'FolderPath', 'InitiatingProcessAccountName', 'SHA256'],
            'DeviceLogonEvents': ['TimeGenerated', 'AccountName', 'DeviceName', 'ActionType', 'RemoteIP', 'RemoteDeviceName'],
            'DeviceNetworkEvents': ['TimeGenerated', 'ActionType', 'DeviceName', 'RemoteIP', 'RemotePort'],
            'DeviceRegistryEvents': ['TimeGenerated', 'ActionType', 'DeviceName', 'RegistryKey'],
            'AzureNetworkAnalytics_CL': ['TimeGenerated', 'FlowType_s', 'SrcPublicIPs_s', 'DestIP_s', 'DestPort_d', 'VM_s'],
            'AzureActivity': ['TimeGenerated', 'OperationNameValue', 'ActivityStatusValue', 'ResourceGroup', 'Caller', 'CallerIpAddress', 'Category'],
            'SigninLogs': ['TimeGenerated', 'UserPrincipalName', 'OperationName', 'Category', 'ResultSignature', 'ResultDescription', 'AppDisplayName', 'IPAddress', 'LocationDetails']
        }
    
    def parse(self, user_query):
        """Parse user query to determine search parameters"""
        
        query_lower = user_query.lower()
        
        # Determine table
        table_name = self._determine_table(query_lower)
        
        # Extract entities
        device_name = self._extract_device(user_query)
        user_name = self._extract_user(user_query)
        caller = self._extract_caller(user_query)
        
        # Extract time range
        time_range_hours = self._extract_timerange(query_lower)
        
        # Get fields
        fields = self.default_fields.get(table_name, [])
        
        # Build rationale
        rationale = f"Parsed locally: Detected {table_name} query for "
        if device_name:
            rationale += f"device '{device_name}' "
        if user_name:
            rationale += f"user '{user_name}' "
        rationale += f"over {time_range_hours} hours"
        
        print(f"{Fore.LIGHTCYAN_EX}📋 Local parser determined:{Fore.RESET}")
        print(f"{Fore.WHITE}  Table: {table_name}")
        print(f"{Fore.WHITE}  Device: {device_name if device_name else '(all)'}")
        print(f"{Fore.WHITE}  User: {user_name if user_name else '(all)'}")
        print(f"{Fore.WHITE}  Time: {time_range_hours} hours{Fore.RESET}\n")
        
        return {
            'table_name': table_name,
            'device_name': device_name,
            'user_principal_name': user_name,
            'caller': caller,
            'time_range_hours': time_range_hours,
            'fields': fields,
            'about_individual_user': bool(user_name),
            'about_individual_host': bool(device_name),
            'about_network_security_group': 'nsg' in query_lower or 'firewall' in query_lower,
            'rationale': rationale
        }
    
    def _determine_table(self, query_lower):
        """Determine which table to query based on keywords"""
        
        # Score each table
        scores = {}
        for table, keywords in self.table_keywords.items():
            score = sum(1 for kw in keywords if kw in query_lower)
            if score > 0:
                scores[table] = score
        
        if not scores:
            # Default to DeviceLogonEvents if uncertain
            return 'DeviceLogonEvents'
        
        # Return table with highest score
        return max(scores, key=scores.get)
    
    def _extract_device(self, query):
        """Extract device/hostname from query"""
        
        # Common patterns
        patterns = [
            r'device[:\s]+([a-zA-Z0-9\-_]+)',
            r'host[:\s]+([a-zA-Z0-9\-_]+)',
            r'computer[:\s]+([a-zA-Z0-9\-_]+)',
            r'machine[:\s]+([a-zA-Z0-9\-_]+)',
            r'server[:\s]+([a-zA-Z0-9\-_]+)',
            r'on\s+([a-zA-Z0-9\-_]+)',
            r'from\s+([a-zA-Z0-9\-_]+)',
            r'([a-zA-Z0-9]+-target-[0-9]+)',  # Common naming pattern
            r'(windows-[a-zA-Z0-9\-]+)',
            r'(server-[0-9]+)',
            r'(vm-[0-9]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, query, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return ""
    
    def _extract_user(self, query):
        """Extract username from query"""
        
        patterns = [
            r'accountname\s+contains\s+[\'"]([a-zA-Z0-9@._\-]+)[\'"]',  # AccountName contains 'value'
            r'accountname\s+contains\s+([a-zA-Z0-9@._\-]+)',  # AccountName contains value
            r'account\s+contains\s+[\'"]([a-zA-Z0-9@._\-]+)[\'"]',
            r'user[:\s]+([a-zA-Z0-9@._\-]+)',
            r'account[:\s]+([a-zA-Z0-9@._\-]+)',
            r'username[:\s]+([a-zA-Z0-9@._\-]+)',
            r'accountname[:\s]+([a-zA-Z0-9@._\-]+)',
            r'principal[:\s]+([a-zA-Z0-9@._\-]+)',
            r'for\s+([a-zA-Z0-9@._\-]+@[a-zA-Z0-9._\-]+)',  # Email format
            r'by\s+([a-zA-Z0-9@._\-]+@[a-zA-Z0-9._\-]+)',
            r'account\s+name\s+[\'"]([a-zA-Z0-9@._\-]+)[\'"]',
            r'with\s+name\s+[\'"]([a-zA-Z0-9@._\-]+)[\'"]'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, query, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return ""
    
    def _extract_caller(self, query):
        """Extract caller (Azure Activity context)"""
        return self._extract_user(query)  # Same extraction logic
    
    def _extract_timerange(self, query_lower):
        """Extract time range from query"""
        
        # Look for explicit time mentions
        if 'last 24 hours' in query_lower or '24 hours' in query_lower or 'today' in query_lower:
            return 24
        if 'last 48 hours' in query_lower or '48 hours' in query_lower or 'yesterday' in query_lower:
            return 48
        if 'last 7 days' in query_lower or '7 days' in query_lower or 'week' in query_lower:
            return 168
        if 'last 30 days' in query_lower or '30 days' in query_lower or 'month' in query_lower:
            return 720
        if 'last 3 days' in query_lower or '3 days' in query_lower:
            return 72
        
        # Look for digit + time unit
        hour_match = re.search(r'(\d+)\s*hours?', query_lower)
        if hour_match:
            return int(hour_match.group(1))
        
        day_match = re.search(r'(\d+)\s*days?', query_lower)
        if day_match:
            return int(day_match.group(1)) * 24
        
        # Default to 4 days
        return 96


# Global parser instance
_parser = None

def get_local_parser():
    """Get or create global parser instance"""
    global _parser
    if _parser is None:
        _parser = LocalQueryParser()
    return _parser


def parse_query_locally(user_query):
    """Parse query without LLM - fully offline"""
    parser = get_local_parser()
    return parser.parse(user_query)

