"""
Behavioral Baseline System
Learns normal behavior patterns and detects deviations
Identifies anomalies that rules and signatures miss
"""

import json
import os
from datetime import datetime, timedelta
from collections import defaultdict
from color_support import Fore

class BehavioralBaseline:
    def __init__(self, baseline_file="behavioral_baseline.json"):
        self.baseline_file = baseline_file
        self.baselines = self._load_baselines()
    
    def _load_baselines(self):
        """Load existing baselines or create empty structure"""
        if not os.path.exists(self.baseline_file):
            return self._create_empty_baseline()
        
        try:
            with open(self.baseline_file, 'r') as f:
                baselines = json.load(f)
                print(f"{Fore.LIGHTCYAN_EX}📊 Loaded behavioral baselines{Fore.RESET}")
                return baselines
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Could not load baselines: {e}{Fore.RESET}")
            return self._create_empty_baseline()
    
    def _create_empty_baseline(self):
        """Create empty baseline structure"""
        return {
            '_meta': {
                'created': datetime.now().isoformat(),
                'last_updated': None,
                'total_events_learned': 0
            },
            'users': {},      # {user: {login_times: [], devices: [], ips: []}}
            'devices': {},    # {device: {users: [], processes: [], connections: []}}
            'network': {},    # {device: {destination_ips: [], ports: [], protocols: []}}
            'processes': {},  # {device: {commands: [], parent_child: []}}
            'rare_events': set()  # Events seen < 3 times
        }
    
    def _save_baselines(self):
        """Save baselines to disk"""
        try:
            # Convert sets to lists for JSON serialization
            serializable = dict(self.baselines)
            if 'rare_events' in serializable and isinstance(serializable['rare_events'], set):
                serializable['rare_events'] = list(serializable['rare_events'])
            
            with open(self.baseline_file, 'w') as f:
                json.dump(serializable, f, indent=2)
            print(f"{Fore.LIGHTGREEN_EX}💾 Saved behavioral baselines{Fore.RESET}")
        except Exception as e:
            print(f"{Fore.RED}Error saving baselines: {e}{Fore.RESET}")
    
    def learn_from_logs(self, log_data, table_name):
        """Build baseline from log data (training phase)"""
        
        print(f"{Fore.LIGHTCYAN_EX}🧠 Learning behavioral patterns from {table_name}...{Fore.RESET}")
        
        lines = log_data.split('\n')
        events_learned = 0
        
        for line in lines[1:]:  # Skip header
            if not line.strip():
                continue
            
            parts = line.split(',')
            if len(parts) < 3:
                continue
            
            # Common fields: timestamp, account, device
            timestamp = parts[0].strip() if len(parts) > 0 else ''
            account = parts[1].strip() if len(parts) > 1 else ''
            device = parts[2].strip() if len(parts) > 2 else ''
            
            # Learn user behavior
            if account and account not in ['AccountName']:
                if account not in self.baselines['users']:
                    self.baselines['users'][account] = {
                        'devices': set(),
                        'login_hours': [],
                        'ips': set()
                    }
                
                if device:
                    self.baselines['users'][account]['devices'].add(device)
                
                # Extract hour from timestamp
                try:
                    if 'T' in timestamp:
                        hour = int(timestamp.split('T')[1].split(':')[0])
                        self.baselines['users'][account]['login_hours'].append(hour)
                except:
                    pass
                
                # Extract IP if present
                if len(parts) > 4:
                    ip = parts[4].strip()
                    if ip and re.match(r'\d+\.\d+\.\d+\.\d+', ip):
                        self.baselines['users'][account]['ips'].add(ip)
            
            # Learn device behavior
            if device and device not in ['DeviceName']:
                if device not in self.baselines['devices']:
                    self.baselines['devices'][device] = {
                        'users': set(),
                        'process_count': 0
                    }
                
                if account:
                    self.baselines['devices'][device]['users'].add(account)
                
                self.baselines['devices'][device]['process_count'] += 1
            
            events_learned += 1
        
        self.baselines['_meta']['last_updated'] = datetime.now().isoformat()
        self.baselines['_meta']['total_events_learned'] = self.baselines['_meta'].get('total_events_learned', 0) + events_learned
        
        self._save_baselines()
        
        print(f"{Fore.LIGHTGREEN_EX}✓ Learned from {events_learned} events{Fore.RESET}")
    
    def detect_anomalies(self, log_data, table_name):
        """Detect anomalies by comparing to baseline"""
        
        if not self.baselines.get('users') and not self.baselines.get('devices'):
            print(f"{Fore.YELLOW}⚠️  No baseline established. Run in learning mode first.{Fore.RESET}")
            return []
        
        print(f"{Fore.LIGHTCYAN_EX}🔍 Checking for behavioral anomalies...{Fore.RESET}")
        
        anomalies = []
        lines = log_data.split('\n')
        
        for line_num, line in enumerate(lines[1:], 1):  # Skip header
            if not line.strip():
                continue
            
            parts = line.split(',')
            if len(parts) < 3:
                continue
            
            timestamp = parts[0].strip() if len(parts) > 0 else ''
            account = parts[1].strip() if len(parts) > 1 else ''
            device = parts[2].strip() if len(parts) > 2 else ''
            
            # Check user anomalies
            if account and account in self.baselines['users']:
                baseline_user = self.baselines['users'][account]
                
                # New device for this user?
                if device and device not in baseline_user.get('devices', set()):
                    anomalies.append({
                        'type': 'first_time_device',
                        'description': f"User '{account}' accessed device '{device}' for first time",
                        'line': line,
                        'confidence': 'Medium',
                        'severity': 'anomaly'
                    })
                
                # Unusual hour?
                try:
                    if 'T' in timestamp:
                        hour = int(timestamp.split('T')[1].split(':')[0])
                        typical_hours = baseline_user.get('login_hours', [])
                        if typical_hours and hour not in typical_hours:
                            anomalies.append({
                                'type': 'unusual_time',
                                'description': f"User '{account}' active at unusual hour: {hour}:00",
                                'line': line,
                                'confidence': 'Low',
                                'severity': 'anomaly'
                            })
                except:
                    pass
                
                # New IP?
                if len(parts) > 4:
                    ip = parts[4].strip()
                    if ip and re.match(r'\d+\.\d+\.\d+\.\d+', ip):
                        if ip not in baseline_user.get('ips', set()):
                            anomalies.append({
                                'type': 'first_time_ip',
                                'description': f"User '{account}' connected from new IP: {ip}",
                                'line': line,
                                'confidence': 'Medium',
                                'severity': 'anomaly'
                            })
            
            # Check for completely new users
            elif account and account not in ['AccountName', '']:
                if account not in self.baselines['users']:
                    anomalies.append({
                        'type': 'new_user',
                        'description': f"First time seeing user: '{account}'",
                        'line': line,
                        'confidence': 'Low',
                        'severity': 'anomaly'
                    })
        
        print(f"{Fore.WHITE}Detected {len(anomalies)} behavioral anomalies{Fore.RESET}")
        return anomalies
    
    def get_baseline_summary(self):
        """Get summary of baseline statistics"""
        return {
            'total_users': len(self.baselines.get('users', {})),
            'total_devices': len(self.baselines.get('devices', {})),
            'events_learned': self.baselines.get('_meta', {}).get('total_events_learned', 0),
            'last_updated': self.baselines.get('_meta', {}).get('last_updated', 'Never')
        }


# Global baseline instance
_baseline = None

def get_baseline():
    """Get or create global baseline instance"""
    global _baseline
    if _baseline is None:
        _baseline = BehavioralBaseline()
    return _baseline

