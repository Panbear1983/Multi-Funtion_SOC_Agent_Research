"""
Correlation Engine - Cross-Table Event Linking
Links related events across multiple log sources
Builds attack timelines and identifies attack chains
"""

import re
from datetime import datetime, timedelta
from collections import defaultdict
from color_support import Fore

class CorrelationEngine:
    def __init__(self):
        self.entity_map = defaultdict(list)  # {entity: [findings]}
        self.timeline = []  # Chronological event list
        self.attack_chains = []  # Linked attack sequences
    
    def correlate_findings(self, all_findings):
        """Correlate findings across tables to build attack chains"""
        
        if len(all_findings) < 2:
            return []  # Need at least 2 findings to correlate
        
        print(f"\n{Fore.LIGHTCYAN_EX}🔗 Correlating {len(all_findings)} findings...{Fore.RESET}")
        
        # Extract entities from all findings
        self._build_entity_map(all_findings)
        
        # Build timeline
        self._build_timeline(all_findings)
        
        # Identify attack chains
        chains = self._identify_attack_chains()
        
        print(f"{Fore.LIGHTGREEN_EX}✓ Found {len(chains)} potential attack chains{Fore.RESET}\n")
        
        return chains
    
    def _build_entity_map(self, findings):
        """Map entities (users, devices, IPs) to their findings"""
        
        for i, finding in enumerate(findings):
            # Extract entities from IOCs
            iocs = finding.get('indicators_of_compromise', [])
            
            for ioc in iocs:
                ioc_str = str(ioc).lower()
                
                # Extract entity type and value
                if 'account:' in ioc_str or 'user:' in ioc_str:
                    entity = ioc_str.split(':')[-1].strip()
                    entity_type = 'user'
                elif 'device:' in ioc_str:
                    entity = ioc_str.split(':')[-1].strip()
                    entity_type = 'device'
                elif re.match(r'\d+\.\d+\.\d+\.\d+', ioc_str):
                    entity = ioc_str
                    entity_type = 'ip'
                else:
                    continue
                
                # Map entity to finding
                self.entity_map[f"{entity_type}:{entity}"].append({
                    'finding_index': i,
                    'finding': finding,
                    'entity_type': entity_type,
                    'entity_value': entity
                })
    
    def _build_timeline(self, findings):
        """Build chronological timeline of events"""
        
        for i, finding in enumerate(findings):
            # Extract timestamps from log lines
            log_lines = finding.get('log_lines', [])
            
            for log in log_lines:
                # Try to parse timestamp (first field in CSV)
                parts = log.split(',')
                if len(parts) > 0:
                    timestamp_str = parts[0].strip()
                    try:
                        # Parse various timestamp formats
                        if 'T' in timestamp_str:
                            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        else:
                            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
                        
                        self.timeline.append({
                            'timestamp': timestamp,
                            'finding_index': i,
                            'finding': finding,
                            'log_line': log
                        })
                    except:
                        continue
        
        # Sort chronologically
        self.timeline.sort(key=lambda x: x['timestamp'])
    
    def _identify_attack_chains(self):
        """Identify sequences of related findings (attack chains)"""
        
        chains = []
        
        # Find entities that appear in multiple findings
        for entity_key, entity_findings in self.entity_map.items():
            if len(entity_findings) < 2:
                continue  # Need 2+ findings for a chain
            
            entity_type, entity_value = entity_key.split(':', 1)
            
            # Build chain from these findings
            chain = {
                'pivot_entity': f"{entity_type}: {entity_value}",
                'finding_count': len(entity_findings),
                'findings': [ef['finding'] for ef in entity_findings],
                'finding_indices': [ef['finding_index'] for ef in entity_findings],
                'tactics': self._extract_tactics(entity_findings),
                'confidence': self._assess_chain_confidence(entity_findings)
            }
            
            chains.append(chain)
        
        return chains
    
    def _extract_tactics(self, entity_findings):
        """Extract MITRE tactics from findings"""
        tactics = []
        for ef in entity_findings:
            mitre = ef['finding'].get('mitre', {})
            tactic = mitre.get('tactic', 'Unknown')
            if tactic and tactic != 'Unknown':
                tactics.append(tactic)
        return list(set(tactics))  # Unique tactics
    
    def _assess_chain_confidence(self, entity_findings):
        """Assess overall confidence of attack chain"""
        confidences = []
        for ef in entity_findings:
            conf = ef['finding'].get('confidence', 'Low')
            if conf == 'High':
                confidences.append(3)
            elif conf == 'Medium':
                confidences.append(2)
            else:
                confidences.append(1)
        
        avg = sum(confidences) / len(confidences) if confidences else 1
        
        if avg >= 2.5:
            return 'High'
        elif avg >= 1.5:
            return 'Medium'
        else:
            return 'Low'
    
    def display_attack_chains(self, chains):
        """Display correlated attack chains"""
        
        if not chains:
            return
        
        print(f"\n{Fore.LIGHTRED_EX}{'='*70}")
        print(f"{Fore.LIGHTRED_EX}🔗 CORRELATED ATTACK CHAINS")
        print(f"{Fore.LIGHTRED_EX}{'='*70}\n")
        
        for i, chain in enumerate(chains, 1):
            print(f"{Fore.LIGHTCYAN_EX}━━━ Attack Chain #{i} ━━━{Fore.RESET}")
            print(f"{Fore.WHITE}Pivot Entity: {Fore.LIGHTYELLOW_EX}{chain['pivot_entity']}")
            print(f"{Fore.WHITE}Linked Findings: {Fore.LIGHTRED_EX}{chain['finding_count']}")
            print(f"{Fore.WHITE}Chain Confidence: {Fore.LIGHTGREEN_EX}{chain['confidence']}")
            print(f"{Fore.WHITE}MITRE Tactics: {Fore.LIGHTCYAN_EX}{' → '.join(chain['tactics'])}")
            
            print(f"\n{Fore.LIGHTBLACK_EX}Linked Findings:")
            for idx in chain['finding_indices']:
                finding = chain['findings'][idx - chain['finding_indices'][0]]
                print(f"{Fore.WHITE}  [Finding #{idx + 1}] {finding.get('title', 'N/A')}")
            
            print(f"\n{Fore.LIGHTCYAN_EX}CHAIN ANALYSIS:")
            print(f"{Fore.WHITE}{self._generate_chain_narrative(chain)}")
            print(f"{Fore.LIGHTCYAN_EX}{'─'*70}\n")
    
    def _generate_chain_narrative(self, chain):
        """Generate narrative description of attack chain"""
        
        entity = chain['pivot_entity']
        count = chain['finding_count']
        tactics = chain['tactics']
        
        narrative = f"This attack chain involves {entity} across {count} separate activities. "
        
        if len(tactics) > 1:
            narrative += f"The attacker progressed through multiple tactics: {' → '.join(tactics)}. "
            narrative += "This indicates a coordinated, multi-stage attack. "
        
        if chain['confidence'] == 'High':
            narrative += "High confidence correlation suggests active compromise requiring immediate response."
        elif chain['confidence'] == 'Medium':
            narrative += "Medium confidence - warrants investigation and monitoring."
        else:
            narrative += "Lower confidence - may be legitimate activity, verify context."
        
        return narrative


# Global correlation engine
_correlation_engine = None

def get_correlation_engine():
    """Get or create global correlation engine"""
    global _correlation_engine
    if _correlation_engine is None:
        _correlation_engine = CorrelationEngine()
    return _correlation_engine


def correlate_findings(findings):
    """Correlate findings and return attack chains"""
    engine = get_correlation_engine()
    return engine.correlate_findings(findings)

