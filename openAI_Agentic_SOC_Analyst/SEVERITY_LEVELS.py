"""
Investigation Severity Levels - 3-Tier Detection System
Allows user to choose detection sensitivity: Strict, Normal, or Relaxed
"""

from color_support import Fore

# Define 4 severity tiers
SEVERITY_TIERS = {
    'critical': {
        'name': 'CRITICAL (Maximum Alert)',
        'description': 'Extreme sensitivity. Reports everything including anomalies. Use during confirmed breaches or red team exercises.',
        'confidence_threshold': 0,  # Report ALL findings (including anomalies)
        'pattern_multiplier': 3.0,  # TRIPLE all pattern weights (was 2.0)
        'max_log_lines': 200,  # Maximum logs (was 150)
        'require_human_review': 3,  # Very low threshold (was 5)
        'mitre_tactics_priority': [
            'Initial Access', 'Execution', 'Persistence', 
            'Privilege Escalation', 'Defense Evasion',
            'Credential Access', 'Discovery', 'Lateral Movement',
            'Collection', 'Exfiltration', 'Impact', 'Command and Control'
        ],
        'alert_style': Fore.RED,
        'min_iocs_to_flag': 1,  # Flag with just 1 IOC
        'include_anomalies': True,  # Include statistical anomalies
        'zero_tolerance': True,  # No filtering - report everything
        'enable_behavioral_analysis': True  # Enable behavioral detection
    },
    
    'strict': {
        'name': 'STRICT (High Security)',
        'description': 'Maximum sensitivity. Flags everything suspicious. Use during active incidents.',
        'confidence_threshold': 0,  # Report ALL including anomalies
        'pattern_multiplier': 2.5,  # 2.5x boost (was 2.0)
        'max_log_lines': 175,  # More logs (was 150)
        'require_human_review': 4,  # Lower threshold (was 5)
        'mitre_tactics_priority': [
            'Initial Access', 'Execution', 'Persistence', 
            'Privilege Escalation', 'Defense Evasion',
            'Credential Access', 'Lateral Movement'
        ],
        'alert_style': Fore.LIGHTRED_EX,
        'min_iocs_to_flag': 1,  # Flag with just 1 IOC
        'include_anomalies': True,  # Include anomalies
        'enable_behavioral_analysis': True
    },
    
    'normal': {
        'name': 'NORMAL (Balanced)',
        'description': 'Standard detection. Good balance between false positives and coverage.',
        'confidence_threshold': 0,  # Report ALL (was 2)
        'pattern_multiplier': 2.0,  # Double boost (was 1.3)
        'max_log_lines': 125,  # More thorough (was 75)
        'require_human_review': 5,  # Lower threshold (was 6)
        'mitre_tactics_priority': [
            'Execution', 'Persistence', 'Privilege Escalation',
            'Credential Access', 'Lateral Movement'
        ],
        'alert_style': Fore.LIGHTYELLOW_EX,
        'min_iocs_to_flag': 1,  # Flag with 1 IOC
        'enable_behavioral_analysis': True
    },
    
    'relaxed': {
        'name': 'RELAXED (Low Noise)',
        'description': 'Minimal false positives. Only high-confidence threats. Use for routine monitoring.',
        'confidence_threshold': 2,  # Report Low+ (was 5)
        'pattern_multiplier': 1.5,  # 50% boost (was 1.0)
        'max_log_lines': 100,  # More analysis (was 50)
        'require_human_review': 6,  # Lower threshold (was 7)
        'mitre_tactics_priority': [
            'Persistence', 'Credential Access', 'Lateral Movement', 'Impact'
        ],
        'alert_style': Fore.LIGHTGREEN_EX,
        'min_iocs_to_flag': 1,  # Flag with 1 IOC (was 2)
        'enable_behavioral_analysis': False  # Disabled for speed
    }
}

# Default severity
DEFAULT_SEVERITY = 'normal'


def get_severity_config(severity_level=None):
    """Get configuration for specified severity level"""
    if severity_level is None:
        severity_level = DEFAULT_SEVERITY
    
    severity_level = severity_level.lower()
    
    if severity_level not in SEVERITY_TIERS:
        print(f"{Fore.YELLOW}Invalid severity level '{severity_level}'. Using 'normal'.{Fore.RESET}")
        severity_level = DEFAULT_SEVERITY
    
    return SEVERITY_TIERS[severity_level]


def prompt_severity_selection():
    """Interactive prompt for user to select severity level"""
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}SELECT INVESTIGATION SEVERITY LEVEL")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}")
    
    print(f"\n{Fore.RED}[1] CRITICAL - Maximum Alert Mode ⚠️")
    print(f"{Fore.WHITE}    • EXTREME sensitivity, reports EVERYTHING including anomalies")
    print(f"{Fore.WHITE}    • Use during: Confirmed breaches, forensic investigation, red team")
    print(f"{Fore.WHITE}    • Expect: Maximum alerts, significant false positives")
    print(f"{Fore.WHITE}    • Settings: 2x pattern boost, 150 log lines, zero filtering")
    
    print(f"\n{Fore.LIGHTRED_EX}[2] STRICT - High Security Mode")
    print(f"{Fore.WHITE}    • Maximum sensitivity, flags everything suspicious")
    print(f"{Fore.WHITE}    • Use during: Active incidents, breach investigation")
    print(f"{Fore.WHITE}    • Expect: High alert volume, more false positives")
    
    print(f"\n{Fore.LIGHTYELLOW_EX}[3] NORMAL - Balanced Mode (Default)")
    print(f"{Fore.WHITE}    • Standard detection, good balance")
    print(f"{Fore.WHITE}    • Use during: Daily operations, threat hunting")
    print(f"{Fore.WHITE}    • Expect: Moderate alerts, some false positives")
    
    print(f"\n{Fore.LIGHTGREEN_EX}[4] RELAXED - Low Noise Mode")
    print(f"{Fore.WHITE}    • High-confidence only, minimal false positives")
    print(f"{Fore.WHITE}    • Use during: Routine monitoring, report generation")
    print(f"{Fore.WHITE}    • Expect: Few alerts, high accuracy")
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'─'*70}")
    
    while True:
        try:
            choice = input(f"{Fore.LIGHTGREEN_EX}Select mode [1-4] or press Enter for Normal: {Fore.RESET}").strip()
            
            if not choice:
                severity = 'normal'
                break
            
            choice_num = int(choice)
            if choice_num == 1:
                severity = 'critical'
                break
            elif choice_num == 2:
                severity = 'strict'
                break
            elif choice_num == 3:
                severity = 'normal'
                break
            elif choice_num == 4:
                severity = 'relaxed'
                break
            else:
                print(f"{Fore.RED}Please enter 1, 2, 3, or 4.{Fore.RESET}")
        except ValueError:
            print(f"{Fore.RED}Invalid input. Enter 1, 2, 3, or 4.{Fore.RESET}")
    
    config = SEVERITY_TIERS[severity]
    print(f"\n{config['alert_style']}✓ Selected: {config['name']}{Fore.RESET}")
    print(f"{Fore.WHITE}{config['description']}{Fore.RESET}")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}\n")
    
    return severity


def apply_severity_to_confidence(base_confidence, severity_config):
    """
    Adjust confidence level based on severity tier
    Returns adjusted confidence string: Low, Medium, High
    """
    # Map confidence to numeric score
    confidence_map = {'Low': 3, 'Medium': 5, 'High': 8, 'Unknown': 3}
    score = confidence_map.get(base_confidence, 5)
    
    # Apply severity multiplier
    adjusted_score = score * severity_config['pattern_multiplier']
    
    # Remap to confidence level
    if adjusted_score >= 7:
        return 'High'
    elif adjusted_score >= 4:
        return 'Medium'
    else:
        return 'Low'


def should_report_finding(confidence, severity_config):
    """
    Determine if finding should be reported based on severity tier
    """
    confidence_map = {'Low': 3, 'Medium': 5, 'High': 8, 'Unknown': 3}
    score = confidence_map.get(confidence, 5)
    
    return score >= severity_config['confidence_threshold']


def filter_findings_by_severity(findings, severity_config):
    """
    Filter findings based on severity level
    Returns only findings that meet the severity threshold
    """
    filtered = []
    
    for finding in findings:
        confidence = finding.get('confidence', 'Medium')
        
        # Check if this finding meets the threshold
        if should_report_finding(confidence, severity_config):
            # Apply severity adjustment to confidence
            adjusted_conf = apply_severity_to_confidence(confidence, severity_config)
            finding['confidence'] = adjusted_conf
            finding['original_confidence'] = confidence
            filtered.append(finding)
    
    return filtered


def get_severity_stats(findings, severity_level):
    """
    Generate statistics about findings under current severity
    """
    config = get_severity_config(severity_level)
    
    total = len(findings)
    filtered = filter_findings_by_severity(findings, config)
    filtered_count = len(filtered)
    suppressed = total - filtered_count
    
    return {
        'total_findings': total,
        'reported_findings': filtered_count,
        'suppressed_findings': suppressed,
        'suppression_rate': (suppressed / total * 100) if total > 0 else 0,
        'severity_name': config['name']
    }


def display_severity_banner(severity_level):
    """Display current severity mode banner"""
    config = get_severity_config(severity_level)
    
    print(f"\n{config['alert_style']}{'='*70}")
    print(f"{config['alert_style']}INVESTIGATION MODE: {config['name']}")
    print(f"{config['alert_style']}{'='*70}{Fore.RESET}")
    print(f"{Fore.WHITE}• Confidence Threshold: {config['confidence_threshold']}/10")
    print(f"{Fore.WHITE}• Pattern Sensitivity: {int(config['pattern_multiplier'] * 100)}%")
    print(f"{Fore.WHITE}• Max Log Lines: {config['max_log_lines']}")
    print(f"{Fore.WHITE}• Human Review at: <{config['require_human_review']}/10 confidence")
    print(f"{config['alert_style']}{'='*70}{Fore.RESET}\n")


def get_severity_recommendations(severity_level, findings_count):
    """Provide recommendations based on current severity and findings"""
    recommendations = []
    
    if severity_level == 'strict' and findings_count > 20:
        recommendations.append("⚠️  High alert volume in STRICT mode. Consider switching to NORMAL mode.")
    
    if severity_level == 'relaxed' and findings_count == 0:
        recommendations.append("ℹ️  No findings in RELAXED mode. Try NORMAL mode for broader coverage.")
    
    if severity_level == 'normal' and findings_count > 50:
        recommendations.append("⚠️  Many findings detected. Review or switch to RELAXED mode to reduce noise.")
    
    return recommendations
