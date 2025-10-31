from color_support import Fore

# Simple registry describing framework profiles. Content/rulepacks live in profiles/ dir.
PROFILES = {
    'none': {
        'name': 'No Framework',
        'description': 'General threat hunting without framework constraints.',
        'table_scope': None,
        'include_rulepacks': [],
        'alert_style': Fore.WHITE,
    },
    'owasp': {
        'name': 'OWASP (App/API Focus)',
        'description': 'Web/app/API centric checks and detections.',
        'table_scope': ['SigninLogs', 'AppGatewayFirewallLog'],
        'include_rulepacks': ['owasp_auth_abuse'],
        'alert_style': Fore.CYAN,
    },
    'stig': {
        'name': 'STIG (Hardening/Compliance)',
        'description': 'System hardening, policy drift, control compliance.',
        'table_scope': ['DeviceRegistryEvents', 'DeviceEvents', 'AzureActivity'],
        'include_rulepacks': ['stig_baseline_controls'],
        'alert_style': Fore.LIGHTMAGENTA_EX,
    },
    'cis': {
        'name': 'CIS Benchmarks',
        'description': 'Baseline configuration controls and deviations.',
        'table_scope': ['AzureActivity', 'SigninLogs', 'DeviceEvents'],
        'include_rulepacks': ['cis_baseline_controls'],
        'alert_style': Fore.LIGHTBLUE_EX,
    },
    'mitre': {
        'name': 'MITRE ATT&CK',
        'description': 'Technique-aligned detections and prioritization.',
        'table_scope': None,
        'include_rulepacks': ['mitre_core_ttps'],
        'alert_style': Fore.LIGHTYELLOW_EX,
    },
}

DEFAULT_PROFILE = 'none'


def prompt_profile_selection():
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
    print(f"{Fore.LIGHTCYAN_EX}SELECT FRAMEWORK PROFILE")
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}")
    print(f"\n[1] None (General Hunting)")
    print(f"[2] OWASP (App/API)")
    print(f"[3] STIG (Hardening)")
    print(f"[4] CIS (Baseline)")
    print(f"[5] MITRE ATT&CK")
    print(f"\n{Fore.LIGHTCYAN_EX}{'─'*70}{Fore.RESET}")
    while True:
        try:
            choice = input(f"{Fore.LIGHTGREEN_EX}Select profile [1-5] (default: 1 None): {Fore.RESET}").strip()
            if not choice:
                sel = 'none'
                break
            mapping = {'1': 'none', '2': 'owasp', '3': 'stig', '4': 'cis', '5': 'mitre'}
            sel = mapping.get(choice)
            if sel:
                break
            print(f"{Fore.RED}Invalid input. Enter 1-5.{Fore.RESET}")
        except (KeyboardInterrupt, EOFError):
            sel = 'none'
            break
    cfg = PROFILES[sel]
    print(f"\n{cfg['alert_style']}✓ Selected Profile: {cfg['name']}{Fore.RESET}")
    print(cfg['description'])
    print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
    return sel


def apply_profile(severity_config, profile_key):
    """Merge profile metadata into severity config (non-destructive copy)."""
    merged = dict(severity_config)
    profile = PROFILES.get(profile_key, PROFILES[DEFAULT_PROFILE])
    if profile.get('table_scope') is not None:
        merged['table_scope'] = profile['table_scope']
    if profile.get('include_rulepacks') is not None:
        merged['include_rulepacks'] = profile['include_rulepacks']
    merged['profile'] = profile_key
    return merged


