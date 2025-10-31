"""
RULEPACK_ENGINE
Loads profile rulepacks (YAML/JSON) and produces KQL constraints.
Currently a stub returning constraints derived only from severity_config/profile metadata.
"""

from typing import Dict, List, Any


def build_kql_constraints(severity_config: Dict[str, Any]) -> Dict[str, Any]:
    """Return constraints dict with optional keys: tables, filters, project, limits.
    This stub uses severity_config hints. Real implementation should load profiles/<profile>/*.yml.
    """
    constraints: Dict[str, Any] = {}

    # Table scope from profile (if any)
    if 'table_scope' in severity_config and severity_config['table_scope']:
        constraints['tables'] = list(severity_config['table_scope'])

    # Limits from severity
    limits = {}
    if 'max_log_lines' in severity_config:
        limits['max_log_lines'] = severity_config['max_log_lines']
    constraints['limits'] = limits

    # Minimal projection guidance (can be expanded by real rulepacks)
    constraints['project'] = None  # Keep None to use pipeline defaults
    constraints['filters'] = []    # Keep empty to avoid changing behavior yet

    return constraints


