from typing import Optional

def get_killchain_exemplar(known_killchain: Optional[str]) -> str:
    """Return a tiny exemplar for a known killchain. Soft stub.

    Keep exemplar extremely small (≤10–15% of prompt tokens) and
    evidence-focused. This is a placeholder that can later be backed by
    a vector store.
    """
    if not known_killchain:
        return ""

    kc = (known_killchain or "").strip().lower()
    if kc in {"rdp_password_spray", "rdp-password-spray", "rdp spray"}:
        return (
            "KNOWN PATTERN EXEMPLAR: RDP Password Spray\n"
            "Signature: Many failed SigninLogs across multiple accounts from same IP(s)\n"
            "Indicators: Same IP repeated; eventual single success after bursts\n"
            "Output Requirements: findings[].evidence_rows, findings[].evidence_fields, findings[].indicators_of_compromise\n"
            "MITRE: Credential Access (T1110.001)\n"
        )
    return (
        f"KNOWN PATTERN EXEMPLAR: {known_killchain}\n"
        "Output Requirements: evidence_rows, evidence_fields, indicators_of_compromise; include MITRE if applicable\n"
    )


