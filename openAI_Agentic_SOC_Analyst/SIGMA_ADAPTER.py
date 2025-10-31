from typing import List

def match_sigma_hints(csv_headers: List[str], known_killchain: str) -> List[str]:
    """Placeholder for pySigma-driven hints.

    Returns a small list of human-readable hints (not filters) that
    can be injected into the prompt. Non-blocking stub.
    """
    if not known_killchain:
        return []
    hints = []
    header_set = {h.lower() for h in csv_headers or []}
    if known_killchain and ("signinlogs" in "".join(header_set) or "userprincipalname" in header_set):
        hints.append("Check repeated failures across multiple users from the same IP(s)")
    return hints


