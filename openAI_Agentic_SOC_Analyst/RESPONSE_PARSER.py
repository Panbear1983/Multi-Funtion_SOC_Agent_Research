"""
RESPONSE_PARSER.py - Unified response parser for different output formats

Handles parsing of LLM responses for:
- Threat Hunt mode: {"findings": [...]}
- CTF mode: {"suggested_answer": "...", "confidence": "...", ...}
"""

import json
from color_support import Fore


def parse_response(response_content, response_format="threat_hunt"):
    """
    Unified response parser for different formats
    
    Args:
        response_content: Raw LLM response (string or dict)
        response_format: "threat_hunt" or "ctf"
    
    Returns:
        Parsed response in appropriate format
    """
    try:
        # Handle both string and dict inputs (tolerates fences / prose around the JSON)
        if isinstance(response_content, str):
            import LLM_ROUTER
            data = LLM_ROUTER.extract_json(response_content)
            if not data:
                raise json.JSONDecodeError("no JSON object in reply", response_content[:50], 0)
        else:
            data = response_content
        
        if response_format == "ctf":
            return parse_ctf_format(data)
        else:  # threat_hunt (default)
            return parse_threat_hunt_format(data)
            
    except json.JSONDecodeError as e:
        return parse_fallback(response_content, response_format, e)
    except Exception as e:
        print(f"{Fore.YELLOW}Error parsing response: {e}{Fore.RESET}")
        return parse_fallback(response_content, response_format, e)


def parse_ctf_format(data):
    """Parse CTF-specific format"""
    return {
        "suggested_answer": str(data.get("suggested_answer", "") or ""),
        "confidence": data.get("confidence", "Low") or "Low",
        "evidence_rows": data.get("evidence_rows", []) or [],
        "evidence_fields": data.get("evidence_fields", []) or [],
        "explanation": data.get("explanation", "") or "",
        "correlation": data.get("correlation", "") or "",
        "guidance": data.get("guidance", "") or "",
        "candidates": data.get("candidates", []) or [],
    }


def parse_threat_hunt_format(data):
    """Parse threat hunt format (default behavior)"""
    # Return as-is for threat hunt (backward compatibility)
    return data


def parse_fallback(response_content, response_format, error=None):
    """
    Fallback parsing when JSON decode fails
    
    Attempts to extract useful information from partial/invalid JSON
    """
    if response_format == "ctf":
        # Try to extract answer from text
        content_str = str(response_content)
        
        # Look for common patterns
        suggested_answer = ""
        confidence = "Low"
        explanation = content_str[:1000] if len(content_str) > 1000 else content_str
        
        # Do NOT guess an answer from the first IP/filename in the text (that invented
        # wrong flags before). Surface candidates in the explanation; the answer stays empty.
        import re
        candidates = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', content_str)[:5]
        candidates += re.findall(r'[\w\-]+\.(?:txt|exe|dll|bat|ps1|sh|zip|7z)', content_str, re.IGNORECASE)[:5]
        cand_note = f" Values mentioned in the reply: {', '.join(dict.fromkeys(candidates))}." if candidates else ""
        return {
            "suggested_answer": "",
            "confidence": "Low",
            "evidence_rows": [],
            "evidence_fields": [],
            "explanation": f"The model's reply was not valid JSON (error: {error}).{cand_note} Raw reply: {explanation}",
            "correlation": ""
        }
    else:
        # Threat hunt fallback
        return {
            "findings": [{
                "title": "Partial LLM Analysis (incomplete)",
                "description": f"LLM response parsing failed: {error}",
                "confidence": "Low",
                "log_lines": [],
                "indicators_of_compromise": [],
                "tags": ["partial", "llm-analysis"],
                "notes": str(response_content)[:1000]
            }]
        }

