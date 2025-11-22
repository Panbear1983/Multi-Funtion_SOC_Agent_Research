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
        # Handle both string and dict inputs
        if isinstance(response_content, str):
            data = json.loads(response_content)
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
        "suggested_answer": data.get("suggested_answer", ""),
        "confidence": data.get("confidence", "Low"),
        "evidence_rows": data.get("evidence_rows", []),
        "evidence_fields": data.get("evidence_fields", []),
        "explanation": data.get("explanation", ""),
        "correlation": data.get("correlation", "")
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
        
        # Try to find answer-like patterns
        import re
        # IP address pattern
        ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', content_str)
        if ip_match:
            suggested_answer = ip_match.group(0)
        
        # Filename pattern
        if not suggested_answer:
            filename_match = re.search(r'[\w\-_]+\.(txt|exe|dll|bat|ps1|sh)', content_str, re.IGNORECASE)
            if filename_match:
                suggested_answer = filename_match.group(0)
        
        return {
            "suggested_answer": suggested_answer,
            "confidence": "Low",
            "evidence_rows": [],
            "evidence_fields": [],
            "explanation": f"Partial parsing (JSON error: {error}). Extracted: {explanation}",
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

