from typing import List, Optional, Dict, Any

try:
    from pydantic import BaseModel, Field
except Exception:
    # Soft fallback if pydantic is not installed; keep non-breaking
    BaseModel = object  # type: ignore
    def Field(default=None, **kwargs):  # type: ignore
        return default


class MitreMapping(BaseModel):
    tactic: Optional[str] = Field(default=None)
    technique: Optional[str] = Field(default=None)
    sub_technique: Optional[str] = Field(default=None)
    id: Optional[str] = Field(default=None)
    description: Optional[str] = Field(default=None)


class Finding(BaseModel):
    title: Optional[str] = Field(default=None)
    description: Optional[str] = Field(default=None)
    mitre: Optional[MitreMapping] = Field(default=None)
    log_lines: Optional[List[str]] = Field(default=None)
    confidence: Optional[str] = Field(default=None)
    recommendations: Optional[List[str]] = Field(default=None)
    indicators_of_compromise: Optional[List[str]] = Field(default=None)
    tags: Optional[List[str]] = Field(default=None)
    notes: Optional[str] = Field(default=None)

    # Evidence-bound extensions (optional; used when guidance is enabled)
    evidence_rows: Optional[List[int]] = Field(default=None)
    evidence_fields: Optional[List[str]] = Field(default=None)
    confidence_rationale: Optional[str] = Field(default=None)


class FindingsResponse(BaseModel):
    findings: List[Finding] = Field(default_factory=list)


def validate_findings(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Soft validation for evidence-bound schema. Non-throwing.

    Returns the original payload (possibly unchanged). If pydantic is
    unavailable or validation fails, this function is a no-op.
    """
    try:
        if BaseModel is object:
            return payload
        _ = FindingsResponse(**payload)
        return payload
    except Exception:
        return payload


