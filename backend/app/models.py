from pydantic import BaseModel, Field, HttpUrl
from typing import List, Optional


class AnalyzeEmailRequest(BaseModel):
    subject: str = Field(default="", max_length=500)
    body: str = Field(default="", max_length=20000)
    sender: str = Field(default="", max_length=500)
    links: List[str] = Field(default_factory=list, max_length=100)


class DetectionReason(BaseModel):
    signal: str
    severity: str
    confidence: float
    points: int
    contribution: float   # = points × confidence — actual score impact of this signal
    explanation: str


class TrustSignal(BaseModel):
    signal: str
    points_reduction: int
    explanation: str


class RecommendedAction(BaseModel):
    title: str
    steps: List[str]


class ScoreAdjustment(BaseModel):
    type: str          # "verdict_floor" | "verdict_ceiling"
    reason: str
    from_score: int
    to_score: int


class AnalyzeEmailResponse(BaseModel):
    score: int
    raw_score: int
    score_adjustments: List[ScoreAdjustment]
    verdict: str
    reasons: List[DetectionReason]
    trust_signals: List[TrustSignal]
    actions: List[RecommendedAction]
    recommendation: str
