from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.models import AnalyzeEmailRequest, AnalyzeEmailResponse
from app.scorer import score_email

app = FastAPI(title="Gmail Email Risk Assessor", version="0.1.0")

# For local demo only. Restrict origins before production usage.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze-email", response_model=AnalyzeEmailResponse)
def analyze_email(payload: AnalyzeEmailRequest):
    result = score_email(
        subject=payload.subject,
        body=payload.body,
        sender=payload.sender,
        links=payload.links,
    )
    return AnalyzeEmailResponse(**result)
