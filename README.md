# Email Risk Scorer

Context-aware email risk analysis for Gmail.

Built as part of the Upwind Bootcamp assignment, this project analyzes an opened email and returns a risk score, verdict, explanations, and recommended actions.

The focus of this project is not just detecting malicious emails — but handling real-world ambiguity, where legitimate emails often look suspicious.

---

## Product Overview

This system is designed as a **decision-support tool**, not a binary classifier.

Instead of “safe vs malicious”, it provides:

- Risk score (0–100)
- Clear verdict (Very Low → Critical)
- Explainable risk signals
- Trust indicators
- Recommended actions

---

## Architecture

Two UI implementations share the same backend:

Gmail → UI Layer → FastAPI → Scoring Engine → Result

### UI Implementations

1. Gmail Add-on (Google Workspace APIs) – primary solution  
2. Chrome Extension – prototype for fast iteration  

---

## Detection Approach

Signal-based scoring model.

Each signal includes:
- severity  
- confidence  
- contribution  
- explanation  

---

## Scoring Logic

contribution = points × confidence  
score = Σ(risk signals) − Σ(trust signals)

---

## Project Structure

backend/  
chrome-extension/  
gmail-addon/  

---

## Key Takeaway

The challenge is not detecting signals — but interpreting them correctly in real-world workflows.
