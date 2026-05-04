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

> Key principle: Security systems must not only detect risk — they must earn user trust.

---

## Architecture

Two UI implementations share the same backend:

Gmail → UI Layer → FastAPI (/analyze-email) → Scoring Engine → Result

---

## UI Implementations

This project includes two UI layers, each serving a different purpose:

### 1. Gmail Add-on (Google Workspace APIs) — Primary Solution

- Fully aligned with assignment requirements
- Runs natively inside Gmail
- Uses structured Gmail APIs
- More stable and production-oriented

This represents the **correct architectural approach for deployment**.

---

### 2. Chrome Extension — Product Prototype

The Chrome extension was built as an additional layer for:

- Richer and more flexible UI
- Better visualization of risk

#### Why this matters

Gmail Add-ons are UI-limited (CardService), restricting:

- Layout flexibility  
- Visual hierarchy  
- Interaction richness  

The Chrome Extension enables:

- More intuitive UX
- Stronger visual feedback
- Higher user engagement potential

> From a product perspective, improved UI clarity can increase **user trust, acquisition & retention**.

---

## Design Decision

The system was designed with:

- A **shared backend (single source of truth)**
- Multiple UI clients

This allows:
- Faster product iteration
- Independent UI experimentation
- Reuse of the scoring engine

---

## Detection Approach

Signal-based scoring model.

Each signal includes:
- severity  
- confidence  
- contribution  
- explanation  

### Risk Signals

- Sensitive action requests (password, payment)
- Urgency / pressure language
- Domain mismatch
- Brand impersonation
- Suspicious links / TLDs
- URL shorteners
- Attachment references
- Gift card / redemption flows
- High number of links

### Trust Signals

- Trusted domains / SaaS platforms
- Domain alignment
- Informational payment context
- Informational password context
- Legitimate workflow patterns
- Human-written tone

---

## Scoring Logic

contribution = points × confidence  
score = Σ(risk signals) − Σ(trust signals)

Adjustments:
- Critical signals → enforce High risk
- High-confidence signals → enforce Medium
- Weak signals cannot dominate

The system exposes:
- Raw score
- Final score
- Score adjustments

---

## Project Structure

backend/           FastAPI + scoring engine  
chrome-extension/  Chrome extension UI  
gmail-addon/       Gmail Add-on implementation  

Each UI implementation includes its own README with:
- Architecture details
- Setup instructions
- Execution flow

---

## Key Takeaway

The challenge is not detecting signals —  
but interpreting them correctly in real-world workflows.

Focus:
- Explainability  
- Context awareness  
- Reducing false positives  
- Building user trust
