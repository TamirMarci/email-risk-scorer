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
- Trust indicators (why an email might be legitimate)
- Recommended actions for high-risk cases

> Key principle: Security systems must not only detect risk — they must earn user trust.

---

## Architecture

Gmail → Chrome Extension → FastAPI (/analyze-email)  
→ Scoring Engine → Score + Verdict + Explanations

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

raw score = Σ(contributions) − Σ(trust signals)

Adjustments:
- Critical signals → force High
- High-confidence signals → force Medium
- Weak signals cannot dominate

---

## Key Engineering Decisions

### Explainability over ML
Full transparency and debuggability.

### Context-Aware Detection
Distinguishes between:
- Informational vs action-based intent

### False Positive Reduction
Handled real-world cases like:
- receipts
- SaaS emails
- gift cards

### Score Transparency
Exposes raw score, final score, and adjustments.

---

## Validation

Tested on:
- Payment confirmations
- SaaS notifications
- Gift cards
- Phishing emails

Results:
- Reduced false positives  
- Better score alignment  
- Clearer explanations  

---

## Security

- No email content stored  
- No links executed  
- No attachments downloaded  
- No external APIs  

---

## Trade-offs

- Rule-based → explainable but less adaptive  
- Chrome Extension → fast dev, not production-ready  
- No threat intel → simpler but less accurate  

---

## Limitations

- Not a Gmail Add-on yet  
- Heuristic-based  
- No SPF/DKIM checks  
- No domain reputation  

---

## Running

cd backend  
python -m venv .venv  

Windows:  
.venv\Scripts\Activate.ps1  

pip install -r requirements.txt  
uvicorn app.main:app --reload --port 8000  

Load extension via chrome://extensions

---

## Key Takeaway

The challenge is not detecting signals —  
but interpreting them correctly in real-world email workflows.

Focus:
- Explainability  
- Context awareness  
- Reducing false positives  
- Building user trust
