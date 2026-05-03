# Issue 4 — Improve Scoring Formula

## Each signal must include:
- severity
- confidence
- contribution = weight × confidence

## Final score:
Score = sum(contributions) - trust reductions
Clamp 0–100

## Goal
Make scoring transparent and consistent.
