# Issue 9 — Reduce False Positives in Sensitive Information Detection

## Problem

The current "Sensitive Information Request" signal is too naive and produces false positives.

Example:
A legitimate payment receipt email containing words like "payment" or "amount" is incorrectly classified as high risk.

This happens because the system relies on keyword matching instead of understanding intent.

---

## Root Cause

Current logic:
- Detects keywords such as "payment", "billing", "transaction"
- Automatically assigns HIGH severity

Missing:
- Distinction between informational vs action-based intent
- Context awareness

---

## Goal

Improve detection logic to differentiate between:

1. Informational emails (safe)
2. Neutral/unclear context
3. Action-required emails (potentially malicious)

---

## Requirements

### 1. Introduce Intent-Based Classification

Classify emails into:

#### Safe / Informational
Examples:
- "Thank you for your purchase"
- "Here is your receipt"
- "Order summary"
- "Payment confirmation"

Expected behavior:
- LOW severity
- Low confidence
- May trigger trust signal

---

#### Neutral
Examples:
- "Billing information"
- "Account details"

Expected behavior:
- MEDIUM severity
- Moderate confidence

---

#### Sensitive Action Required
Examples:
- "Verify your payment"
- "Update your payment details"
- "Click to complete payment"
- "Payment failed — fix now"

Expected behavior:
- HIGH or CRITICAL severity
- High confidence

---

### 2. Implement Keyword Groups

Define:

- PAYMENT_CONTEXT_KEYWORDS  
  (payment, invoice, billing, transaction)

- SAFE_CONTEXT_KEYWORDS  
  (receipt, confirmation, thank you, order summary, total amount)

- ACTION_KEYWORDS  
  (verify, update, confirm, click, complete, fix, urgent, action required)

---

### 3. Update Detection Logic

Replace naive rule with:

- If PAYMENT keywords exist:
  - If SAFE keywords exist → downgrade severity
  - If ACTION keywords exist → raise severity
  - Otherwise → medium severity

---

### 4. Add Trust Signal

If email clearly matches receipt/confirmation pattern:

- Reduce score (e.g., -8 to -12 points)
- Add explanation:
  "Informational payment email detected (receipt/confirmation)"

---

### 5. Preserve Security

Important:
- Do NOT fully suppress the signal
- Malicious emails can mimic receipts
- Only reduce confidence/severity, not eliminate detection

---

## Expected Outcome

- Reduced false positives for:
  - Receipts
  - Order confirmations
  - Transaction summaries

- Improved alignment between:
  - Score
  - Verdict
  - Explanation

- More realistic behavior in real-world email scenarios

---

## Validation

Test against:
- Legitimate receipts (e.g., payment confirmations)
- Real SaaS billing emails
- Simulated phishing emails requesting payment updates

Success criteria:
- Legitimate receipts → LOW risk
- Action-based payment emails → HIGH risk