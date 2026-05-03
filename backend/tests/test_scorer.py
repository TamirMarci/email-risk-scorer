import pytest
from app.scorer import score_email, VERDICT_THRESHOLDS


# ── Hebrew receipt ──────────────────────────────────────────────────────────

def test_hebrew_legitimate_receipt_low_risk():
    """Order confirmation in Hebrew with 'שולם באשראי' should not trigger a HIGH signal."""
    result = score_email(
        subject="אישור הזמנה #12345",
        body=(
            "שלום, תודה על רכישתך.\n"
            "מספר הזמנה: 12345.\n"
            "סכום כולל: 150 ₪.\n"
            "שולם באשראי.\n"
            "אישור תשלום."
        ),
        sender="orders@mystore.co.il",
        links=[],
    )
    assert result["score"] < VERDICT_THRESHOLDS["Medium"], (
        f"Expected Low or Very Low for a Hebrew receipt, got {result['verdict']} (score {result['score']})"
    )
    high_sensitive = [
        r for r in result["reasons"]
        if r.severity in ("high", "critical") and r.signal == "Sensitive information request"
    ]
    assert not high_sensitive, (
        f"Should not have a HIGH 'Sensitive information request' for a receipt; got: {high_sensitive}"
    )


# ── English receipt ─────────────────────────────────────────────────────────

def test_english_legitimate_receipt_low_risk():
    """English payment confirmation should not trigger a HIGH signal."""
    result = score_email(
        subject="Payment confirmation",
        body=(
            "Thank you for your purchase.\n"
            "Your receipt ID is ABC-123.\n"
            "Total amount: $49.99.\n"
            "Your order has been processed."
        ),
        sender="billing@example.com",
        links=[],
    )
    assert result["score"] < VERDICT_THRESHOLDS["Medium"], (
        f"Expected Low or Very Low for an English receipt, got {result['verdict']} (score {result['score']})"
    )
    high_reasons = [r for r in result["reasons"] if r.severity in ("high", "critical")]
    assert not high_reasons, (
        f"No HIGH/CRITICAL signals expected for a receipt email; got: {high_reasons}"
    )


# ── Hebrew phishing ─────────────────────────────────────────────────────────

def test_hebrew_phishing_payment_action():
    """Hebrew email asking the user to update credit-card details — must be HIGH or above."""
    result = score_email(
        subject="עדכן פרטי אשראי",
        body="לקוח יקר, עדכן פרטי אשראי בחשבונך. לחץ להשלמת התשלום כעת.",
        sender="support@suspicious-domain.com",
        links=[],
    )
    assert result["score"] >= VERDICT_THRESHOLDS["Medium"], (
        f"Expected at least Medium for a Hebrew phishing email, got {result['verdict']} (score {result['score']})"
    )
    high_reasons = [r for r in result["reasons"] if r.severity in ("high", "critical")]
    assert high_reasons, (
        "Expected at least one HIGH or CRITICAL signal for a Hebrew phishing email"
    )


# ── English phishing ────────────────────────────────────────────────────────

def test_english_phishing_payment_action():
    """English email asking to verify credit-card / fix a failed payment — must be HIGH or above."""
    result = score_email(
        subject="Your payment failed",
        body="Please verify your credit card details. Payment failed. Click here to complete your payment.",
        sender="billing@suspicious-domain.net",
        links=[],
    )
    assert result["score"] >= VERDICT_THRESHOLDS["Medium"], (
        f"Expected at least Medium for an English phishing email, got {result['verdict']} (score {result['score']})"
    )
    high_reasons = [r for r in result["reasons"] if r.severity in ("high", "critical")]
    assert high_reasons, (
        "Expected at least one HIGH or CRITICAL signal for an English phishing email"
    )


# ── Score transparency ──────────────────────────────────────────────────────

def test_score_adjustment_present_when_floor_applied():
    """When a floor rule raises the score, raw_score < score and adjustment is returned."""
    result = score_email(
        subject="Urgent: verify your credit card",
        body="Please verify your credit card details immediately.",
        sender="support@somesite.com",
        links=[],
    )
    if result["score"] != result["raw_score"]:
        assert result["score_adjustments"], (
            "score_adjustments must be non-empty when score != raw_score"
        )
        adj = result["score_adjustments"][0]
        assert adj.from_score == result["raw_score"]
        assert adj.to_score == result["score"]


def test_score_adjustment_empty_for_clean_email():
    """A clean email with no floor/ceiling override should have empty score_adjustments."""
    result = score_email(
        subject="Hello",
        body="Just wanted to say hi.",
        sender="friend@gmail.com",
        links=[],
    )
    assert result["score_adjustments"] == [], (
        f"Expected no adjustments for a clean email, got: {result['score_adjustments']}"
    )
