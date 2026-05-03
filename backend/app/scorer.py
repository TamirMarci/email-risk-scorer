import re
from urllib.parse import urlparse
from difflib import SequenceMatcher
from typing import Dict, List, Tuple

from app.models import DetectionReason, TrustSignal, RecommendedAction, ScoreAdjustment
from app.config import (
    PUBLIC_EMAIL_PROVIDERS,
    ATS_AND_SAAS_DOMAINS,
    TRUSTED_COMPANY_DOMAINS,
    TRACKING_DOMAINS,
)


_HIGH_RISK_ACTIONS = [
    RecommendedAction(
        title="Do not click any links",
        steps=[
            "Do not click links, buttons, or attachments in this email.",
            "If you need to visit the site, type the address directly into your browser.",
        ],
    ),
    RecommendedAction(
        title="Verify the sender",
        steps=[
            "Check the full sender email address, not just the display name.",
            "Contact the organisation using a phone number or address from their official website — not from this email.",
        ],
    ),
    RecommendedAction(
        title="Report phishing",
        steps=[
            "In Gmail, open the email.",
            "Click the three-dot menu (⋮) next to the reply button.",
            'Select "Report phishing".',
        ],
    ),
    RecommendedAction(
        title="Block the sender",
        steps=[
            "In Gmail, open the email.",
            "Click the three-dot menu (⋮) next to the reply button.",
            'Select "Block [sender name]".',
        ],
    ),
]


VERDICT_THRESHOLDS = {
    "Critical": 85,
    "High": 65,
    "Medium": 45,
    "Low": 25,
    "Very Low": 0,
}


LEGITIMATE_WORKFLOW_KEYWORDS = [
    "notification", "update", "account", "system", "service", "platform",
    "dashboard", "activity", "alert", "security notice", "login", "workspace",
    "ticket", "support", "receipt", "confirmation", "invoice", "subscription",
    "order", "billing", "delivery", "authentication",
    "התראה", "עדכון", "מערכת", "שירות", "חשבון", "אישור", "קבלה",
    "חשבונית", "הזמנה", "תשלום",
]

HUMAN_WRITTEN_PHRASES = [
    "hope this finds you", "please let me know", "feel free to",
    "looking forward to", "best regards", "kind regards", "warm regards",
    "thanks", "thank you",
    "בברכה", "תודה", "יום טוב",
]


VALUE_REDEMPTION_KEYWORDS = [
    "gift card", "voucher", "redeem", "claim", "open gift", "gift voucher",
    "reward", "coupon", "benefit", "promo code",
    "גיפט קארד", "שובר", "הטבה", "מתנה", "למימוש", "מימוש",
    "לפתיחה", "פתח מתנה", "קופון", "קוד הטבה",
]


SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "work", "country", "gq", "tk"}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "cutt.ly", "rb.gy",
}

BRANDS = [
    "paypal", "microsoft", "google", "amazon", "apple", "netflix",
    "facebook", "instagram", "linkedin", "github", "upwind", "buyme",
]


URGENT_WORDS = [
    "urgent", "immediately", "verify now", "act now", "final notice",
    "account suspended", "account locked", "password expires",
    "unusual activity", "security alert", "confirm your account",
    "click now", "click here",
    "דחוף", "מיידי", "לחץ עכשיו", "החשבון ייחסם",
    "החשבון נחסם", "פעילות חריגה", "נדרש אימות",
    "אמת עכשיו", "לחץ לאימות",
]


PASSWORD_ACTION_KEYWORDS = [
    "enter your password", "verify your password", "reset your password",
    "confirm your password", "provide your password", "submit your password",
    "update your password", "password expires", "password expired",
    "הזן סיסמה", "הזן את הסיסמה", "אמת סיסמה", "אמת את הסיסמה",
    "עדכן סיסמה", "עדכן את הסיסמה", "אשר סיסמה",
]

PASSWORD_INFO_CONTEXT = [
    "password changed", "password was changed", "password updated",
    "your password has been changed", "your password was reset",
    "סיסמה עודכנה", "הסיסמה עודכנה", "שינוי סיסמה",
    "הסיסמה שונתה",
]


ALWAYS_HIGH_SENSITIVE = [
    "wire", "otp", "2fa", "social security",
    "קוד אימות",
]


FINANCIAL_CONTEXT_KEYWORDS = [
    "credit card", "bank", "payment", "invoice", "billing", "transaction",
    "אשראי", "תשלום", "חשבונית", "קבלה",
]

SAFE_CONTEXT_PHRASES = [
    "receipt", "confirmation", "thank you", "thanks for", "order summary",
    "order confirmation", "your purchase", "you purchased", "total amount",
    "your order", "has been processed", "has been charged", "paid by",
    "payment confirmation", "invoice summary", "receipt id",
    "אישור הזמנה", "אישור תשלום", "קבלה", "חשבונית",
    "שולם באשראי", "מספר הזמנה", "סכום כולל",
    "תודה על רכישתך", "פרטי הזמנה", "סיכום הזמנה",
    "אישור רכישה", "סך הכל", "סה״כ", "שולם",
]

ACTION_REQUIRED_KEYWORDS = [
    "verify your", "update your", "confirm your", "complete your",
    "fix your", "provide your", "enter your", "submit your",
    "click here", "click to complete", "action required", "action needed",
    "payment failed", "payment declined", "past due", "overdue",
    "billing issue", "update payment", "verify payment",
    "הזן פרטי", "עדכן פרטי", "אשר פרטי", "אמת פרטי",
    "לחץ להשלמת", "השלם את התשלום", "התשלום נכשל",
    "עדכן אמצעי תשלום", "אמת פרטי תשלום",
]

SUSPICIOUS_ATTACHMENTS = (
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd",
    ".ps1", ".jar", ".iso", ".img", ".lnk",
)


_MULTI_PART_TLDS = {
    "co.uk", "com.au", "co.nz", "co.za", "co.il", "org.uk",
    "net.uk", "ac.uk", "gov.uk", "com.br", "co.jp",
}


def _root_domain(domain: str) -> str:
    domain = (domain or "").lower().strip(".")
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain

    two_part = ".".join(parts[-2:])
    if two_part in _MULTI_PART_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


def _is_known_safe_domain(domain: str) -> bool:
    root = _root_domain(domain)
    return domain in ATS_AND_SAAS_DOMAINS or root in ATS_AND_SAAS_DOMAINS


def _is_tracking_domain(domain: str) -> bool:
    root = _root_domain(domain)
    return domain in TRACKING_DOMAINS or root in TRACKING_DOMAINS


def _domain_from_url(url: str) -> str:
    try:
        parsed = urlparse(url if re.match(r"^https?://", url, re.I) else f"https://{url}")
        return parsed.netloc.lower().replace("www.", "").split(":")[0]
    except Exception:
        return ""


def _sender_domain(sender: str) -> str:
    match = re.search(r"@([A-Za-z0-9.-]+)", sender or "")
    return match.group(1).lower().replace("www.", "") if match else ""


def _add(
    reasons: List[DetectionReason],
    signal: str,
    severity: str,
    confidence: float,
    points: int,
    explanation: str,
):
    reasons.append(
        DetectionReason(
            signal=signal,
            severity=severity,
            confidence=confidence,
            points=points,
            contribution=round(points * confidence, 1),
            explanation=explanation,
        )
    )


def _brand_impersonation_level(domain: str, has_sensitive_request: bool) -> Tuple[str, str]:
    clean = domain.replace("-", "").replace(".", "")
    parts = domain.split(".")

    for brand in BRANDS:
        if parts and parts[0] == brand:
            continue

        brand_present = (
            brand in clean
            and not domain.endswith(f"{brand}.com")
            and domain != f"{brand}.com"
        )

        ratio = SequenceMatcher(None, clean[: max(len(brand) + 2, 4)], brand).ratio()
        is_typosquat = ratio > 0.78 and brand not in domain

        if not (brand_present or is_typosquat):
            continue

        if _is_known_safe_domain(domain):
            return "low", brand

        if is_typosquat and has_sensitive_request:
            return "critical", brand

        if is_typosquat or has_sensitive_request:
            return "high", brand

        return "medium", brand

    return "", ""


def score_email(subject: str, body: str, sender: str, links: List[str]) -> Dict:
    reasons: List[DetectionReason] = []
    text = f"{subject}\n{body}".lower()
    sender_domain = _sender_domain(sender)

    domains = []
    for link in links:
        domain = _domain_from_url(link)
        if domain:
            domains.append(domain)

    unique_domains = sorted(set(domains))

    value_redemption_context = any(kw in text for kw in VALUE_REDEMPTION_KEYWORDS)

    if not sender_domain:
        _add(
            reasons,
            "Missing sender domain",
            "medium",
            0.75,
            10,
            "The sender address does not include a recognisable domain name.",
        )

    if re.search(r"@(gmail|outlook|hotmail|yahoo)\.com", sender.lower()) and any(b in text for b in BRANDS):
        _add(
            reasons,
            "Brand sent from personal mailbox",
            "high",
            0.85,
            20,
            "A well-known brand is mentioned, but the email was sent from a personal mailbox rather than a corporate domain.",
        )

    has_urgency = False
    for word in URGENT_WORDS:
        if word.lower() in text:
            _add(
                reasons,
                "Urgency language",
                "medium",
                0.55,
                8,
                f"The email uses pressure language: '{word}'.",
            )
            has_urgency = True
            break

    has_sensitive_request = False
    is_informational_payment = False
    is_password_info = False

    if any(phrase in text for phrase in PASSWORD_ACTION_KEYWORDS):
        _add(
            reasons,
            "Sensitive information request",
            "high",
            0.80,
            18,
            "The email asks the user to enter, update, or verify a password.",
        )
        has_sensitive_request = True
    elif any(phrase in text for phrase in PASSWORD_INFO_CONTEXT):
        _add(
            reasons,
            "Password update information",
            "low",
            0.30,
            6,
            "The email references a password update but does not request password input.",
        )
        is_password_info = True

    if not has_sensitive_request:
        for word in ALWAYS_HIGH_SENSITIVE:
            if word.lower() in text:
                _add(
                    reasons,
                    "Sensitive information request",
                    "high",
                    0.75,
                    18,
                    f"The email references '{word}', which may indicate a request for sensitive information.",
                )
                has_sensitive_request = True
                break

    if not has_sensitive_request:
        matched_financial = next((kw for kw in FINANCIAL_CONTEXT_KEYWORDS if kw in text), None)
        if matched_financial:
            is_action = any(kw in text for kw in ACTION_REQUIRED_KEYWORDS)
            is_informational = any(phrase in text for phrase in SAFE_CONTEXT_PHRASES)

            if is_action:
                _add(
                    reasons,
                    "Sensitive information request",
                    "high",
                    0.80,
                    18,
                    "The email asks the user to update or verify payment details.",
                )
                has_sensitive_request = True

            elif is_informational:
                _add(
                    reasons,
                    "Payment context",
                    "low",
                    0.30,
                    6,
                    "Payment confirmation context detected; no request for payment details was found.",
                )
                is_informational_payment = True

            else:
                _add(
                    reasons,
                    "Financial reference",
                    "medium",
                    0.50,
                    10,
                    f"The email references '{matched_financial}', but no clear payment-related action is requested.",
                )

    if len(links) >= 10 and value_redemption_context:
        _add(
            reasons,
            "Gift card or redemption flow",
            "medium",
            0.65,
            14,
            "The email contains a gift card, voucher, or redemption flow with many links. Verify the sender before opening.",
        )

    if len(links) >= 7:
        _add(
            reasons,
            "Many links",
            "medium",
            0.70,
            12,
            f"The email contains {len(links)} links, which is unusually high for a personal message.",
        )
    elif len(links) >= 4:
        _add(
            reasons,
            "Many links",
            "low",
            0.50,
            6,
            f"The email contains {len(links)} links, which is higher than typical personal correspondence.",
        )

    for domain in unique_domains:
        tld = domain.split(".")[-1] if "." in domain else ""
        if tld in SUSPICIOUS_TLDS:
            _add(
                reasons,
                "Suspicious top-level domain",
                "medium",
                0.65,
                12,
                f"A link uses a .{tld} domain, which is uncommon and sometimes associated with unsolicited mail.",
            )
            break

    for domain in unique_domains:
        if domain in URL_SHORTENERS:
            _add(
                reasons,
                "URL shortener",
                "medium",
                0.70,
                12,
                f"A link uses a URL shortener ({domain}), which hides the actual destination.",
            )
            break

    impersonation_params = {
        "critical": (
            0.90,
            25,
            lambda d, b: f"The link domain '{d}' closely resembles '{b}' and the email requests sensitive information.",
        ),
        "high": (
            0.80,
            18,
            lambda d, b: f"The link domain '{d}' resembles '{b}' but is not an official domain.",
        ),
        "medium": (
            0.60,
            10,
            lambda d, b: f"The link domain '{d}' includes the name '{b}' but is not an official domain.",
        ),
        "low": (
            0.35,
            4,
            lambda d, b: f"The link domain '{d}' includes '{b}' and appears to be a known legitimate platform.",
        ),
    }

    for domain in unique_domains:
        severity, brand = _brand_impersonation_level(domain, has_sensitive_request)
        if severity:
            conf, pts, explain = impersonation_params[severity]
            _add(reasons, "Possible brand impersonation", severity, conf, pts, explain(domain, brand))
            break

    if sender_domain and unique_domains:
        sender_root = _root_domain(sender_domain)
        sender_is_allowlisted = (
            sender_root in PUBLIC_EMAIL_PROVIDERS
            or sender_domain in PUBLIC_EMAIL_PROVIDERS
            or _is_known_safe_domain(sender_domain)
            or sender_root in TRUSTED_COMPANY_DOMAINS
            or sender_domain in TRUSTED_COMPANY_DOMAINS
        )

        if not sender_is_allowlisted:
            unrecognized_external = [
                d
                for d in unique_domains
                if _root_domain(d) != sender_root
                and not _is_known_safe_domain(d)
                and not _is_tracking_domain(d)
                and _root_domain(d) not in TRUSTED_COMPANY_DOMAINS
                and d not in TRUSTED_COMPANY_DOMAINS
            ]

            has_sender_domain_link = any(_root_domain(d) == sender_root for d in unique_domains)

            if unrecognized_external and not has_sender_domain_link:
                _add(
                    reasons,
                    "Sender/link domain mismatch",
                    "low",
                    0.40,
                    6,
                    "Links point to domains that differ from the sender. This can be normal in modern SaaS and notification workflows.",
                )

    attachment_matches = re.findall(
        r"[\w.-]+\.(?:exe|scr|js|vbs|bat|cmd|ps1|jar|iso|img|lnk)",
        text,
        flags=re.I,
    )
    if attachment_matches:
        ext = attachment_matches[0].rsplit(".", 1)[-1].upper()
        _add(
            reasons,
            "Suspicious attachment reference",
            "critical",
            0.85,
            22,
            f"The email references a .{ext} file, which can execute code if opened.",
        )

    trust_signals: List[TrustSignal] = []
    sender_root = _root_domain(sender_domain) if sender_domain else ""

    if sender_domain and unique_domains and all(_root_domain(d) == sender_root for d in unique_domains):
        trust_signals.append(
            TrustSignal(
                signal="Domain alignment",
                points_reduction=8,
                explanation="All links point to the sender's own root domain, consistent with legitimate email.",
            )
        )

    if sender_domain and (
        sender_root in TRUSTED_COMPANY_DOMAINS or sender_domain in TRUSTED_COMPANY_DOMAINS
    ):
        trust_signals.append(
            TrustSignal(
                signal="Trusted company domain",
                points_reduction=10,
                explanation="The sender's domain is on the trusted domain list.",
            )
        )

    if sender_domain and _is_known_safe_domain(sender_domain):
        trust_signals.append(
            TrustSignal(
                signal="Known SaaS sender",
                points_reduction=8,
                explanation="The email originates from a known SaaS or enterprise platform.",
            )
        )

    has_many_links = len(links) >= 7

    if (
        any(kw in text for kw in LEGITIMATE_WORKFLOW_KEYWORDS)
        and not has_many_links
        and not value_redemption_context
    ):
        trust_signals.append(
            TrustSignal(
                signal="Legitimate workflow context",
                points_reduction=5,
                explanation="The email matches patterns of common system, service, receipt, or notification workflows.",
            )
        )

    if is_informational_payment:
        trust_signals.append(
            TrustSignal(
                signal="Informational payment context",
                points_reduction=10,
                explanation="The email appears to be a receipt or payment confirmation rather than a request for action.",
            )
        )

    if is_password_info:
        trust_signals.append(
            TrustSignal(
                signal="Informational password context",
                points_reduction=4,
                explanation="The email describes a password-related event but does not request password input.",
            )
        )

    if not has_urgency and not has_sensitive_request and not value_redemption_context and not has_many_links:
        trust_signals.append(
            TrustSignal(
                signal="No pressure indicators",
                points_reduction=2,
                explanation="The email does not use urgency or pressure tactics.",
            )
        )

    if any(phrase in text for phrase in HUMAN_WRITTEN_PHRASES):
        trust_signals.append(
            TrustSignal(
                signal="Human-written tone",
                points_reduction=3,
                explanation="The email contains natural human communication patterns.",
            )
        )

    raw_contributions = sum(r.contribution for r in reasons)
    total_trust = sum(ts.points_reduction for ts in trust_signals)
    raw_score = max(0, min(100, int(raw_contributions - total_trust)))
    score = raw_score
    score_adjustments: List[ScoreAdjustment] = []

    has_critical = any(r.severity == "critical" for r in reasons)
    high_signals = [r for r in reasons if r.severity == "high"]
    non_high = [r for r in reasons if r.severity != "high"]
    medium_signals = [r for r in reasons if r.severity == "medium"]

    has_qualified_high = bool(high_signals) and (
        any(r.confidence >= 0.70 for r in high_signals) or len(non_high) > 0
    )

    has_compound_medium_risk = (
        len(medium_signals) >= 2
        or (value_redemption_context and len(links) >= 10)
    )

    if has_critical:
        floored = max(score, VERDICT_THRESHOLDS["High"])
        if floored > score:
            score_adjustments.append(
                ScoreAdjustment(
                    type="verdict_floor",
                    reason="A critical-severity signal was detected — score raised to at least the High verdict threshold.",
                    from_score=score,
                    to_score=floored,
                )
            )
            score = floored

    elif has_qualified_high:
        floored = max(score, VERDICT_THRESHOLDS["Medium"])
        if floored > score:
            score_adjustments.append(
                ScoreAdjustment(
                    type="verdict_floor",
                    reason="A high-confidence risk signal was detected — score raised to at least the Medium verdict threshold.",
                    from_score=score,
                    to_score=floored,
                )
            )
            score = floored

    elif has_compound_medium_risk:
        floored = max(score, VERDICT_THRESHOLDS["Low"])
        if floored > score:
            score_adjustments.append(
                ScoreAdjustment(
                    type="verdict_floor",
                    reason="Multiple medium-level indicators were detected — score raised to at least the Low verdict threshold.",
                    from_score=score,
                    to_score=floored,
                )
            )
            score = floored

    else:
        capped = min(score, VERDICT_THRESHOLDS["Medium"] - 1)
        if capped < score:
            score_adjustments.append(
                ScoreAdjustment(
                    type="verdict_ceiling",
                    reason="No high-confidence signals found — score capped below the Medium verdict threshold.",
                    from_score=score,
                    to_score=capped,
                )
            )
            score = capped

    if score >= VERDICT_THRESHOLDS["Critical"]:
        verdict = "Critical"
        recommendation = "Highly likely risky. Do not interact with this email. Report it and delete immediately."
    elif score >= VERDICT_THRESHOLDS["High"]:
        verdict = "High"
        recommendation = "Strong risk indicators found. Do not click links or open attachments. Verify the sender through another channel."
    elif score >= VERDICT_THRESHOLDS["Medium"]:
        verdict = "Medium"
        recommendation = "Moderate risk detected. Be cautious, verify the sender, and avoid clicking unrecognised links."
    elif score >= VERDICT_THRESHOLDS["Low"]:
        verdict = "Low"
        recommendation = "Minor indicators found. Verify the sender if this email was unexpected, especially before opening links or redeeming offers."
    else:
        verdict = "Very Low"
        recommendation = "No significant threats detected. Continue treating unexpected emails with care."

    actions = _HIGH_RISK_ACTIONS if verdict in ("High", "Critical") else []

    return {
        "score": score,
        "raw_score": raw_score,
        "score_adjustments": score_adjustments,
        "verdict": verdict,
        "reasons": reasons,
        "trust_signals": trust_signals,
        "actions": actions,
        "recommendation": recommendation,
    }