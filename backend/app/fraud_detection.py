"""Deterministic, explainable safety signals for user-provided message text.

This module does not verify a sender or determine whether a message is fraud.
It only recognizes selected patterns and returns conservative next steps.
Messages are processed in memory and are neither logged nor persisted here.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit


MAX_MESSAGE_LENGTH = 8_000


@dataclass(frozen=True)
class Indicator:
    code: str
    label: str
    explanation: str


@dataclass(frozen=True)
class Assessment:
    risk_classification: str
    matched_indicators: list[Indicator]
    explanations: list[str]
    recommended_actions: list[str]
    clarifying_question: str | None
    safety_disclaimer: str


SAFETY_DISCLAIMER = (
    "This is a limited, text-based safety aid. It cannot verify a caller or "
    "determine with certainty whether a message is fraudulent."
)

_CREDENTIAL = re.compile(
    r"\b(?:otp(?:s)?|one[\s-]?time (?:password|passcode|code)|"
    r"verification code|security code|cvv|cvc|pin(?:s)?|password(?:s)?|passcode)\b",
    re.IGNORECASE,
)
_CREDENTIAL_ACTION = re.compile(
    r"\b(?:share|send|give|provide|tell|read(?:\s+out)?|reply\s+with|"
    r"enter|confirm|forward|text|type|reveal|disclose|hand\s+over|ask\s+for|"
    r"request|need(?:ed)?|require|what(?:'s|\s+is))\b",
    re.IGNORECASE,
)
_NEGATION_BEFORE_ACTION = re.compile(
    r"(?:never|don't|do not|should not|must not|avoid|not to)\s*$", re.IGNORECASE
)
_NEGATED_CLAUSE_END = re.compile(
    r"\b(?:never|don't|do not|shouldn't|should not|mustn't|must not|avoid|"
    r"didn't|did not|will not|won't|cannot|can't|not\s+(?:to|asked|asking|supposed))"
    r"\b[^.!?;\n]{0,55}$",
    re.IGNORECASE,
)
_URL = re.compile(r"(?:https?://|www\.)[^\s<>()\[\]{}\"']+", re.IGNORECASE)
_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "rb.gy", "cutt.ly", "rebrand.ly", "shorturl.at", "lnkd.in",
    "tiny.cc", "soo.gd", "s.id",
}
_URL_LURE = re.compile(
    r"\b(?:verify|verification|kyc|account|bank|login|password|otp|refund|"
    r"payment|blocked|suspended|update|claim|wallet|urgent)\b", re.IGNORECASE
)
_SENSITIVE_ORGS = re.compile(
    r"\b(?:bank|police|cbi|enforcement directorate|\bed\b|rbi|income tax|"
    r"government|govt|telecom department|customs|cyber crime|cybercrime)\b",
    re.IGNORECASE,
)
_AUTHORITY_CLAIM = re.compile(
    r"\b(?:i am|this is|calling from|speaking from|officer from|"
    r"representing|on behalf of)\b", re.IGNORECASE
)
_REQUEST_OR_THREAT = re.compile(
    r"\b(?:pay|send|transfer|deposit|share|provide|verify|install|download|"
    r"scan|click|open|must|unless|otherwise|or else|arrest|blocked|suspended|"
    r"frozen|seized|warrant|case against)\b", re.IGNORECASE
)
_URGENCY = re.compile(
    r"\b(?:now|immediately|urgent(?:ly)?|today|right away|(?:within|in)\s+\d+\s+"
    r"(?:minutes?|hours?)|last chance|final warning|before\s+(?:\d|midnight)|"
    r"expire[sd]?|deadline)\b", re.IGNORECASE
)


def _add(
    found: dict[str, tuple[Indicator, bool]],
    code: str,
    label: str,
    explanation: str,
    high_risk: bool = False,
) -> None:
    """Add a stable indicator once; repeated matches do not echo user text."""
    existing = found.get(code)
    indicator = Indicator(code=code, label=label, explanation=explanation)
    found[code] = (indicator, high_risk or (existing[1] if existing else False))


def _has_credential_harvest(text: str) -> bool:
    credentials = list(_CREDENTIAL.finditer(text))
    actions = list(_CREDENTIAL_ACTION.finditer(text))
    for action in actions:
        sentence_start = max(
            text.rfind(mark, 0, action.start()) for mark in (".", "!", "?", ";", "\n")
        ) + 1
        before_action = text[max(sentence_start, action.start() - 55):action.start()]
        if _NEGATION_BEFORE_ACTION.search(before_action) or _NEGATED_CLAUSE_END.search(before_action):
            continue
        if any(abs(action.start() - credential.start()) <= 64 for credential in credentials):
            return True
    return False


def _has_active_action(text: str, actions: re.Pattern[str]) -> bool:
    """Ignore a request verb when its sentence explicitly advises against it."""
    for action in actions.finditer(text):
        sentence_start = max(
            text.rfind(mark, 0, action.start()) for mark in (".", "!", "?", ";", "\n")
        ) + 1
        prefix = text[max(sentence_start, action.start() - 55):action.start()]
        if not _NEGATED_CLAUSE_END.search(prefix):
            return True
    return False


def _extract_urls(text: str) -> list[str]:
    return [match.rstrip(".,!?;:") for match in _URL.findall(text)]


def _url_host(url: str) -> str:
    parsed = urlsplit(url if "://" in url else f"https://{url}")
    return (parsed.hostname or "").lower().rstrip(".")


def _is_suspicious_url(url: str) -> bool:
    host = _url_host(url)
    if not host:
        return False
    if "xn--" in host or "@" in url:
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return bool(re.search(r"(?:login|verify|secure|kyc|account|wallet|bank)", host))


def _has_nearby(text: str, first: re.Pattern[str], second: re.Pattern[str], distance: int = 70) -> bool:
    left = list(first.finditer(text))
    right = list(second.finditer(text))
    return any(abs(a.start() - b.start()) <= distance for a in left for b in right)


def _assess_english(message: str) -> Assessment:
    """Return deterministic safety indicators for a message, without retaining it."""
    text = message.lower()
    found: dict[str, tuple[Indicator, bool]] = {}
    explicit_high: set[str] = set()

    if _has_credential_harvest(text):
        _add(
            found,
            "credential_harvesting",
            "Request for a sensitive credential",
            "The text asks for a one-time code, PIN, CVV, password, or similar credential. Legitimate support should not need you to disclose these secrets.",
            high_risk=True,
        )
        explicit_high.add("credential_harvesting")

    kyc_request = re.search(
        r"\b(?:kyc|e[\s-]?kyc|know your customer)\b.{0,65}\b(?:update|complete|verify|"
        r"reactivate|expire|expired|block|suspend|deactivate|deadline|immediately|now)\b|"
        r"\b(?:update|complete|verify|reactivate)\b.{0,45}\b(?:kyc|e[\s-]?kyc)\b",
        text,
    ) and _has_active_action(
        text,
        re.compile(r"\b(?:update|complete|verify|reactivate|expire[sd]?|block|suspend|deactivate|deadline|immediately|now)\b"),
    )
    account_threat = re.search(
        r"\b(?:account|bank account|sim|wallet)\b.{0,55}\b(?:blocked|suspended|frozen|"
        r"locked|closed|deactivated)\b|\b(?:blocked|suspended|frozen|locked|closed|"
        r"deactivated)\b.{0,45}\b(?:account|bank account|sim|wallet)\b",
        text,
    ) and _has_active_action(
        text, re.compile(r"\b(?:blocked|suspended|frozen|locked|closed|deactivated)\b")
    )
    if kyc_request or account_threat:
        urgent_threat = bool((_URGENCY.search(text) or re.search(r"\bunless\b|\bor else\b", text)) and account_threat)
        _add(
            found,
            "kyc_or_account_threat",
            "KYC or account-blocking pressure",
            "The text links KYC or account access to a demand, deadline, or threat. Verify account notices independently through the institution’s official app or contact details.",
            high_risk=urgent_threat,
        )
        if urgent_threat:
            explicit_high.add("kyc_or_account_threat")

    urls = _extract_urls(text)
    short_link_found = False
    suspicious_link_found = False
    for url in urls:
        host = _url_host(url)
        if host in _SHORTENERS or any(host.endswith(f".{domain}") for domain in _SHORTENERS):
            short_link_found = True
        if _is_suspicious_url(url) or _URL_LURE.search(url) and _URL_LURE.search(text):
            suspicious_link_found = True
    if short_link_found:
        _add(
            found,
            "shortened_link",
            "Shortened link",
            "A shortened link hides its destination. Avoid opening it when it arrives unexpectedly; verify the request through a known official channel.",
        )
    if suspicious_link_found:
        _add(
            found,
            "suspicious_url",
            "Potentially suspicious URL",
            "A link has a sensitive sign-in or account-related pattern. The text alone cannot establish who controls that destination.",
        )

    remote_app = re.search(
        r"\b(?:install|download|open|use|set up|give|grant|allow)\b.{0,70}\b(?:anydesk|"
        r"teamviewer|rustdesk|ultraviewer|quick[\s-]?support|chrome remote desktop|"
        r"remote access|screen[\s-]?sharing|remote control app)\b|"
        r"\b(?:anydesk|teamviewer|rustdesk|ultraviewer|quick[\s-]?support|"
        r"chrome remote desktop|remote access|screen[\s-]?sharing|remote control app)\b"
        r".{0,70}\b(?:install|download|open|use|set up|give|grant|allow)\b",
        text,
    )
    if remote_app and _has_active_action(
        text, re.compile(r"\b(?:install|download|open|use|set up|give|grant|allow)\b")
    ):
        _add(
            found,
            "remote_access_request",
            "Remote-access app or screen-control request",
            "The text asks for software or permissions that could let another person view or control a device. Do not install it or grant access at a caller’s direction.",
            high_risk=True,
        )
        explicit_high.add("remote_access_request")

    qr_receive = re.search(
        r"\b(?:scan|use|open)\b.{0,45}\b(?:qr|qr code)\b.{0,70}\b(?:receive|get|claim|"
        r"collect|refund|cashback|payment|money)\b|\b(?:receive|get|claim|collect|refund|"
        r"cashback|payment|money)\b.{0,70}\b(?:scan|use|open)\b.{0,45}\b(?:qr|qr code)\b",
        text,
    )
    upi_manipulation = re.search(
        r"\bupi\b.{0,45}\b(?:pin|qr|collect request|receive|refund|cashback|credit)\b|"
        r"\b(?:receive|refund|cashback|credit)\b.{0,45}\bupi\b.{0,30}\b(?:pin|qr)\b",
        text,
    )
    active_qr_action = _has_active_action(text, re.compile(r"\b(?:scan|use|open)\b"))
    active_upi_action = _has_active_action(
        text, re.compile(r"\b(?:enter|share|send|approve|scan|use|open)\b")
    )
    if (qr_receive and active_qr_action) or (upi_manipulation and active_upi_action):
        _add(
            found,
            "qr_upi_payment_manipulation",
            "QR-code or UPI payment manipulation",
            "The text connects a QR code or UPI action with receiving money, a refund, or entering a PIN. Scanning a code or entering a UPI PIN can authorize a payment; independently verify the request.",
            high_risk=True,
        )
        explicit_high.add("qr_upi_payment_manipulation")

    digital_arrest = re.search(
        r"\b(?:digital arrest|arrested? immediately|will be arrested|arrest warrant|"
        r"police custody|under arrest|video call.{0,35}arrest|arrest.{0,35}video call|"
        r"case.{0,30}arrest|arrest.{0,30}case)\b",
        text,
    )
    intimidation = re.search(
        r"\b(?:we will arrest you|you will be arrested|warrant for your arrest|"
        r"money laundering case|account will be seized|assets will be seized|"
        r"family will be arrested|do not tell anyone|cannot disconnect|stay on the call)\b",
        text,
    )
    if digital_arrest or intimidation:
        _add(
            found,
            "digital_arrest_or_intimidation",
            "Arrest or intimidation tactic",
            "The text uses arrest, legal-case, secrecy, or coercive threats to pressure the recipient. End the interaction and independently contact a trusted person or relevant institution.",
            high_risk=True,
        )
        explicit_high.add("digital_arrest_or_intimidation")

    authority_claim = bool(_SENSITIVE_ORGS.search(text) and _AUTHORITY_CLAIM.search(text))
    if authority_claim:
        _add(
            found,
            "authority_impersonation_claim",
            "Claimed bank, police, or government authority",
            "The text claims to represent a financial institution or authority. A claimed identity is not verified by the message itself.",
        )

    money_action = re.compile(r"\b(?:send|transfer|pay|deposit|wire|remit|upi)\b", re.IGNORECASE)
    money_target = re.compile(r"\b(?:money|cash|funds|amount|payment|rupees?|rs\.?|upi|₹|\d{2,})\b", re.IGNORECASE)
    urgent_money = (
        _has_nearby(text, money_action, money_target, distance=70)
        and _has_nearby(text, money_action, _URGENCY, distance=70)
        and _has_active_action(text, money_action)
    )
    authority_demand = authority_claim and bool(_REQUEST_OR_THREAT.search(text)) and bool(
        re.search(r"\b(?:pay|send|transfer|deposit|share|provide|install|scan|click|verify)\b", text)
    )
    if urgent_money:
        _add(
            found,
            "urgent_money_transfer",
            "Urgent money-transfer demand",
            "The text pairs a request to move or pay money with urgency. Pause and confirm independently before taking any financial action.",
            high_risk=True,
        )
        explicit_high.add("urgent_money_transfer")
    if authority_demand:
        explicit_high.add("authority_impersonation_claim")
        existing = found["authority_impersonation_claim"][0]
        found["authority_impersonation_claim"] = (existing, True)

    if explicit_high:
        classification = "high"
        actions = [
            "Stop the interaction. Do not share codes, passwords, PINs, or banking credentials; do not install requested apps, scan payment codes, or transfer money.",
            "Contact the person or institution independently using a number or app you already trust.",
            "If you already shared information or authorized a payment, contact your bank or payment provider through its official channel promptly.",
        ]
        question = None
    elif found:
        classification = "caution"
        actions = [
            "Pause before clicking links, sharing information, installing apps, or making payments.",
            "Verify the request through a known official number or app, not through contact details in the message.",
        ]
        question = "What is the sender asking you to do next?"
    else:
        classification = "insufficient_information"
        actions = [
            "No listed warning pattern was found in the text provided; that does not confirm the message or caller is genuine.",
            "If you feel pressured, pause and verify independently before sharing information or taking action.",
        ]
        question = "What did the caller or sender ask you to do?"

    indicators = [entry[0] for entry in found.values()]
    return Assessment(
        risk_classification=classification,
        matched_indicators=indicators,
        explanations=[indicator.explanation for indicator in indicators],
        recommended_actions=actions,
        clarifying_question=question,
        safety_disclaimer=SAFETY_DISCLAIMER,
    )


SUPPORTED_LANGUAGES = ("en-IN", "hi-IN", "mr-IN", "ta-IN")

# Language-specific patterns are deliberately small and explicit. They cover
# common native-script phrases and English banking terms commonly mixed into
# Indian-language messages. No translation service or learned model is used.
_LOCAL_PATTERNS: dict[str, dict[str, tuple[str, ...]]] = {
    "hi-IN": {
        "credential": (r"otp|ओटीपी|पिन|pin|cvv|सीवीवी|पासवर्ड|password|verification code|सत्यापन कोड",),
        "credential_action": (r"share|send|tell|give|read|reply|enter|provide|बताएं|बताइए|बताओ|भेजें|भेजिए|दें|दीजिए|साझा|डालें|लिखें",),
        "negation": (r"कभी\s*(?:भी\s*)?(?:नहीं|ना|मत)|नहीं(?!\s*तो)|मत|(?:^|\s)न\s+करें|न\s+करना|never|don't|do not|मत\s+करो",),
        "kyc": (r"kyc|केवाईसी|e-?kyc",),
        "kyc_action": (r"update|complete|verify|अपडेट|पूरा|करें|करो|सत्यापित|नवीनीकरण|आज|अभी|तुरंत",),
        "account": (r"account|खाता|बैंक\s+खाता|wallet|वॉलेट|sim",),
        "blocked": (r"blocked|block|suspend|frozen|deactivated|बंद|ब्लॉक|निष्क्रिय|फ्रीज|रोक दिया|बंद हो जाएगा",),
        "url_lure": (r"verify|kyc|account|bank|login|password|otp|refund|payment|blocked|सत्यापन|खाता|बैंक",),
        "remote_action": (r"install|download|open|grant|allow|इंस्टॉल|डाउनलोड|खोलें|खोलो|करें|करो|अनुमति",),
        "qr": (r"qr|क्यूआर|यूपीआई|upi",),
        "qr_action": (r"scan|approve|enter|send|भेजें|स्कैन|स्कैन करें|स्कैन करो|दर्ज|डालें|स्वीकार|approve",),
        "receive": (r"receive|get|refund|cashback|credit|पाएं|पाओ|प्राप्त|रिफंड|वापसी|कैशबैक|पैसे मिलेंगे",),
        "authority": (r"bank|बैंक|police|पुलिस|सरकार|government|rbi|सीबीआई|cbi|आयकर",),
        "authority_claim": (r"calling from|speaking from|this is|i am|से बोल रहा|से बोल रही|की तरफ से|अधिकारी बोल रहा|अधिकारी बोल रही",),
        "money_action": (r"transfer|send|pay|deposit|भेजें|भेजो|जमा|ट्रांसफर|भुगतान|पेमेंट|करो",),
        "money": (r"money|funds|₹|रुपये|पैसे|रकम|रुपए",),
        "urgency": (r"now|immediately|urgent|today|अभी|तुरंत|आज ही|जल्दी|समय सीमा|मिनट में|घंटे में",),
    },
    "mr-IN": {
        "credential": (r"otp|ओटीपी|पिन|pin|cvv|सीव्हीव्ही|पासवर्ड|password|verification code|सत्यापन कोड",),
        "credential_action": (r"share|send|tell|give|read|reply|enter|provide|सांगा|सांग|द्या|द्यावा|पाठवा|भरा|टाका|शेअर|सामायिक",),
        "negation": (r"कधीही\s*(?:नाही|नका)|कधी\s*(?:नाही|नका)|नाही(?!तर)|नका|(?:^|\s)न\s+करा|never|don't|do not",),
        "kyc": (r"kyc|केवायसी|e-?kyc",),
        "kyc_action": (r"update|complete|verify|अपडेट|पूर्ण|करा|सत्यापित|नूतनीकरण|आज|आत्ता|लगेच",),
        "account": (r"account|खाते|बँक\s+खाते|wallet|वॉलेट|sim",),
        "blocked": (r"blocked|block|suspend|frozen|deactivated|बंद|ब्लॉक|निष्क्रिय|गोठवले|गोठवले जाईल|रद्द",),
        "url_lure": (r"verify|kyc|account|bank|login|password|otp|refund|payment|blocked|सत्यापन|खाते|बँक",),
        "remote_action": (r"install|download|open|grant|allow|इन्स्टॉल|डाउनलोड|उघडा|उघड|परवानगी|करा|कर",),
        "qr": (r"qr|क्यूआर|यूपीआय|upi",),
        "qr_action": (r"scan|approve|enter|send|पाठवा|स्कॅन|स्कॅन करा|भरा|टाका|मंजूर|मान्य करा",),
        "receive": (r"receive|get|refund|cashback|credit|मिळवा|मिळेल|परतावा|रिफंड|कॅशबॅक|जमा",),
        "authority": (r"bank|बँक|police|पोलीस|सरकार|government|rbi|सीबीआय|cbi|आयकर",),
        "authority_claim": (r"calling from|speaking from|this is|i am|बँकेतून बोलत|पोलीस अधिकारी|सरकारच्या वतीने|कडून बोलत",),
        "money_action": (r"transfer|send|pay|deposit|पाठवा|पाठव|जमा|ट्रान्सफर|भरा|भरणा करा",),
        "money": (r"money|funds|₹|रुपये|पैसे|रक्कम",),
        "urgency": (r"now|immediately|urgent|today|आत्ता|तात्काळ|लगेच|आजच|मिनिटांत|तासांत|मुदत",),
    },
    "ta-IN": {
        "credential": (r"otp|ஓடிபி|பின்|pin|cvv|சிவிவி|கடவுச்சொல்|password|verification code",),
        "credential_action": (r"share|send|tell|give|read|reply|enter|provide|சொல்லுங்கள்|சொல்|அனுப்பு|அனுப்புங்கள்|கொடு|கொடுங்கள்|பகிர்|உள்ளிடு|உள்ளிடுங்கள்",),
        "negation": (r"ஒருபோதும்\s*(?:பகிராதீர்கள்|சொல்லாதீர்கள்)|பகிராதீர்கள்|சொல்லாதீர்கள்|வேண்டாம்|இல்லை(?!யெனில்)|never|don't|do not",),
        "kyc": (r"kyc|கேஒய்சி|e-?kyc",),
        "kyc_action": (r"update|complete|verify|புதுப்பி|புதுப்பிக்கவும்|நிறைவு|சரிபார்க்கவும்|செய்|இன்று|உடனே|இப்போதே",),
        "account": (r"account|கணக்கு|வங்கி கணக்கு|wallet|வாலெட்|sim",),
        "blocked": (r"blocked|block|suspend|frozen|deactivated|முடக்கம்|முடக்கப்படும்|நிறுத்தப்படும்|செயலிழக்க|பூட்டப்படும்",),
        "url_lure": (r"verify|kyc|account|bank|login|password|otp|refund|payment|blocked|சரிபார்ப்பு|கணக்கு|வங்கி",),
        "remote_action": (r"install|download|open|grant|allow|நிறுவு|பதிவிறக்கு|திற|அனுமதி|செய்யுங்கள்|செய்",),
        "qr": (r"qr|க்யூஆர்|யுபிஐ|upi",),
        "qr_action": (r"scan|approve|enter|send|அனுப்பு|ஸ்கேன்|ஸ்கேன் செய்யுங்கள்|உள்ளிடு|அனுமதி|ஒப்புதல்",),
        "receive": (r"receive|get|refund|cashback|credit|பெற|கிடைக்கும்|திரும்பப்பெற|பணம் திரும்ப|கேஷ்பேக்|வரவு",),
        "authority": (r"bank|வங்கி|police|காவல்துறை|அரசு|government|rbi|cbi|வருமானவரி",),
        "authority_claim": (r"calling from|speaking from|this is|i am|வங்கியிலிருந்து பேசுகிறேன்|காவல்துறையிலிருந்து|அரசின் சார்பில்|அதிகாரி பேசுகிறேன்",),
        "money_action": (r"transfer|send|pay|deposit|அனுப்பு|பரிமாற்றம்|செலுத்து|டெபாசிட்|பணம் அனுப்பு",),
        "money": (r"money|funds|₹|ரூபாய்|பணம்|தொகை",),
        "urgency": (r"now|immediately|urgent|today|இப்போது|உடனே|அவசரம்|இன்றே|நிமிடங்களில்|மணி நேரத்தில்|காலக்கெடு",),
    },
}

_LOCAL_TEXT: dict[str, dict[str, object]] = {
    "hi-IN": {
        "indicators": {
            "credential_harvesting": ("संवेदनशील जानकारी माँगी जा रही है", "संदेश में OTP, PIN, CVV या पासवर्ड बताने को कहा गया है। ये गोपनीय जानकारी किसी कॉलर या संदेश के साथ साझा न करें।"),
            "kyc_or_account_threat": ("KYC या खाता बंद करने का दबाव", "संदेश में KYC या खाते की सुविधा को किसी मांग, समय सीमा या बंद करने की धमकी से जोड़ा गया है। सूचना को बैंक के आधिकारिक ऐप या ज्ञात नंबर से जाँचें।"),
            "suspicious_url": ("संदिग्ध लिंक", "लिंक में खाता या सुरक्षा से जुड़े शब्द हैं। केवल संदेश से यह पता नहीं चलता कि वेबसाइट असली है या नहीं।"),
            "shortened_link": ("छोटा किया गया लिंक", "छोटा लिंक अपना असली पता छिपाता है। अनजान लिंक न खोलें; आधिकारिक चैनल से जाँचें।"),
            "remote_access_request": ("रिमोट एक्सेस ऐप का अनुरोध", "संदेश में ऐसा ऐप या अनुमति माँगी गई है जिससे कोई आपके डिवाइस को देख या नियंत्रित कर सकता है। इसे इंस्टॉल न करें और पहुँच न दें।"),
            "qr_upi_payment_manipulation": ("QR या UPI भुगतान का दबाव", "संदेश QR या UPI को पैसे पाने या रिफंड से जोड़ता है। QR स्कैन करना या UPI PIN डालना भुगतान की अनुमति दे सकता है।"),
            "authority_impersonation_claim": ("बैंक या सरकारी अधिकारी होने का दावा", "संदेश भेजने वाला बैंक या अधिकारी होने का दावा करता है। केवल इस दावे से पहचान सत्यापित नहीं होती।"),
            "urgent_money_transfer": ("तुरंत पैसे भेजने की मांग", "पैसे भेजने या भुगतान करने की मांग के साथ जल्दबाज़ी का दबाव है। पहले स्वतंत्र रूप से पुष्टि करें।"),
        },
        "high_actions": ["बातचीत रोकें। OTP, PIN, पासवर्ड या बैंक जानकारी साझा न करें; ऐप इंस्टॉल, QR स्कैन या भुगतान न करें।", "व्यक्ति या संस्था से पहले से ज्ञात आधिकारिक नंबर या ऐप के ज़रिए संपर्क करें।", "यदि जानकारी साझा की या भुगतान किया है, तो अपने बैंक या भुगतान सेवा से आधिकारिक माध्यम पर तुरंत संपर्क करें।"],
        "caution_actions": ["लिंक खोलने, जानकारी साझा करने, ऐप इंस्टॉल करने या भुगतान करने से पहले रुकें।", "संदेश में दिए संपर्क विवरण के बजाय आधिकारिक नंबर या ऐप से पुष्टि करें।"],
        "unknown_actions": ["दिए गए पाठ में पहचाने गए चेतावनी संकेत नहीं मिले; इससे संदेश या कॉलर की असलियत साबित नहीं होती।", "दबाव महसूस हो तो कोई कदम उठाने से पहले स्वतंत्र रूप से पुष्टि करें।"],
        "question": "कॉलर या भेजने वाला आपसे आगे क्या करने को कह रहा है?", "disclaimer": "यह सीमित पाठ-आधारित सुरक्षा सहायता है। यह कॉलर की पहचान सत्यापित नहीं कर सकती और न ही धोखाधड़ी निश्चित रूप से बता सकती है।",
    },
    "mr-IN": {
        "indicators": {
            "credential_harvesting": ("संवेदनशील माहितीची मागणी", "संदेशात OTP, PIN, CVV किंवा पासवर्ड सांगण्यास सांगितले आहे. ही गोपनीय माहिती कोणत्याही कॉलर किंवा संदेशासोबत शेअर करू नका."),
            "kyc_or_account_threat": ("KYC किंवा खाते बंद करण्याचा दबाव", "संदेशात KYC किंवा खाते वापरणे एखाद्या मागणीशी, मुदतीशी किंवा खाते बंद करण्याच्या धमकीशी जोडले आहे. बँकेच्या अधिकृत ॲप किंवा ओळखीच्या क्रमांकावरून तपासा."),
            "suspicious_url": ("संशयास्पद लिंक", "लिंकमध्ये खाते किंवा सुरक्षिततेशी संबंधित शब्द आहेत. केवळ संदेशावरून संकेतस्थळ खरे आहे की नाही हे ठरत नाही."),
            "shortened_link": ("लहान केलेली लिंक", "लहान लिंक मूळ पत्ता लपवते. अनोळखी लिंक उघडू नका; अधिकृत मार्गाने तपासा."),
            "remote_access_request": ("रिमोट ॲक्सेस ॲपची मागणी", "संदेशात तुमचे डिव्हाइस पाहता किंवा नियंत्रित करता येईल असे ॲप किंवा परवानगी मागितली आहे. ते इन्स्टॉल करू नका किंवा प्रवेश देऊ नका."),
            "qr_upi_payment_manipulation": ("QR किंवा UPI पेमेंटचा दबाव", "संदेश QR किंवा UPI ला पैसे मिळणे किंवा परतावा यांच्याशी जोडतो. QR स्कॅन करणे किंवा UPI PIN टाकणे पेमेंटला मान्यता देऊ शकते."),
            "authority_impersonation_claim": ("बँक किंवा सरकारी अधिकारी असल्याचा दावा", "संदेश पाठवणारा बँक किंवा अधिकारी असल्याचा दावा करतो. केवळ या दाव्याने ओळख सिद्ध होत नाही."),
            "urgent_money_transfer": ("तातडीने पैसे पाठवण्याची मागणी", "पैसे पाठवण्याच्या किंवा पेमेंटच्या मागणीसोबत घाईचा दबाव आहे. आधी स्वतंत्रपणे खात्री करा."),
        },
        "high_actions": ["संभाषण थांबवा. OTP, PIN, पासवर्ड किंवा बँक तपशील शेअर करू नका; ॲप इन्स्टॉल, QR स्कॅन किंवा पेमेंट करू नका.", "व्यक्ती किंवा संस्थेशी आधीपासून माहीत असलेल्या अधिकृत क्रमांकावरून किंवा ॲपमधून संपर्क साधा.", "माहिती शेअर केली किंवा पेमेंट केले असल्यास, अधिकृत मार्गाने बँक किंवा पेमेंट सेवेशी त्वरित संपर्क साधा."],
        "caution_actions": ["लिंक उघडण्यापूर्वी, माहिती शेअर करण्यापूर्वी, ॲप इन्स्टॉल करण्यापूर्वी किंवा पेमेंट करण्यापूर्वी थांबा.", "संदेशातील संपर्क तपशीलाऐवजी अधिकृत क्रमांक किंवा ॲपद्वारे खात्री करा."],
        "unknown_actions": ["दिलेल्या मजकुरात ओळखलेले इशारे आढळले नाहीत; यामुळे संदेश किंवा कॉलर खरा असल्याचे सिद्ध होत नाही.", "दबाव जाणवल्यास कोणतीही कृती करण्यापूर्वी स्वतंत्रपणे खात्री करा."],
        "question": "कॉलर किंवा संदेश पाठवणारा पुढे काय करण्यास सांगतो?", "disclaimer": "ही मर्यादित मजकूर-आधारित सुरक्षा मदत आहे. ती कॉलरची ओळख पडताळू शकत नाही किंवा फसवणूक निश्चितपणे ठरवू शकत नाही.",
    },
    "ta-IN": {
        "indicators": {
            "credential_harvesting": ("ரகசிய தகவல் கேட்கப்படுகிறது", "செய்தியில் OTP, PIN, CVV அல்லது கடவுச்சொல்லைச் சொல்லுமாறு கேட்கப்படுகிறது. இந்த ரகசியங்களை அழைப்பவர் அல்லது செய்தியுடன் பகிர வேண்டாம்."),
            "kyc_or_account_threat": ("KYC அல்லது கணக்கு முடக்க அழுத்தம்", "KYC அல்லது கணக்கு அணுகலை ஒரு கோரிக்கை, காலக்கெடு அல்லது முடக்கப்படும் என்ற மிரட்டலுடன் செய்தி இணைக்கிறது. வங்கியின் அதிகாரப்பூர்வ செயலி அல்லது அறிந்த எண்ணில் சரிபார்க்கவும்."),
            "suspicious_url": ("சந்தேகத்திற்குரிய இணைப்பு", "இணைப்பில் கணக்கு அல்லது பாதுகாப்பு தொடர்பான சொற்கள் உள்ளன. செய்தியை மட்டும் வைத்து இணையதளம் உண்மையானதா என உறுதிப்படுத்த முடியாது."),
            "shortened_link": ("சுருக்கப்பட்ட இணைப்பு", "சுருக்கப்பட்ட இணைப்பு உண்மையான முகவரியை மறைக்கிறது. எதிர்பாராத இணைப்பைத் திறக்காமல் அதிகாரப்பூர்வ வழியில் சரிபார்க்கவும்."),
            "remote_access_request": ("தொலைநிலை அணுகல் செயலி கோரிக்கை", "உங்கள் சாதனத்தைப் பார்க்க அல்லது கட்டுப்படுத்தக்கூடிய செயலி அல்லது அனுமதி கேட்கப்படுகிறது. அதை நிறுவவோ அணுகலை வழங்கவோ வேண்டாம்."),
            "qr_upi_payment_manipulation": ("QR அல்லது UPI பணப் பரிவர்த்தனை அழுத்தம்", "பணம் பெற அல்லது திரும்பப் பெற QR அல்லது UPI பயன்படுத்தச் செய்தி கூறுகிறது. QR ஸ்கேன் செய்வது அல்லது UPI PIN உள்ளிடுவது பணம் செலுத்த அனுமதிக்கலாம்."),
            "authority_impersonation_claim": ("வங்கி அல்லது அரசு அதிகாரி எனக் கூறுதல்", "செய்தி அனுப்புபவர் வங்கி அல்லது அதிகாரி எனக் கூறுகிறார். இந்தக் கூற்று மட்டும் அடையாளத்தை உறுதிப்படுத்தாது."),
            "urgent_money_transfer": ("அவசர பணப் பரிமாற்ற கோரிக்கை", "பணம் அனுப்ப அல்லது செலுத்தும் கோரிக்கையுடன் அவசரப்படுத்தும் அழுத்தம் உள்ளது. முதலில் தனியாகச் சரிபார்க்கவும்."),
        },
        "high_actions": ["உரையாடலை நிறுத்துங்கள். OTP, PIN, கடவுச்சொல் அல்லது வங்கி விவரங்களைப் பகிர வேண்டாம்; செயலி நிறுவுதல், QR ஸ்கேன் அல்லது பணம் செலுத்த வேண்டாம்.", "நீங்கள் ஏற்கனவே அறிந்த அதிகாரப்பூர்வ எண் அல்லது செயலி மூலம் அந்த நபர் அல்லது நிறுவனத்தைத் தொடர்புகொள்ளுங்கள்.", "விவரங்களைப் பகிர்ந்திருந்தால் அல்லது பணம் செலுத்தியிருந்தால், அதிகாரப்பூர்வ வழியில் வங்கி அல்லது பணச் சேவையை உடனே தொடர்புகொள்ளுங்கள்."],
        "caution_actions": ["இணைப்பைத் திறப்பதற்கு, தகவல் பகிர்வதற்கு, செயலி நிறுவுவதற்கு அல்லது பணம் செலுத்துவதற்கு முன் நிறுத்துங்கள்.", "செய்தியில் உள்ள தொடர்பு விவரங்களைப் பயன்படுத்தாமல் அதிகாரப்பூர்வ எண் அல்லது செயலியில் சரிபார்க்கவும்."],
        "unknown_actions": ["கொடுக்கப்பட்ட உரையில் பட்டியலிடப்பட்ட எச்சரிக்கை முறை கண்டறியப்படவில்லை; இதனால் செய்தி அல்லது அழைப்பவர் உண்மையானவர் என உறுதி செய்ய முடியாது.", "அழுத்தம் இருந்தால் செயல்படுவதற்கு முன் தனியாகச் சரிபார்க்கவும்."],
        "question": "அழைப்பவர் அல்லது அனுப்புநர் அடுத்து என்ன செய்யச் சொல்கிறார்?", "disclaimer": "இது வரையறுக்கப்பட்ட உரை-அடிப்படையிலான பாதுகாப்பு உதவி. அழைப்பவரைச் சரிபார்க்கவோ மோசடியை உறுதியாகத் தீர்மானிக்கவோ முடியாது.",
    },
}


def _local_re(patterns: dict[str, tuple[str, ...]], name: str) -> re.Pattern[str]:
    return re.compile("(?:" + "|".join(patterns[name]) + ")", re.IGNORECASE)


def _active_local_action(text: str, action: re.Pattern[str], negation: re.Pattern[str]) -> bool:
    for match in action.finditer(text):
        context = text[max(0, match.start() - 38):min(len(text), match.end() + 28)]
        if not negation.search(context):
            return True
    return False


def _localized_indicator(language: str, code: str) -> Indicator:
    label, explanation = _LOCAL_TEXT[language]["indicators"][code]  # type: ignore[index,misc]
    return Indicator(code, label, explanation)


def _assess_local(message: str, language: str) -> Assessment:
    patterns = _LOCAL_PATTERNS[language]
    text = message.lower()
    found: dict[str, Indicator] = {}
    high: set[str] = set()
    credential = _local_re(patterns, "credential")
    credential_action = _local_re(patterns, "credential_action")
    negation = _local_re(patterns, "negation")
    credential_pair = _has_nearby(text, credential, credential_action, 90)
    if credential_pair and _active_local_action(text, credential_action, negation):
        found["credential_harvesting"] = _localized_indicator(language, "credential_harvesting")
        high.add("credential_harvesting")

    kyc = _local_re(patterns, "kyc")
    kyc_action = _local_re(patterns, "kyc_action")
    account = _local_re(patterns, "account")
    blocked = _local_re(patterns, "blocked")
    threat = _has_nearby(text, account, blocked, 65) and _active_local_action(text, blocked, negation)
    kyc_demand = _has_nearby(text, kyc, kyc_action, 80) and _active_local_action(text, kyc_action, negation)
    if threat or kyc_demand:
        found["kyc_or_account_threat"] = _localized_indicator(language, "kyc_or_account_threat")
        if threat or _active_local_action(text, _local_re(patterns, "urgency"), negation):
            high.add("kyc_or_account_threat")

    urls = _extract_urls(text)
    short_link = any((host := _url_host(url)) in _SHORTENERS or any(host.endswith(f".{domain}") for domain in _SHORTENERS) for url in urls)
    suspicious_link = any(_is_suspicious_url(url) for url in urls) or bool(urls and _local_re(patterns, "url_lure").search(text))
    if short_link:
        found["shortened_link"] = _localized_indicator(language, "shortened_link")
    if suspicious_link:
        found["suspicious_url"] = _localized_indicator(language, "suspicious_url")

    remote_action = _local_re(patterns, "remote_action")
    remote_terms = re.compile(r"anydesk|teamviewer|rustdesk|ultraviewer|quick\s*support|chrome remote desktop|remote access|screen\s*sharing|ரிமோட்", re.IGNORECASE)
    if _has_nearby(text, remote_terms, remote_action, 90) and _active_local_action(text, remote_action, negation):
        found["remote_access_request"] = _localized_indicator(language, "remote_access_request")
        high.add("remote_access_request")

    qr = _local_re(patterns, "qr")
    qr_action = _local_re(patterns, "qr_action")
    receive = _local_re(patterns, "receive")
    qr_manipulation = (_has_nearby(text, qr, qr_action, 70) and _has_nearby(text, qr, receive, 90)) or (
        _has_nearby(text, qr, _local_re(patterns, "credential"), 45) and _has_nearby(text, qr, receive, 90)
    )
    if qr_manipulation and _active_local_action(text, qr_action, negation):
        found["qr_upi_payment_manipulation"] = _localized_indicator(language, "qr_upi_payment_manipulation")
        high.add("qr_upi_payment_manipulation")

    authority_claim = _has_nearby(text, _local_re(patterns, "authority"), _local_re(patterns, "authority_claim"), 90)
    if authority_claim:
        found["authority_impersonation_claim"] = _localized_indicator(language, "authority_impersonation_claim")

    money_action = _local_re(patterns, "money_action")
    urgent = _local_re(patterns, "urgency")
    money_demand = _has_nearby(text, money_action, _local_re(patterns, "money"), 90) and _has_nearby(text, money_action, urgent, 85)
    if money_demand and _active_local_action(text, money_action, negation):
        found["urgent_money_transfer"] = _localized_indicator(language, "urgent_money_transfer")
        high.add("urgent_money_transfer")
    if authority_claim and _active_local_action(text, _local_re(patterns, "money_action"), negation):
        high.add("authority_impersonation_claim")

    content = _LOCAL_TEXT[language]
    indicators = list(found.values())
    if high:
        risk = "high"
        actions = content["high_actions"]
        question = None
    elif found:
        risk = "caution"
        actions = content["caution_actions"]
        question = content["question"]
    else:
        risk = "insufficient_information"
        actions = content["unknown_actions"]
        question = content["question"]
    return Assessment(
        risk_classification=risk,
        matched_indicators=indicators,
        explanations=[item.explanation for item in indicators],
        recommended_actions=actions,  # type: ignore[arg-type]
        clarifying_question=question,  # type: ignore[arg-type]
        safety_disclaimer=content["disclaimer"],  # type: ignore[arg-type]
    )


def assess_message(message: str, language: str = "en-IN") -> Assessment:
    """Assess supported language text deterministically without retaining it."""
    if language == "en-IN":
        return _assess_english(message)
    if language not in _LOCAL_PATTERNS:
        raise ValueError(f"Unsupported language: {language}")
    return _assess_local(message, language)
