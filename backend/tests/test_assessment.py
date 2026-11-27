import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.fraud_detection import MAX_MESSAGE_LENGTH
from app.main import AssessmentResponse, app

client = TestClient(app)


@pytest.mark.parametrize(
    ("message", "expected_indicator", "expected_risk"),
    [
        ("Send me the OTP to release your account.", "credential_harvesting", "high"),
        ("Read your one-time passcode aloud to confirm the refund.", "credential_harvesting", "high"),
        ("Reply with your card CVV and PIN now.", "credential_harvesting", "high"),
        ("What's your password?", "credential_harvesting", "high"),
        ("Tell me the security code to unlock your account.", "credential_harvesting", "high"),
        (
            "Complete your KYC immediately or your account will be blocked today.",
            "kyc_or_account_threat",
            "high",
        ),
        ("Update e-KYC today or your wallet will be deactivated.", "kyc_or_account_threat", "high"),
        ("Your bank account has been frozen; verify your details now.", "kyc_or_account_threat", "high"),
        (
            "Sign in at https://secure-account-check.example/login to verify your bank account.",
            "suspicious_url",
            "caution",
        ),
        ("Open http://192.0.2.10/verify to restore your account.", "suspicious_url", "caution"),
        ("Visit https://xn--paypa1-9za.example/claim", "suspicious_url", "caution"),
        ("Use this link https://bit.ly/4F2abc to continue.", "shortened_link", "caution"),
        ("Continue at https://go.tinyurl.com/abc", "shortened_link", "caution"),
        ("Install AnyDesk so I can fix your bank account.", "remote_access_request", "high"),
        ("Download TeamViewer and grant me screen-sharing access now.", "remote_access_request", "high"),
        ("Scan this QR code to receive your refund.", "qr_upi_payment_manipulation", "high"),
        ("Enter your UPI PIN to receive the cashback.", "qr_upi_payment_manipulation", "high"),
        ("Approve this UPI collect request to get your refund.", "qr_upi_payment_manipulation", "high"),
        (
            "This is an officer calling from the police department.",
            "authority_impersonation_claim",
            "caution",
        ),
        ("I am calling from your bank's fraud team.", "authority_impersonation_claim", "caution"),
        ("This is an officer representing the government; pay the fee now.", "authority_impersonation_claim", "high"),
        (
            "You are under digital arrest and will be arrested unless you pay now.",
            "digital_arrest_or_intimidation",
            "high",
        ),
        ("There is a warrant for your arrest; do not tell anyone.", "digital_arrest_or_intimidation", "high"),
        ("Transfer the money to my account right now.", "urgent_money_transfer", "high"),
        ("Deposit the funds within 10 minutes or lose access.", "urgent_money_transfer", "high"),
    ],
)
def test_detects_requested_categories(message: str, expected_indicator: str, expected_risk: str) -> None:
    response = client.post("/assess", json={"message": message, "source_type": "call"})

    assert response.status_code == 200
    body = AssessmentResponse.model_validate(response.json())
    assert body.risk_classification == expected_risk
    assert expected_indicator in {indicator.code for indicator in body.matched_indicators}


def test_reports_multiple_indicators_and_explanations() -> None:
    response = client.post(
        "/assess",
        json={"message": "Your account will be blocked. Send your OTP and transfer money now."},
    )

    body = AssessmentResponse.model_validate(response.json())
    codes = {indicator.code for indicator in body.matched_indicators}
    assert body.risk_classification == "high"
    assert {"credential_harvesting", "kyc_or_account_threat", "urgent_money_transfer"} <= codes
    assert len(body.explanations) == len(body.matched_indicators)
    assert all(indicator.explanation for indicator in body.matched_indicators)


@pytest.mark.parametrize(
    "message",
    [
        "Never share your OTP, PIN, CVV, or password. Contact your bank using its official app.",
        "Your bank will never ask you to disclose your OTP.",
        "I received a call about an account issue.",
        "The caller mentioned a QR code and UPI but did not ask me to scan anything.",
        "I am reading about OTP safety and KYC guidelines.",
    ],
)
def test_harmless_or_ambiguous_text_does_not_create_false_positive(message: str) -> None:
    response = client.post("/assess", json={"message": message})

    assert response.status_code == 200
    body = AssessmentResponse.model_validate(response.json())
    assert body.risk_classification == "insufficient_information"


def test_unmatched_text_returns_insufficient_information_and_question() -> None:
    response = client.post("/assess", json={"message": "Hello, are we still meeting tomorrow?"})

    body = AssessmentResponse.model_validate(response.json())
    assert body.risk_classification == "insufficient_information"
    assert body.matched_indicators == []
    assert body.clarifying_question
    assert "cannot verify" in body.safety_disclaimer
    assert not any("OTP" in action or "password" in action for action in body.recommended_actions)


@pytest.mark.parametrize("message", ["", "   ", "\n\t"])
def test_rejects_empty_or_whitespace_message(message: str) -> None:
    response = client.post("/assess", json={"message": message})

    assert response.status_code == 422


def test_rejects_message_over_limit() -> None:
    submitted = "private-message-" + "x" * MAX_MESSAGE_LENGTH
    response = client.post("/assess", json={"message": submitted})

    assert response.status_code == 422
    assert submitted not in response.text


def test_rejects_unknown_source_type() -> None:
    response = client.post("/assess", json={"message": "hello", "source_type": "email"})

    assert response.status_code == 422


def test_response_has_only_supported_classification_and_no_confidence_field() -> None:
    response = client.post("/assess", json={"message": "Can you call me back?", "source_type": "WhatsApp"})

    assert response.status_code == 200
    body = AssessmentResponse.model_validate(response.json())
    assert body.risk_classification in {"high", "caution", "insufficient_information"}
    assert "safe" not in response.json()
    assert "confidence" not in response.json()


def test_assessment_does_not_echo_or_log_submitted_message(caplog: pytest.LogCaptureFixture) -> None:
    submitted = "sample private message: call me about account 482917"

    response = client.post("/assess", json={"message": submitted})

    assert response.status_code == 200
    assert submitted not in response.text
    assert submitted not in caplog.text


def test_response_schema_rejects_unsupported_risk_value() -> None:
    with pytest.raises(ValidationError):
        AssessmentResponse.model_validate(
            {
                "risk_classification": "safe",
                "matched_indicators": [],
                "explanations": [],
                "recommended_actions": [],
                "clarifying_question": None,
                "safety_disclaimer": "test",
            }
        )


@pytest.mark.parametrize(
    "message",
    [
        "This guide says never install AnyDesk at a caller's request.",
        "Never scan a QR code to receive money; that could authorize a payment.",
        "Do not transfer the money now without checking with me.",
        "Your bank account will not be blocked.",
    ],
)
def test_negated_safety_guidance_is_not_misclassified(message: str) -> None:
    body = AssessmentResponse.model_validate(client.post("/assess", json={"message": message}).json())

    assert body.risk_classification == "insufficient_information"
    assert body.matched_indicators == []


def test_health_endpoint_remains_available() -> None:
    assert client.get("/health").json() == {"status": "ok"}


@pytest.mark.parametrize(
    ("language", "message", "expected_indicator"),
    [
        ("hi-IN", "अपना OTP अभी बताएं।", "credential_harvesting"),
        ("hi-IN", "आज KYC अपडेट करें नहीं तो खाता बंद हो जाएगा।", "kyc_or_account_threat"),
        ("hi-IN", "यह लिंक https://secure-bank.example/verify खोलें।", "suspicious_url"),
        ("hi-IN", "फोन ठीक करने के लिए AnyDesk इंस्टॉल करें।", "remote_access_request"),
        ("hi-IN", "रिफंड पाने के लिए QR स्कैन करें और UPI PIN डालें।", "qr_upi_payment_manipulation"),
        ("hi-IN", "मैं बैंक से बोल रहा हूँ, अभी पैसे ट्रांसफर करें।", "authority_impersonation_claim"),
        ("hi-IN", "आज ही रुपये transfer करें।", "urgent_money_transfer"),
        ("mr-IN", "तुमचा OTP आत्ता सांगा.", "credential_harvesting"),
        ("mr-IN", "आज KYC अपडेट करा नाहीतर खाते ब्लॉक होईल.", "kyc_or_account_threat"),
        ("mr-IN", "या लिंकवर जा https://secure-bank.example/verify", "suspicious_url"),
        ("mr-IN", "मोबाईल दुरुस्तीसाठी AnyDesk डाउनलोड करा.", "remote_access_request"),
        ("mr-IN", "परतावा मिळवण्यासाठी QR स्कॅन करा आणि UPI PIN भरा.", "qr_upi_payment_manipulation"),
        ("mr-IN", "मी बँकेतून बोलत आहे, आज पैसे ट्रान्सफर करा.", "authority_impersonation_claim"),
        ("mr-IN", "आजच पैसे transfer करा.", "urgent_money_transfer"),
        ("ta-IN", "உங்கள் OTP உடனே சொல்லுங்கள்.", "credential_harvesting"),
        ("ta-IN", "இன்று KYC புதுப்பிக்கவும் இல்லையெனில் கணக்கு முடக்கப்படும்.", "kyc_or_account_threat"),
        ("ta-IN", "இந்த இணைப்பைத் திறக்கவும் https://secure-bank.example/verify", "suspicious_url"),
        ("ta-IN", "உதவிக்காக AnyDesk நிறுவுங்கள்.", "remote_access_request"),
        ("ta-IN", "பணம் திரும்பப் பெற QR ஸ்கேன் செய்து UPI PIN உள்ளிடுங்கள்.", "qr_upi_payment_manipulation"),
        ("ta-IN", "நான் வங்கியிலிருந்து பேசுகிறேன், இன்று பணம் அனுப்புங்கள்.", "authority_impersonation_claim"),
        ("ta-IN", "இன்றே பணம் அனுப்புங்கள்.", "urgent_money_transfer"),
    ],
)
def test_localized_attacks_and_code_mixing(language: str, message: str, expected_indicator: str) -> None:
    response = client.post("/assess", json={"message": message, "language": language})

    assert response.status_code == 200
    body = AssessmentResponse.model_validate(response.json())
    assert expected_indicator in {indicator.code for indicator in body.matched_indicators}
    assert body.risk_classification in {"high", "caution"}
    assert body.safety_disclaimer
    assert body.recommended_actions


@pytest.mark.parametrize(
    ("language", "message"),
    [
        ("hi-IN", "अपना OTP कभी साझा न करें। बैंक के आधिकारिक ऐप से जाँचें।"),
        ("mr-IN", "कृपया OTP कधीही शेअर करू नका."),
        ("ta-IN", "OTP-ஐ ஒருபோதும் பகிராதீர்கள்."),
        ("hi-IN", "मेरा खाता बैंक ऐप में सही दिख रहा है।"),
        ("mr-IN", "माझ्या खात्यात KYC माहिती दिसते."),
        ("ta-IN", "வங்கி கணக்கு பற்றிய பொதுவான தகவல் வேண்டும்."),
    ],
)
def test_localized_negations_and_ambiguous_messages(language: str, message: str) -> None:
    body = AssessmentResponse.model_validate(
        client.post("/assess", json={"message": message, "language": language}).json()
    )

    assert body.risk_classification == "insufficient_information"
    assert body.matched_indicators == []


@pytest.mark.parametrize("language", ["hi-IN", "mr-IN", "ta-IN"])
def test_localized_response_content(language: str) -> None:
    body = AssessmentResponse.model_validate(
        client.post("/assess", json={"message": "नमस्कार", "language": language}).json()
    )

    assert body.risk_classification == "insufficient_information"
    assert body.recommended_actions
    assert body.safety_disclaimer
    assert body.clarifying_question


def test_language_is_optional_defaults_to_en_in_and_rejects_unknown_locale() -> None:
    defaulted = client.post("/assess", json={"message": "Send me the OTP."})
    unsupported = client.post("/assess", json={"message": "नमस्कार", "language": "bn-IN"})

    assert defaulted.status_code == 200
    assert defaulted.json()["risk_classification"] == "high"
    assert unsupported.status_code == 422
