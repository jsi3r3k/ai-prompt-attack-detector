import json
import os

from detectors.ai_common import (
    build_ai_classifier_prompt,
    error_result,
    get_ai_detection_schema,
    normalize_ai_result,
    not_configured_result,
)

from config import GEMINI_API_KEY, GEMINI_MODEL


def detect_with_gemini(prompt):
    api_key = (GEMINI_API_KEY or "").strip()
    model = (GEMINI_MODEL or "gemini-2.5-flash-lite").strip()

    if not api_key:
        return {
            "status": "error",
            "is_attack": False,
            "risk_score": None,
            "risk_level": "UNKNOWN",
            "matches": [],
            "categories": [],
            "safe_to_process": False,
            "recommendation": "Gemini API key is not configured.",
            "detection_method": "gemini_api",
            "error": "Missing GEMINI_API_KEY.",
        }

    try:
        from google import genai
    except ImportError:
        return not_configured_result(
            provider="gemini",
            model=model,
            message="google-genai package is not installed. Run: pip install -U google-genai",
        )

    try:
        client = genai.Client()

        interaction = client.interactions.create(
            model=model,
            input=build_ai_classifier_prompt(prompt),
            response_format={
                "type": "text",
                "mime_type": "application/json",
                "schema": get_ai_detection_schema(),
            },
        )

        data = json.loads(interaction.output_text)

        return normalize_ai_result(
            data=data,
            provider="gemini",
            model=model,
        )

    except Exception as error:
        return error_result(
            provider="gemini",
            model=model,
            error_message=str(error),
        )