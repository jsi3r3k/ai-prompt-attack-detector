import json
import os

from detectors.ai_common import (
    build_ai_classifier_prompt,
    error_result,
    get_ai_detection_schema,
    normalize_ai_result,
    not_configured_result,
)


def detect_with_gemini(prompt, model="gemini-3.5-flash"):
    if os.getenv("GEMINI_API_KEY") is None:
        return not_configured_result(
            provider="gemini",
            model=model,
            message="Gemini API key is not configured. Set GEMINI_API_KEY to enable Gemini detection.",
        )

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