import json
import os

from detectors.ai_common import (
    build_ai_classifier_prompt,
    error_result,
    get_ai_detection_schema,
    normalize_ai_result,
    not_configured_result,
)

from config import OPENAI_API_KEY, OPENAI_MODEL

def detect_with_openai(prompt, model=None):
    selected_model = model or OPENAI_MODEL

    if OPENAI_API_KEY is None or OPENAI_API_KEY.strip() == "":
        return not_configured_result(
            provider="openai",
            model=selected_model,
            message="OpenAI API key is not configured. Set OPENAI_API_KEY in your .env file.",
        )
    try:
        from openai import OpenAI
    except ImportError:
        return not_configured_result(
            provider="openai",
            model=model,
            message="openai package is not installed. Run: pip install openai",
        )

    try:
        client = OpenAI()

        response = client.responses.create(
            model=model,
            input=[
                {
                    "role": "system",
                    "content": "You are a cybersecurity classifier. Return structured JSON only.",
                },
                {
                    "role": "user",
                    "content": build_ai_classifier_prompt(prompt),
                },
            ],
            text={
                "format": {
                    "type": "json_schema",
                    "name": "prompt_attack_detection",
                    "schema": get_ai_detection_schema(),
                    "strict": True,
                }
            },
        )

        data = json.loads(response.output_text)

        return normalize_ai_result(
            data,
            detection_method="openai_api",
        )

    except Exception as error:
        return error_result(
            provider="openai",
            model=model,
            error_message=str(error),
        )