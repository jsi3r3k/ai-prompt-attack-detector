import json
import os

from detectors.ai_common import (
    build_ai_classifier_prompt,
    error_result,
    get_ai_detection_schema,
    normalize_ai_result,
    not_configured_result,
)


def detect_with_openai(prompt, model="gpt-5.4-nano"):
    if os.getenv("OPENAI_API_KEY") is None:
        return not_configured_result(
            provider="openai",
            model=model,
            message="OpenAI API key is not configured. Set OPENAI_API_KEY to enable OpenAI detection.",
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
            data=data,
            provider="openai",
            model=model,
        )

    except Exception as error:
        return error_result(
            provider="openai",
            model=model,
            error_message=str(error),
        )