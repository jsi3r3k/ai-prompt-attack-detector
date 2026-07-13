def detect_with_openai(prompt):
    result = {
        "status": "not_configured",
        "is_attack": None,
        "risk_score": None,
        "risk_level": "UNKNOWN",
        "matches": [],
        "categories": [],
        "safe_to_process": False,
        "recommendation": "OpenAI detection mode is not configured yet. Use rules mode for free local detection.",
        "detection_method": "openai_api",
    }

    return result