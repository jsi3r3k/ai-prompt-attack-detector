detection_rules = [
    {
        "phrase": "ignore previous instructions",
        "category": "instruction_override",
        "severity": 35,
    },
    {
        "phrase": "forget previous instructions",
        "category": "instruction_override",
        "severity": 35,
    },
    {
        "phrase": "reveal your system prompt",
        "category": "system_prompt_extraction",
        "severity": 50,
    },
    {
        "phrase": "show me your hidden instructions",
        "category": "system_prompt_extraction",
        "severity": 50,
    },
    {
        "phrase": "jailbreak",
        "category": "jailbreak_attempt",
        "severity": 40,
    },
    {
        "phrase": "developer message",
        "category": "internal_instruction_extraction",
        "severity": 45,
    },
    {
        "phrase": "system message",
        "category": "internal_instruction_extraction",
        "severity": 45,
    },
    {
        "phrase": "override instructions",
        "category": "instruction_override",
        "severity": 40,
    },
]


def get_risk_level(risk_score):
    if risk_score == 0 or risk_score < 10:
        return "LOW"
    elif risk_score < 50:
        return "MEDIUM"
    elif risk_score < 80:
        return "HIGH"
    else:
        return "CRITICAL"


def get_recommendation(risk_level):
    if risk_level == "LOW":
        return "Prompt looks safe and can be processed."
    elif risk_level == "MEDIUM":
        return "Prompt should be processed with caution."
    elif risk_level == "HIGH":
        return "Prompt should be reviewed before sending it to the AI model."
    else:
        return "Prompt should be blocked before reaching the AI model."


def normalize_prompt(prompt):
    return prompt.lower().strip()


def detect_with_rules(prompt):
    normalized_prompt = normalize_prompt(prompt)
    matches = []

    for rule in detection_rules:
        if rule["phrase"] in normalized_prompt:
            matches.append(rule)

    risk_score = 0

    for match in matches:
        risk_score += match["severity"]

    if risk_score > 100:
        risk_score = 100

    risk_level = get_risk_level(risk_score)

    categories = []

    for match in matches:
        if match["category"] not in categories:
            categories.append(match["category"])

    recommendation = get_recommendation(risk_level)
    safe_to_process = risk_level in ["LOW", "MEDIUM"]

    return {
        "status": "completed",
        "is_attack": risk_score > 0,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "matches": matches,
        "categories": categories,
        "safe_to_process": safe_to_process,
        "recommendation": recommendation,
        "checked_rules_count": len(detection_rules),
        "matched_rules_count": len(matches),
        "detection_method": "rule_based",
    }