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
    if risk_score == 0:
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
    elif risk_level == "CRITICAL":
        return "Prompt should be blocked before reaching the AI model."
    else:
        return "Unknown risk level. Contact the administrator."


def detect_with_rules(prompt):
    normalized_prompt = prompt.lower()
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

    result = {
        "status": "completed",
        "is_attack": risk_score > 0,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "matches": matches,
        "categories": categories,
        "safe_to_process": safe_to_process,
        "recommendation": recommendation,
        "detection_method": "rule_based",
    }

    return result


def detect_prompt_attack(prompt, method="rules"):
    if method == "rules":
        return detect_with_rules(prompt)

    elif method == "openai":
        return {
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

    else:
        return {
            "status": "error",
            "is_attack": None,
            "risk_score": None,
            "risk_level": "UNKNOWN",
            "matches": [],
            "categories": [],
            "safe_to_process": False,
            "recommendation": "Unknown detection method selected. Available methods: rules, openai.",
            "detection_method": method,
        }


def print_report(result):
    if result["status"] != "completed":
        print("Detection could not be completed.")
        print("Status:", result["status"])
        print("Detection method:", result["detection_method"])
        print("Safe to process:", result["safe_to_process"])
        print("Recommendation:", result["recommendation"])
        return
    elif result["is_attack"]:
        print("Warning: this prompt may be a prompt injection attack.")
        print("Risk score:", result["risk_score"])
        print("Risk level:", result["risk_level"])
        print("Safe to process:", result["safe_to_process"])
        print("Recommendation:", result["recommendation"])
        print("Categories:", ", ".join(result["categories"]))
        print("Detection method:", result["detection_method"])
        print("Suspicious matches:")

        for match in result["matches"]:
            print("- Phrase:", match["phrase"])
            print("  Category:", match["category"])
            print("  Severity:", match["severity"])
    else:
        print("This prompt looks safe.")
        print("Risk score:", result["risk_score"])
        print("Risk level:", result["risk_level"])
        print("Detection method:", result["detection_method"])
        print("Safe to process:", result["safe_to_process"])
        print("Recommendation:", result["recommendation"])


def main():
    prompt = input("Give your prompt: ")
    method = input("Give your method [rules/openai]: ")

    if method == "":
        method = "rules"

    result = detect_prompt_attack(prompt, method=method)

    print_report(result)

if __name__ == "__main__":
    main()