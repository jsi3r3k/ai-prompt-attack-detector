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


def detect_prompt_attack(prompt):
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

    result = {
        "is_attack": risk_score > 0,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "matches": matches,
        "detection_method": "rule_based",
    }

    return result


def print_report(result):
    if result["is_attack"]:
        print("Warning: this prompt may be a prompt injection attack.")
        print("Risk score:", result["risk_score"])
        print("Risk level:", result["risk_level"])
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


if __name__ == "__main__":
    prompt = input("Prompt: ")

    result = detect_prompt_attack(prompt)

    print_report(result)