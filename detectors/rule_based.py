import re
import unicodedata

from detectors.rules_database import DETECTION_RULES

LEETSPEAK_TABLE = str.maketrans({
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
})


def normalize_prompt(prompt):
    normalized = unicodedata.normalize("NFKC", prompt)
    normalized = normalized.lower()
    normalized = normalized.translate(LEETSPEAK_TABLE)
    normalized = re.sub(r"[_\-./\\|]+", " ", normalized)
    normalized = re.sub(r"[^\w\s]", " ", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()

    return normalized


def compact_prompt(prompt):
    normalized = normalize_prompt(prompt)
    compacted = re.sub(r"[^a-z0-9]", "", normalized)

    return compacted


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


def find_rule_matches(rule, normalized_prompt, compacted_prompt):
    matched_patterns = []

    for pattern in rule["patterns"]:
        if re.search(pattern, normalized_prompt):
            matched_patterns.append(pattern)

    for compact_pattern in rule.get("compact_patterns", []):
        if compact_pattern in compacted_prompt:
            matched_patterns.append("compact: " + compact_pattern)

    return matched_patterns

def detect_with_rules(prompt):
    normalized_prompt = normalize_prompt(prompt)
    compacted_prompt = compact_prompt(prompt)

    matches = []

    for rule in DETECTION_RULES:
        matched_patterns = find_rule_matches(rule, normalized_prompt, compacted_prompt)

        if len(matched_patterns) > 0:
            matches.append({
                "id": rule["id"],
                "phrase": rule["phrase"],
                "category": rule["category"],
                "severity": rule["severity"],
                "description": rule["description"],
                "matched_patterns": matched_patterns,
            })

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
        "detection_method": "rule_based",
        "checked_rules_count": len(DETECTION_RULES),
        "matched_rules_count": len(matches),
    }