import re
import unicodedata
from difflib import SequenceMatcher

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

ACTION_TERMS = [
    "ignore", "disregard", "forget", "bypass", "override", "disable", "remove"
]

EXTRACTION_TERMS = [
    "reveal", "show", "print", "display", "leak", "expose", "dump", "export"
]

AUTHORITY_TERMS = [
    "previous", "prior", "earlier", "above", "system", "developer", "hidden", "internal"
]

INSTRUCTION_TERMS = [
    "instruction", "instructions", "prompt", "message", "messages", "rules", "policy", "policies"
]

SAFETY_TERMS = [
    "safety", "guardrails", "guardrail", "moderation", "filter", "filters", "policy", "policies"
]

SECRET_TERMS = [
    "secret", "secrets", "token", "tokens", "password", "passwords", "api", "key", "keys", "env"
]


def similarity(first_word, second_word):
    return SequenceMatcher(None, first_word, second_word).ratio()


def find_fuzzy_terms(tokens, terms, threshold=0.82):
    hits = []

    for token in tokens:
        for term in terms:
            score = similarity(token, term)
        
            if token == term or score >= threshold:
                hits.append({
                    "token": token,
                    "matched_term": term,
                    "score": round(score, 2),
                })

    return hits


def add_heuristic_match(matches, match_id, category, severity, description, matched_terms):
    existing_ids = []

    for match in matches:
        existing_ids.append(match["id"])

    if match_id in existing_ids:
        return
    
    matches.append({
        "id": match_id,
        "phrase": match_id.replace("_", " "),
        "category": category,
        "severity":severity,
        "description":description,
        "matched_patterns": ["heuristic:fuzzy_semantic_match"],
        "matched_terms": matched_terms,
    })


def add_heuristic_matches(matches, normalized_prompt):
    tokens = normalized_prompt.split()
    
    action_hits = find_fuzzy_terms(tokens, ACTION_TERMS)
    extraction_hits = find_fuzzy_terms(tokens, EXTRACTION_TERMS)
    authority_hits = find_fuzzy_terms(tokens, AUTHORITY_TERMS)
    instruction_hits = find_fuzzy_terms(tokens, INSTRUCTION_TERMS)
    safety_hits = find_fuzzy_terms(tokens, SAFETY_TERMS)
    secret_hits = find_fuzzy_terms(tokens, SECRET_TERMS)

    if action_hits and authority_hits and instruction_hits:
        add_heuristic_match(
            matches=matches,
            match_id="fuzzy_instruction_override",
            category="instruction_override",
            severity=55,
            description="Fuzzy semantic match for instruction override attempt.",
            matched_terms={
                "actions": action_hits,
                "authority_terms": authority_hits,
                "instruction_terms": instruction_hits,
            },
        )

    if action_hits and safety_hits:
        add_heuristic_match(
            matches=matches,
            match_id="fuzzy_safety_bypass",
            category="safety_bypass",
            severity=50,
            description="Fuzzy semantic match for safety bypass attempt.",
            matched_terms={
                "actions": action_hits,
                "safety_terms": safety_hits,
            },
        )

    if extraction_hits and authority_hits and instruction_hits:
        add_heuristic_match(
            matches=matches,
            match_id="fuzzy_system_prompt_extraction",
            category="system_prompt_extraction",
            severity=60,
            description="Fuzzy semantic match for system or developer prompt extraction.",
            matched_terms={
                "extraction_terms": extraction_hits,
                "authority_terms": authority_hits,
                "instruction_terms": instruction_hits,
            },
        )

    if extraction_hits and secret_hits:
        add_heuristic_match(
            matches=matches,
            match_id="fuzzy_secret_extraction",
            category="secret_extraction",
            severity=70,
            description="Fuzzy semantic match for secret extraction attempt.",
            matched_terms={
                "extraction_terms": extraction_hits,
                "secret_terms": secret_hits,
            },
        )


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
        
        add_heuristic_matches(matches, normalized_prompt)

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