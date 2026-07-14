import argparse

from detectors.rule_based import detect_with_rules
from detectors.openai_detector import detect_with_openai
from detectors.gemini_detector import detect_with_gemini
from reports.console_report import print_console_report
from reports.json_report import print_json_report


from detectors.rule_based import detect_with_rules
from detectors.gemini_detector import detect_with_gemini
from detectors.openai_detector import detect_with_openai


def get_level_from_score(score):
    if score == 0:
        return "LOW"
    elif score < 45:
        return "MEDIUM"
    elif score < 75:
        return "HIGH"
    else:
        return "CRITICAL"


def combine_categories(first, second):
    combined = []

    for category in first + second:
        if category not in combined:
            combined.append(category)

    return combined


def detect_with_hybrid(prompt, ai_detector=detect_with_gemini, provider_name="gemini"):
    rules_result = detect_with_rules(prompt)
    ai_result = ai_detector(prompt)

    if ai_result["status"] != "completed":
        rules_result["detection_method"] = "hybrid_rules_with_" + provider_name + "_fallback"
        rules_result["ai_provider"] = provider_name
        rules_result["ai_provider_status"] = ai_result["status"]
        rules_result["ai_provider_error"] = ai_result.get("error")
        rules_result["ai_provider_recommendation"] = ai_result.get("recommendation")
        rules_result["recommendation"] = (
            rules_result["recommendation"]
            + " AI provider was unavailable, so the local rules engine result is shown."
        )

        return rules_result

    combined_score = max(
        rules_result.get("risk_score", 0),
        ai_result.get("risk_score", 0),
    )

    combined_level = get_level_from_score(combined_score)

    return {
        "status": "completed",
        "is_attack": rules_result["is_attack"] or ai_result["is_attack"],
        "risk_score": combined_score,
        "risk_level": combined_level,
        "matches": rules_result["matches"],
        "categories": combine_categories(
            rules_result.get("categories", []),
            ai_result.get("categories", []),
        ),
        "safe_to_process": combined_level in ["LOW", "MEDIUM"],
        "recommendation": "Hybrid analysis completed using local rules and AI provider.",
        "detection_method": "hybrid_rules_and_" + provider_name,
        "rules_result": rules_result,
        "ai_result": ai_result,
    }


def detect_prompt_attack(prompt, method):
    if method == "rules":
        return detect_with_rules(prompt)
    elif method == "gemini":
        return detect_with_gemini(prompt)
    elif method == "openai":
        return detect_with_openai(prompt)
    elif method == "hybrid":
        return detect_with_hybrid(prompt, detect_with_gemini, "gemini")
    else:
        return {
            "status": "error",
            "is_attack": None,
            "risk_score": None,
            "risk_level": "UNKNOWN",
            "matches": [],
            "categories": [],
            "safe_to_process": False,
            "recommendation": "Unknown detection method selected. Available methods: rules, gemini, openai, hybrid.",
            "detection_method": method,
        }


def detect_with_ai_fallback(prompt, ai_detector, provider_name):
    rules_result = detect_with_rules(prompt)
    ai_result = ai_detector(prompt)

    if ai_result["status"] != "completed":
        rules_result["detection_method"] = "rule_based_with_" + provider_name + "_fallback"
        rules_result["ai_provider"] = provider_name
        rules_result["ai_provider_status"] = ai_result["status"]
        rules_result["ai_provider_error"] = ai_result.get("error")
        rules_result["ai_provider_recommendation"] = ai_result.get("recommendation")

        rules_result["recommendation"] = (
            rules_result["recommendation"] +
            " AI provider was unavailable, so the local rules engine result is shown."
        )

        return rules_result
    
    combined_risk_score = max(
        rules_result["risk_score"],
        ai_result["risk_score"],
    )

    combined_categories = []

    for category in rules_result["categories"] + ai_result["categories"]:
        if category not in combined_categories:
            combined_categories.append(category)
    
    combined_result = ai_result
    combined_result["risk_score"] = combined_risk_score
    combined_result["categories"] = combined_categories
    combined_result["matches"] = rules_result["matches"]
    combined_result["detection_method"] = "hybrid_" + provider_name + "_and_rules"
    combined_result["safe_to_process"] = combined_risk_score < 75

    return combined_result

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Detect all possible attacks in prompt."
    )
    parser.add_argument(
        "--prompt",
        type=str,
        help="Prompt text to analyze."
    )
    parser.add_argument(
        "--method",
        type=str,
        choices=["rules", "openai", "gemini", "hybrid"],
        default="rules",
        help="Choice method of investigate your prompt."
    )
    parser.add_argument(
        "--format",
        type=str,
        choices=["console", "json"],
        default="console",
        help="Choice your preffered raport format."
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    prompt = args.prompt

    if prompt is None or prompt.strip == "":
        prompt = input("Prompt: ")

    result = detect_prompt_attack(prompt, args.method)

    if args.format == "json":
        print_json_report(result)
    else:
        print_console_report(result)

if __name__ == "__main__":
    main()