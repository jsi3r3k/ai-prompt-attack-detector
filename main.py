from detectors.rule_based import detect_with_rules
from detectors.openai_detector import detect_with_openai
from reports.console_report import print_report


def detect_prompt_attack(prompt, method):
    if method == "rules":
        return detect_with_rules(prompt)
    elif method == "openai":
        return detect_with_openai(prompt)
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


def main():
    prompt = input("Prompt: ")
    method = input("Detection method [rules/openai]: ")

    if method == "":
        method = "rules"

    result = detect_prompt_attack(prompt, method)

    print_report(result)


if __name__ == "__main__":
    main()