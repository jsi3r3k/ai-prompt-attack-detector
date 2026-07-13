import argparse

from detectors.rule_based import detect_with_rules
from detectors.openai_detector import detect_with_openai
from reports.console_report import print_console_report
from reports.json_report import print_json_report


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
        choices=["rules", "openai"],
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