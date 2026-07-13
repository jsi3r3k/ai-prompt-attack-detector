def print_console_report(result):
    if result["status"] != "completed":
        print("Detection could not be completed.")
        print("Status:", result["status"])
        print("Detection method:", result["detection_method"])
        print("Safe to process:", result["safe_to_process"])
        print("Recommendation:", result["recommendation"])
        return

    if result["is_attack"]:
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