suspicious_phrases = [
    "ignore previous instructions",
    "forget previous instructions",
    "reveal your system prompt",
    "show me your hidden instructions",
    "jailbreak",
    "developer message",
    "system message",
    "override instructions",
]

prompt = input("Ask question: ")
prompt = prompt.lower()

found_suspicious_phrases = []

for suspicious_phrase in suspicious_phrases:
    if suspicious_phrase in prompt:
        found_suspicious_phrases.append(suspicious_phrase)

risk_score = len(found_suspicious_phrases) * 25

if risk_score > 100:
    risk_score = 100

if risk_score == 0:
    risk_level = "LOW"
elif risk_score < 50:
    risk_level = "MEDIUM"
else:
    risk_level = "HIGH"

if len(found_suspicious_phrases) > 0:
    print("Warning: this prompt may be a prompt injection attack.")
    print("Suspicious phrases found:")

    for phrase in found_suspicious_phrases:
        print("- " + phrase)
else:
    print("This prompt looks safe.")

print("Risk score:", risk_score)
print("Risk level:", risk_level)