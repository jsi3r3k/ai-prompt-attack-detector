DETECTION_RULES = [
    {
        "id": "instruction_override_previous",
        "phrase": "ignore previous instructions",
        "category": "instruction_override",
        "severity": 45,
        "description": "Attempts to override previous or higher-priority instructions.",
        "patterns": [
            r"\b(ignore|disregard|forget|bypass|override)\b.{0,80}\b(previous|prior|earlier|above|original)\b.{0,80}\b(instructions?|rules?|directions?|messages?|prompt)\b",
            r"\bdo not follow\b.{0,80}\b(previous|prior|above|earlier)\b",
        ],
        "compact_patterns": [
            "ignorepreviousinstructions",
            "forgetpreviousinstructions",
            "overridepreviousinstructions",
        ],
    },
    {
        "id": "system_prompt_extraction",
        "phrase": "reveal system prompt",
        "category": "system_prompt_extraction",
        "severity": 55,
        "description": "Attempts to extract system prompts or hidden model instructions.",
        "patterns": [
            r"\b(reveal|show|print|display|tell me|give me|leak|expose)\b.{0,80}\b(system prompt|system message|hidden instructions|developer message|internal instructions|initial prompt)\b",
        ],
        "compact_patterns": [
            "revealsystemprompt",
            "showhiddeninstructions",
            "printsystemmessage",
        ],
    },
    {
        "id": "developer_message_extraction",
        "phrase": "developer message",
        "category": "internal_instruction_extraction",
        "severity": 50,
        "description": "Attempts to access developer messages or internal instruction layers.",
        "patterns": [
            r"\b(developer message|developer instructions|internal message|internal instructions)\b",
            r"\b(show|reveal|print|display)\b.{0,80}\b(developer|internal)\b.{0,80}\b(message|instructions|rules)\b",
        ],
        "compact_patterns": [
            "developermessage",
            "developerinstructions",
            "internalinstructions",
        ],
    },
    {
        "id": "jailbreak_attempt",
        "phrase": "jailbreak",
        "category": "jailbreak_attempt",
        "severity": 45,
        "description": "Attempts to jailbreak or unlock restricted model behavior.",
        "patterns": [
            r"\b(jailbreak|dan mode|developer mode|unfiltered mode|no restrictions)\b",
            r"\bpretend\b.{0,80}\b(unrestricted|unfiltered|no rules|no limitations)\b",
        ],
        "compact_patterns": [
            "jailbreak",
            "danmode",
            "developermode",
        ],
    },
    {
        "id": "safety_bypass",
        "phrase": "bypass safety",
        "category": "safety_bypass",
        "severity": 45,
        "description": "Attempts to disable safety policies, filters, or guardrails.",
        "patterns": [
            r"\b(disable|turn off|bypass|ignore|remove)\b.{0,80}\b(safety|guardrails|policy|policies|filters?|moderation)\b",
        ],
        "compact_patterns": [
            "bypasssafety",
            "disableguardrails",
            "ignorepolicy",
        ],
    },
    {
        "id": "secret_extraction",
        "phrase": "reveal secrets",
        "category": "secret_extraction",
        "severity": 60,
        "description": "Attempts to extract secrets, tokens, passwords, or environment variables.",
        "patterns": [
            r"\b(show|print|reveal|leak|dump|exfiltrate)\b.{0,80}\b(api keys?|tokens?|passwords?|secrets?|environment variables?|env vars?)\b",
        ],
        "compact_patterns": [
            "revealapikey",
            "printenvvars",
            "dumpsecrets",
        ],
    },
    {
        "id": "conversation_exfiltration",
        "phrase": "dump conversation",
        "category": "conversation_exfiltration",
        "severity": 40,
        "description": "Attempts to export or dump conversation history, memory, or context.",
        "patterns": [
            r"\b(send|copy|export|dump|print|show)\b.{0,80}\b(conversation|chat history|all messages|memory|context)\b",
        ],
        "compact_patterns": [
            "dumpconversation",
            "exportchathistory",
            "showallmessages",
        ],
    },
    {
        "id": "encoded_payload",
        "phrase": "encoded hidden instructions",
        "category": "obfuscation",
        "severity": 30,
        "description": "Suspicious encoded or obfuscated instruction payload.",
        "patterns": [
            r"\b(decode|base64|rot13|hex|encoded)\b.{0,100}\b(instruction|prompt|message|payload|command)\b",
        ],
        "compact_patterns": [
            "base64instructions",
            "encodedprompt",
        ],
    },
]