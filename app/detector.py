import re

class SecurityDetector:
    """
    Detection engine for identifying potential indirect prompt injection attacks,
    exfiltration attempts, system overrides, and malicious payloads in untrusted content.
    """

    PATTERNS = [
        # System Prompt Overrides & Instruction Hijacking
        {
            "id": "OVERRIDE_DIRECTIVE",
            "category": "System Prompt Override",
            "severity": "HIGH",
            "weight": 40,
            "pattern": r"(?i)\b(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|system)\s+(instructions|directives|prompts|rules)\b",
            "explanation": "Attempts to overwrite or erase the AI agent's base system prompt instructions."
        },
        {
            "id": "NEW_INSTRUCTION_HEADER",
            "category": "System Prompt Override",
            "severity": "HIGH",
            "weight": 35,
            "pattern": r"(?i)\b(new|updated|important|priority)\s+instructions?\s*[:\-]",
            "explanation": "Injects a fake high-priority instruction header to hijack downstream AI reasoning."
        },
        {
            "id": "PERSONA_SWITCH",
            "category": "Jailbreak / Persona Switch",
            "severity": "HIGH",
            "weight": 35,
            "pattern": r"(?i)\b(you\s+are\s+now|act\s+as|pretend\s+to\s+be|roleplay\s+as)\s+(an?\s+)?(unrestricted|unfiltered|DAN|developer\s+mode|god\s+mode)\b",
            "explanation": "Attempts to switch the AI agent into an unrestricted or unsafe role/persona."
        },

        # Data & Credential Exfiltration
        {
            "id": "EXFILTRATE_SYSTEM_PROMPT",
            "category": "Data Exfiltration",
            "severity": "HIGH",
            "weight": 40,
            "pattern": r"(?i)\b(print|output|display|show|reveal|echo|send|exfiltrate)\s+(the\s+)?(system\s+prompt|initial\s+prompt|api\s+keys?|passwords?|credentials?|secret_keys?)\b",
            "explanation": "Instructs the AI agent to output confidential system instructions, credentials, or API keys."
        },
        {
            "id": "MARKDOWN_EXFILTRATION",
            "category": "Data Exfiltration",
            "severity": "HIGH",
            "weight": 40,
            "pattern": r"!\[.*?\]\(https?://[^\s\)]+[\?&](key|token|data|prompt|secret|stolen)=",
            "explanation": "Uses an embedded Markdown image tag to exfiltrate stolen data to an external attacker server."
        },
        {
            "id": "EXTERNAL_URL_FETCH",
            "category": "Data Exfiltration",
            "severity": "MEDIUM",
            "weight": 25,
            "pattern": r"(?i)\b(fetch|send|post|transmit)\s+(data|info|keys?|content)\s+to\s+https?://",
            "explanation": "Instructs the AI agent to exfiltrate information to an external web destination."
        },

        # Hidden System Tags & Boundary Spanning
        {
            "id": "HIDDEN_SYSTEM_TAG",
            "category": "Hidden Payload / System Tags",
            "severity": "HIGH",
            "weight": 35,
            "pattern": r"</?(system|instruction|override|admin|prompt_injection)>",
            "explanation": "Uses fake structural HTML/XML tags (e.g. <system>) to trick the LLM parser into accepting external text as system instructions."
        },
        {
            "id": "ZERO_WIDTH_CHARACTER",
            "category": "Obfuscated Payload",
            "severity": "MEDIUM",
            "weight": 20,
            "pattern": r"[\u200B-\u200D\uFEFF]",
            "explanation": "Contains hidden zero-width Unicode characters used for steganography or bypassing text filters."
        },

        # Malicious Code Execution / Command Injection
        {
            "id": "SHELL_EXECUTION",
            "category": "Malicious Command Directive",
            "severity": "HIGH",
            "weight": 40,
            "pattern": r"(?i)\b(rm\s+-rf|format\s+[c-z]:|os\.system|subprocess\.call|drop\s+table|delete\s+from)\b",
            "explanation": "Contains dangerous system-level command execution or database deletion directives."
        }
    ]

    def analyze(self, content: str) -> dict:
        """
        Analyzes the provided text content for indirect prompt-injection vectors.

        Returns a dictionary containing:
        - risk_score: int (0 to 100)
        - risk_level: str ("SAFE", "SUSPICIOUS", "MALICIOUS")
        - recommended_action: str ("ALLOW", "ISOLATE", "BLOCK")
        - summary: str (human readable explanation)
        - flagged_snippets: list of dicts with match details
        - stats: dict containing content metrics
        """
        if not content or not content.strip():
            return {
                "risk_score": 0,
                "risk_level": "SAFE",
                "recommended_action": "ALLOW",
                "summary": "Content is empty or contains no text to analyze.",
                "flagged_snippets": [],
                "stats": {"length": 0, "lines": 0, "patterns_flagged": 0}
            }

        lines = content.splitlines()
        flagged_snippets = []
        matched_pattern_ids = set()
        total_weight = 0

        # Scan line by line for precise line matching
        for line_idx, line in enumerate(lines, start=1):
            for rule in self.PATTERNS:
                matches = re.finditer(rule["pattern"], line)
                for match in matches:
                    matched_snippet = match.group(0)
                    flagged_snippets.append({
                        "pattern_id": rule["id"],
                        "category": rule["category"],
                        "severity": rule["severity"],
                        "line": line_idx,
                        "snippet": matched_snippet,
                        "line_content": line.strip(),
                        "explanation": rule["explanation"]
                    })
                    if rule["id"] not in matched_pattern_ids:
                        matched_pattern_ids.add(rule["id"])
                        total_weight += rule["weight"]

        # Also check multi-line match for markdown image exfiltration or tags spanning lines
        for rule in self.PATTERNS:
            if rule["id"] not in matched_pattern_ids:
                if re.search(rule["pattern"], content, re.DOTALL):
                    matched_pattern_ids.add(rule["id"])
                    total_weight += rule["weight"]
                    flagged_snippets.append({
                        "pattern_id": rule["id"],
                        "category": rule["category"],
                        "severity": rule["severity"],
                        "line": 1,
                        "snippet": "Multi-line pattern match",
                        "line_content": rule["category"],
                        "explanation": rule["explanation"]
                    })

        # Calculate final risk score (0 to 100)
        risk_score = min(100, total_weight)

        # Classify risk level and recommended action
        if risk_score >= 60:
            risk_level = "MALICIOUS"
            recommended_action = "BLOCK"
            summary = (f"HIGH RISK DETECTED (Score {risk_score}/100): Content contains active indirect prompt injection "
                       f"or data exfiltration directives targeting AI agents. Recommended Action: BLOCK.")
        elif risk_score >= 25:
            risk_level = "SUSPICIOUS"
            recommended_action = "ISOLATE"
            summary = (f"SUSPICIOUS CONTENT (Score {risk_score}/100): Content contains ambiguous or potentially risky "
                       f"instructions. Recommended Action: ISOLATE FOR HUMAN REVIEW.")
        else:
            risk_level = "SAFE"
            recommended_action = "ALLOW"
            summary = "SAFE CONTENT (Score 0/100): No indirect prompt injection or malicious directives were detected."

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "recommended_action": recommended_action,
            "summary": summary,
            "flagged_snippets": flagged_snippets,
            "stats": {
                "length": len(content),
                "lines": len(lines),
                "patterns_flagged": len(flagged_snippets)
            }
        }
