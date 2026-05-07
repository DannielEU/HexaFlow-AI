"""
Language-agnostic OWASP Top 10 prompt builder for source code analysis.
"""

import os

_LANG_MAP: dict[str, str] = {
    ".java": "Java",
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".jsx": "JavaScript (React)",
    ".tsx": "TypeScript (React)",
    ".go": "Go",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".cpp": "C++",
    ".c": "C",
    ".kt": "Kotlin",
    ".swift": "Swift",
    ".rs": "Rust",
    ".scala": "Scala",
    ".sh": "Shell",
    ".tf": "Terraform",
    ".yaml": "YAML",
    ".yml": "YAML",
}

_MAX_CONTENT_CHARS = 4000


def _detect_language(filename: str) -> str:
    ext = os.path.splitext(filename)[1].lower()
    return _LANG_MAP.get(ext, "unknown")


def build_code_analysis_prompt(filename: str, content: str) -> str:
    language = _detect_language(filename)
    truncated = content[:_MAX_CONTENT_CHARS]

    return f"""You are HexaFlow Code Analyzer, an automated OWASP security scanner integrated into a CI/CD pipeline.
Analyze the following {language} source code file for security vulnerabilities.

FILE: {filename}
LANGUAGE: {language}

FOCUS AREAS (CWE references):
- SQL Injection (CWE-89)
- Cross-Site Scripting XSS (CWE-79)
- Hardcoded Secrets/Credentials (CWE-798)
- Broken Authentication / Improper Auth (CWE-287)
- Command Injection (CWE-78)
- Path Traversal (CWE-22)
- XML External Entity XXE (CWE-611)
- Deserialization of Untrusted Data (CWE-502)
- Sensitive Data Exposure (CWE-311)
- Security Misconfiguration (CWE-16)

SEVERITY CLASSIFICATION:
- CRITICAL: exploitable remotely without authentication, direct data breach risk
- HIGH: significant risk, exploitable with minimal effort or auth
- MEDIUM: requires specific conditions or privileges to exploit
- LOW: defense-in-depth improvement, best practice violation

SOURCE CODE:
```
{truncated}
```

Return ONLY a valid JSON array. No markdown, no explanation, no text outside the array.
Each item must have exactly these fields:
- "type": vulnerability type name (string)
- "severity": one of CRITICAL, HIGH, MEDIUM, LOW (string)
- "line_number": approximate line number, 0 if unknown (integer)
- "description": what the vulnerability is and why it is dangerous (string, max 300 chars)
- "code_snippet": the vulnerable code fragment (string, max 200 chars)
- "suggestion": concrete actionable fix (string, max 300 chars)
- "cwe_id": CWE identifier e.g. "CWE-89" (string)

If no vulnerabilities are found, return exactly: []

Format: [{{"type": "", "severity": "", "line_number": 0, "description": "", "code_snippet": "", "suggestion": "", "cwe_id": ""}}]"""
