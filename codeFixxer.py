import google.generativeai as genai
import os

# Set up the API key
genai.configure(api_key=os.environ.get("GOOGLE_API_KEY"))

class VulnerabilityFixer:
    def __init__(self):
        self.model = genai.GenerativeModel('gemini-pro')

    def generate_fix(self, vulnerability_id, title, description, recommendation, original_code):
        prompt = self._create_prompt(vulnerability_id, title, description, recommendation, original_code)
        response = self.model.generate_content(prompt)
        return response.text

    def _create_prompt(self, vulnerability_id, title, description, recommendation, original_code):
        return f"""
        As a secure coding expert specializing in LLM applications, fix the following code to address the {vulnerability_id} vulnerability:

        Vulnerability: {title}
        Description: {description}
        Recommendation: {recommendation}

        Original code:
        ```python
        {original_code}
        ```

        Please provide only the fixed code snippet, without explanations. Ensure that the fix addresses the specific vulnerability described.

        Fixed code:
        """

def extract_code_snippet(file_path, start_line, context_lines=5):
    with open(file_path, 'r') as file:
        lines = file.readlines()
    
    start = max(0, start_line - context_lines - 1)
    end = min(len(lines), start_line + context_lines)
    
    return ''.join(lines[start:end])

def main(file_path, vulnerabilities):
    fixer = VulnerabilityFixer()

    for vuln in vulnerabilities:
        code_snippet = extract_code_snippet(file_path, vuln['location'])
        fixed_code = fixer.generate_fix(
            vuln['vulnerability_id'],
            vuln['title'],
            vuln['description'],
            vuln['recommendation'],
            code_snippet
        )

        print(f"\nFixed code for {vuln['vulnerability_id']} vulnerability:")
        print(fixed_code)
        print("-" * 80)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python vulnerability_fixer.py <path_to_vulnerable_code.py>")
        sys.exit(1)
    
    vulnerabilities = [
        {
            "vulnerability_id": "LLM01",
            "title": "Potential Prompt Injection Vulnerability",
            "severity": "HIGH",
            "location": 0,  # Update with actual line number
            "description": "Direct string concatenation with user input detected",
            "recommendation": "Implement input validation and sanitization"
        },
        {
            "vulnerability_id": "LLM02",
            "title": "Insecure Output Handling",
            "severity": "MEDIUM",
            "location": 0,  # Update with actual line number
            "description": "Model output used without validation",
            "recommendation": "Implement output validation and sanitization"
        },
        {
            "vulnerability_id": "LLM03",
            "title": "Insufficient Training Data Validation",
            "severity": "HIGH",
            "location": 0,  # Update with actual line number
            "description": "Training function lacks comprehensive data validation",
            "recommendation": "Implement data validation checks"
        },
        {
            "vulnerability_id": "LLM04",
            "title": "Insufficient DOS Prevention",
            "severity": "HIGH",
            "location": 0,  # Update with actual line number
            "description": "Missing rate limiting, timeout, or resource controls",
            "recommendation": "Implement comprehensive DOS prevention measures"
        },
        {
            "vulnerability_id": "LLM05",
            "title": "Potential Supply Chain Vulnerability",
            "severity": "MEDIUM",
            "location": 0,  # Update with actual line number
            "description": "Using potentially untrusted dependency ",
            "recommendation": "Verify and pin trusted dependencies"
        },
        {
            "vulnerability_id": "LLM06",
            "title": "Potential Sensitive Information Disclosure",
            "severity": "HIGH",
            "location": 0,  # Update with actual line number
            "description": "Hardcoded sensitive information detected",
            "recommendation": "Remove hardcoded sensitive data and use secure storage"
        },
        {
            "vulnerability_id": "LLM07",
            "title": "Insecure Plugin Implementation",
            "severity": "HIGH",
            "location": 0,  # Update with actual line number
            "description": "Plugin lacks necessary security controls",
            "recommendation": "Implement input validation, permission checks, and sandboxing"
        },
        {
            "vulnerability_id": "LLM08",
            "title": "Insufficient Agency Controls",
            "severity": "MEDIUM",
            "location": 0,  # Update with actual line number
            "description": "LLM operations lack proper permission checks",
            "recommendation": "Implement permission checks and agency limitations"
        },
        {
            "vulnerability_id": "LLM09",
            "title": "Insufficient Overreliance Prevention",
            "severity": "MEDIUM",
            "location": 0,  # Update with actual line number
            "description": "Missing confidence checks or fallback mechanisms",
            "recommendation": "Implement confidence scoring and fallback mechanisms"
        },
        {
            "vulnerability_id": "LLM10",
            "title": "Insufficient Model Theft Prevention",
            "severity": "HIGH",
            "location": 0,  # Update with actual line number
            "description": "Missing access controls or rate limiting for model access",
            "recommendation": "Implement access controls and rate limiting"
        }
    ]
    
    main(sys.argv[1], vulnerabilities)
