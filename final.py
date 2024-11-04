import ast
import re
from typing import List, Dict, Set, Tuple
from dataclasses import dataclass
from pathlib import Path
import astroid
from collections import Counter

@dataclass
class SecurityFinding:
    vulnerability_id: str
    title: str
    severity: str
    location: str
    description: str
    recommendation: str

class LLMSecurityAnalyzer:
    def __init__(self):
        self.findings: List[SecurityFinding] = []
        self.user_input_functions = {
            'input', 'raw_input', 'request.get', 'request.post',
            'stdin.readline', 'argv', 'getattr', 'eval', 'exec'
        }
        self.sensitive_patterns = [
            r'api[_-]?key',
            r'password',
            r'secret',
            r'token',
            r'credential',
            r'auth',
            r'private[_-]?key'
        ]
        self.trusted_packages = {
            'transformers', 'torch', 'tensorflow', 'keras', 
            'numpy', 'pandas', 'scikit-learn', 'spacy'
        }
        
    def _contains_user_input(self, node: ast.AST) -> bool:
        """Check if AST node contains user input"""
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id in self.user_input_functions:
                    return True
            elif isinstance(node.func, ast.Attribute):
                # Check for method calls like request.get
                full_name = f"{node.func.value.id}.{node.func.attr}"
                if full_name in self.user_input_functions:
                    return True
        
        # Check for string concatenation with potential user input
        if isinstance(node, ast.BinOp):
            if isinstance(node.left, ast.Call) or isinstance(node.right, ast.Call):
                return self._contains_user_input(node.left) or self._contains_user_input(node.right)
        
        return False

    def _has_output_validation(self, node: ast.AST) -> bool:
        """Check if output is properly validated"""
        validation_patterns = {
            'validate', 'sanitize', 'clean', 'filter', 'check',
            'verify', 'escape', 'encode', 'strip'
        }
        
        # Look for validation function calls
        if isinstance(node, ast.Call):
            parent = getattr(node, 'parent', None)
            while parent and not isinstance(parent, ast.FunctionDef):
                parent = getattr(parent, 'parent', None)
            
            if parent:
                # Check function body for validation calls
                for child in ast.walk(parent):
                    if isinstance(child, ast.Call):
                        if isinstance(child.func, ast.Name):
                            if any(pattern in child.func.id.lower() for pattern in validation_patterns):
                                return True
                        elif isinstance(child.func, ast.Attribute):
                            if any(pattern in child.func.attr.lower() for pattern in validation_patterns):
                                return True
        
        return False

    def _has_data_validation(self, node: ast.FunctionDef) -> bool:
        """Check for comprehensive data validation in training functions"""
        validation_checks = {
            'type_checking': False,
            'range_checking': False,
            'null_checking': False,
            'format_validation': False
        }
        
        for child in ast.walk(node):
            # Check for type checking
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    if child.func.id in {'isinstance', 'type'}:
                        validation_checks['type_checking'] = True
            
            # Check for range validation
            if isinstance(child, ast.Compare):
                if any(isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE)) for op in child.ops):
                    validation_checks['range_checking'] = True
            
            # Check for null checking
            if isinstance(child, ast.Compare):
                if any(isinstance(op, ast.Is) for op in child.ops):
                    if any(isinstance(comp, ast.Constant) and comp.value is None for comp in child.comparators):
                        validation_checks['null_checking'] = True
            
            # Check for format validation
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute):
                    if child.func.attr in {'match', 'search', 'findall'}:
                        validation_checks['format_validation'] = True
        
        return all(validation_checks.values())

    def _is_trusted_dependency(self, node: ast.AST) -> bool:
        """Verify if imported dependency is from trusted sources"""
        if isinstance(node, ast.Import):
            return all(name.name.split('.')[0] in self.trusted_packages for name in node.names)
        elif isinstance(node, ast.ImportFrom):
            return node.module.split('.')[0] in self.trusted_packages
        return False

    def _contains_sensitive_pattern(self, text: str) -> bool:
        """Detect potential sensitive information in string literals"""
        # First check for common sensitive patterns
        if any(re.search(pattern, text.lower()) for pattern in self.sensitive_patterns):
            return True
            
        # Check for potential hardcoded values
        if re.match(r'^[A-Za-z0-9+/]{32,}={0,2}$', text):  # Base64 pattern
            return True
            
        # Check for potential API keys
        if re.match(r'[a-zA-Z0-9_-]{32,}', text):
            return True
            
        # Check for potential JWT tokens
        if re.match(r'^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$', text):
            return True
            
        return False

    def _is_plugin_class(self, node: ast.ClassDef) -> bool:
        """Identify plugin implementations"""
        # Check class name
        if 'plugin' in node.name.lower():
            return True
            
        # Check base classes
        for base in node.bases:
            if isinstance(base, ast.Name):
                if 'plugin' in base.id.lower():
                    return True
                    
        # Check for plugin-related decorators
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name):
                if 'plugin' in decorator.id.lower():
                    return True
                    
        return False

    def _has_security_validation(self, node: ast.ClassDef) -> bool:
        """Check for security validation in plugin implementation"""
        security_checks = {
            'input_validation': False,
            'permission_check': False,
            'sandbox_check': False
        }
        
        for child in ast.walk(node):
            if isinstance(child, ast.FunctionDef):
                # Check for input validation
                for grandchild in ast.walk(child):
                    if isinstance(grandchild, ast.Call):
                        if isinstance(grandchild.func, ast.Name):
                            if any(pattern in grandchild.func.id.lower() 
                                 for pattern in ['validate', 'sanitize', 'clean']):
                                security_checks['input_validation'] = True
                                
                # Check for permission validation
                if any(pattern in child.name.lower() 
                      for pattern in ['permission', 'auth', 'access']):
                    security_checks['permission_check'] = True
                    
                # Check for sandbox implementation
                if any(pattern in child.name.lower() 
                      for pattern in ['sandbox', 'isolate', 'container']):
                    security_checks['sandbox_check'] = True
                    
        return all(security_checks.values())

    def _has_permission_checks(self, node: ast.FunctionDef) -> bool:
        """Verify implementation of permission checks"""
        permission_patterns = {
            'check_permission',
            'has_permission',
            'is_authorized',
            'can_access',
            'verify_access'
        }
        
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    if child.func.id in permission_patterns:
                        return True
                elif isinstance(child.func, ast.Attribute):
                    if child.func.attr in permission_patterns:
                        return True
                        
            # Check for role-based access control
            if isinstance(child, ast.Compare):
                if isinstance(child.left, ast.Name):
                    if 'role' in child.left.id.lower():
                        return True
                        
        return False

    def _has_confidence_scoring(self, node: ast.FunctionDef) -> bool:
        """Check for confidence score implementation"""
        confidence_indicators = {
            'score': False,
            'threshold': False,
            'comparison': False
        }
        
        for child in ast.walk(node):
            # Look for confidence score calculation
            if isinstance(child, ast.Assign):
                if isinstance(child.targets[0], ast.Name):
                    if 'confidence' in child.targets[0].id.lower():
                        confidence_indicators['score'] = True
                        
            # Look for threshold definition
            if isinstance(child, ast.Assign):
                if isinstance(child.targets[0], ast.Name):
                    if 'threshold' in child.targets[0].id.lower():
                        confidence_indicators['threshold'] = True
                        
            # Look for confidence comparison
            if isinstance(child, ast.Compare):
                if isinstance(child.left, ast.Name):
                    if 'confidence' in child.left.id.lower():
                        confidence_indicators['comparison'] = True
                        
        return all(confidence_indicators.values())

    def _has_fallback_mechanism(self, node: ast.FunctionDef) -> bool:
        """Verify implementation of fallback mechanisms"""
        has_try_except = False
        has_fallback_call = False
        
        for child in ast.walk(node):
            # Check for try-except blocks
            if isinstance(child, ast.Try):
                has_try_except = True
                
                # Check for fallback implementation in except handlers
                for handler in child.handlers:
                    for grandchild in ast.walk(handler):
                        if isinstance(grandchild, ast.Call):
                            if isinstance(grandchild.func, ast.Name):
                                if 'fallback' in grandchild.func.id.lower():
                                    has_fallback_call = True
                            elif isinstance(grandchild.func, ast.Attribute):
                                if 'fallback' in grandchild.func.attr.lower():
                                    has_fallback_call = True
                                    
        return has_try_except and has_fallback_call

    def _has_access_control(self, node: ast.FunctionDef) -> bool:
        """Check for access control implementation"""
        access_control_patterns = {
            'authentication': False,
            'authorization': False,
            'rate_limiting': False
        }
        
        for child in ast.walk(node):
            # Check for authentication
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    if any(pattern in child.func.id.lower() 
                          for pattern in ['authenticate', 'login', 'verify_token']):
                        access_control_patterns['authentication'] = True
                        
            # Check for authorization
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    if any(pattern in child.func.id.lower() 
                          for pattern in ['authorize', 'check_permission']):
                        access_control_patterns['authorization'] = True
                        
            # Check for rate limiting
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    if 'rate_limit' in child.func.id.lower():
                        access_control_patterns['rate_limiting'] = True
                        
        return all(access_control_patterns.values())

    def _has_rate_limiting(self, node: ast.FunctionDef) -> bool:
        """Verify implementation of rate limiting"""
        rate_limit_components = {
            'counter': False,
            'time_window': False,
            'limit_check': False
        }
        
        for child in ast.walk(node):
            # Check for counter implementation
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    if child.func.id in {'Counter', 'increment', 'count'}:
                        rate_limit_components['counter'] = True
                        
            # Check for time window
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute):
                    if child.func.attr in {'time', 'timestamp', 'datetime'}:
                        rate_limit_components['time_window'] = True
                        
            # Check for limit comparison
            if isinstance(child, ast.Compare):
                if isinstance(child.left, ast.Name):
                    if any(pattern in child.left.id.lower() 
                          for pattern in ['rate', 'limit', 'count']):
                        rate_limit_components['limit_check'] = True
                        
        return all(rate_limit_components.values())

    def analyze_source_code(self, source_code: str) -> List[SecurityFinding]:
        """Main method to analyze LLM source code for vulnerabilities"""
        self.findings = []
        
        try:
            # Parse the source code into an AST
            tree = ast.parse(source_code)
            
            # Run all security checks
            for node in ast.walk(tree):
                # LLM01: Prompt Injection
                if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                    if self._contains_user_input(node):
                        self.findings.append(SecurityFinding(
                            vulnerability_id="LLM01",
                            title="Potential Prompt Injection Vulnerability",
                            severity="HIGH",
                            location=f"Line {node.lineno}",
                            description="Direct string concatenation with user input detected",
                            recommendation="Implement input validation and sanitization"
                        ))
                
                # LLM02: Output Handling
                if isinstance(node, ast.Call):
                    if not self._has_output_validation(node):
                        self.findings.append(SecurityFinding(
                            vulnerability_id="LLM02",
                            title="Insecure Output Handling",
                            severity="MEDIUM",
                            location=f"Line {node.lineno}",
                            description="Model output used without validation",
                            recommendation="Implement output validation and sanitization"
                        ))
                
                # LLM03: Data Poisoning
                if isinstance(node, ast.FunctionDef):
                    if 'train' in node.name.lower():
                        if not self._has_data_validation(node):
                            self.findings.append(SecurityFinding(
                                vulnerability_id="LLM03",
                                title="Insufficient Training Data Validation",
                                severity="HIGH",
                                location=f"Line {node.lineno}",
                                description="Training function lacks comprehensive data validation",
                                recommendation="Implement data validation checks"
                            ))
                
                
                # LLM06: Sensitive Information
                if isinstance(node, ast.Str):
                    if self._contains_sensitive_pattern(node.s):
                        self.findings.append(SecurityFinding(
                            vulnerability_id="LLM06",
                            title="Potential Sensitive Information Disclosure",
                            severity="HIGH",
                            location=f"Line {node.lineno}",
                            description="Hardcoded sensitive information detected",
                            recommendation="Remove hardcoded sensitive data and use secure storage"
                        ))

                # LLM07: Plugin Security
                if isinstance(node, ast.ClassDef):
                    if self._is_plugin_class(node) and not self._has_security_validation(node):
                        self.findings.append(SecurityFinding(
                            vulnerability_id="LLM07",
                            title="Insecure Plugin Implementation",
                            severity="HIGH",
                            location=f"Line {node.lineno}",
                            description="Plugin lacks necessary security controls",
                            recommendation="Implement input validation, permission checks, and sandboxing"
                        ))

                # LLM08: Agency Controls
                if isinstance(node, ast.FunctionDef):
                    if not self._has_permission_checks(node):
                        # Check if function has LLM-related operations
                        has_llm_ops = any(
                            isinstance(child, ast.Call) and 
                            isinstance(child.func, ast.Name) and 
                            any(op in child.func.id.lower() for op in ['predict', 'generate', 'complete'])
                            for child in ast.walk(node)
                        )
                        if has_llm_ops:
                            self.findings.append(SecurityFinding(
                                vulnerability_id="LLM08",
                                title="Insufficient Agency Controls",
                                severity="MEDIUM",
                                location=f"Line {node.lineno}",
                                description="LLM operations lack proper permission checks",
                                recommendation="Implement permission checks and agency limitations"
                            ))

                # LLM09: Overreliance Prevention
                if isinstance(node, ast.FunctionDef):
                    has_llm_output = False
                    for child in ast.walk(node):
                        if isinstance(child, ast.Call):
                            if isinstance(child.func, ast.Name):
                                if any(op in child.func.id.lower() for op in ['predict', 'generate', 'complete']):
                                    has_llm_output = True
                                    break
                    
                    if has_llm_output:
                        if not (self._has_confidence_scoring(node) and self._has_fallback_mechanism(node)):
                            self.findings.append(SecurityFinding(
                                vulnerability_id="LLM09",
                                title="Insufficient Overreliance Prevention",
                                severity="MEDIUM",
                                location=f"Line {node.lineno}",
                                description="Missing confidence checks or fallback mechanisms",
                                recommendation="Implement confidence scoring and fallback mechanisms"
                            ))

                # LLM10: Model Theft Prevention
                if isinstance(node, ast.FunctionDef):
                    # Check if function exposes model functionality
                    exposes_model = any(
                        isinstance(child, ast.Call) and 
                        isinstance(child.func, ast.Name) and 
                        any(op in child.func.id.lower() for op in ['model', 'predict', 'inference'])
                        for child in ast.walk(node)
                    )
                    
                    if exposes_model and not (self._has_access_control(node) and self._has_rate_limiting(node)):
                        self.findings.append(SecurityFinding(
                            vulnerability_id="LLM10",
                            title="Insufficient Model Theft Prevention",
                            severity="HIGH",
                            location=f"Line {node.lineno}",
                            description="Missing access controls or rate limiting for model access",
                            recommendation="Implement access controls and rate limiting"
                        ))

            # Check for Supply Chain Vulnerabilities (LLM05)
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    if not self._is_trusted_dependency(node):
                        self.findings.append(SecurityFinding(
                            vulnerability_id="LLM05",
                            title="Potential Supply Chain Vulnerability",
                            severity="MEDIUM",
                            location=f"Line {node.lineno}",
                            description=f"Using potentially untrusted dependency",
                            recommendation="Verify and pin trusted dependencies"
                        ))

            # Check for Model DOS Prevention (LLM04)
            has_rate_limiting = False
            has_timeout = False
            has_resource_limit = False

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if 'rate_limit' in node.func.id.lower():
                            has_rate_limiting = True
                        elif 'timeout' in node.func.id.lower():
                            has_timeout = True
                elif isinstance(node, ast.Try):
                    for handler in node.handlers:
                        if isinstance(handler.type, ast.Name):
                            if handler.type.id in ['TimeoutError', 'ResourceExhaustedError']:
                                has_resource_limit = True

            if not (has_rate_limiting and has_timeout and has_resource_limit):
                self.findings.append(SecurityFinding(
                    vulnerability_id="LLM04",
                    title="Insufficient DOS Prevention",
                    severity="HIGH",
                    location="Global",
                    description="Missing rate limiting, timeout, or resource controls",
                    recommendation="Implement comprehensive DOS prevention measures"
                ))

        except SyntaxError as e:
            self.findings.append(SecurityFinding(
                vulnerability_id="PARSE_ERROR",
                title="Source Code Parse Error",
                severity="HIGH",
                location=f"Line {e.lineno}",
                description=f"Could not parse source code: {str(e)}",
                recommendation="Ensure valid Python syntax"
            ))
        
        return self.findings

def analyze_llm_security(source_code_path: str) -> None:
    """Analyze LLM source code for security vulnerabilities"""
    analyzer = LLMSecurityAnalyzer()
    
    try:
        # Read source code
        with open(source_code_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
        
        # Analyze code
        findings = analyzer.analyze_source_code(source_code)
        
        # Print findings
        if not findings:
            print("\nNo security vulnerabilities detected.")
        else:
            print(f"\nFound {len(findings)} potential security issues:")
            for finding in findings:
                print(f"\nVulnerability: {finding.vulnerability_id} - {finding.title}")
                print(f"Severity: {finding.severity}")
                print(f"Location: {finding.location}")
                print(f"Description: {finding.description}")
                print(f"Recommendation: {finding.recommendation}")
                print("-" * 80)
    
    except Exception as e:
        print(f"Error analyzing file: {str(e)}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python llm_security_analyzer.py <path_to_llm_source.py>")
        sys.exit(1)
    
    analyze_llm_security(sys.argv[1])
