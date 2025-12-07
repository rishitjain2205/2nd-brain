#!/usr/bin/env python3
"""
AUTOMATED SECURITY SCANNER
Scans code, configs, and files for security vulnerabilities

Run: python3 tests/security_scanner.py
"""

import os
import re
import sys
from pathlib import Path
from typing import List, Dict, Tuple
import json

# Colors for output
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BLUE = '\033[94m'
RESET = '\033[0m'


class SecurityIssue:
    """Represents a security issue found"""

    CRITICAL = 'CRITICAL'
    HIGH = 'HIGH'
    MEDIUM = 'MEDIUM'
    LOW = 'LOW'
    INFO = 'INFO'

    def __init__(self, severity, title, description, file_path=None, line_number=None, recommendation=None):
        self.severity = severity
        self.title = title
        self.description = description
        self.file_path = file_path
        self.line_number = line_number
        self.recommendation = recommendation

    def __str__(self):
        color = {
            'CRITICAL': RED,
            'HIGH': RED,
            'MEDIUM': YELLOW,
            'LOW': BLUE,
            'INFO': GREEN
        }.get(self.severity, RESET)

        output = f"{color}[{self.severity}]{RESET} {self.title}\n"
        output += f"  {self.description}\n"

        if self.file_path:
            location = f"{self.file_path}"
            if self.line_number:
                location += f":{self.line_number}"
            output += f"  Location: {location}\n"

        if self.recommendation:
            output += f"  Fix: {self.recommendation}\n"

        return output


class SecurityScanner:
    """Automated security scanner"""

    def __init__(self, project_root):
        self.project_root = Path(project_root)
        self.issues = []

    def scan_all(self):
        """Run all security scans"""
        print(f"{BLUE}Starting comprehensive security scan...{RESET}\n")

        self.scan_dangerous_functions()
        self.scan_hardcoded_secrets()
        self.scan_sql_patterns()
        self.scan_insecure_deserialization()
        self.scan_file_permissions()
        self.scan_environment_variables()
        self.scan_dependencies()
        self.scan_authentication()
        self.scan_crypto_usage()
        self.scan_input_validation()

        return self.issues

    def add_issue(self, issue: SecurityIssue):
        """Add a security issue to the list"""
        self.issues.append(issue)

    def scan_dangerous_functions(self):
        """Scan for dangerous function calls"""
        print("🔍 Scanning for dangerous functions...")

        dangerous_patterns = [
            (r'pickle\.loads?\(', 'Pickle deserialization', 'RCE vulnerability', SecurityIssue.CRITICAL),
            (r'eval\(', 'eval() usage', 'Code injection risk', SecurityIssue.CRITICAL),
            (r'exec\(', 'exec() usage', 'Code injection risk', SecurityIssue.CRITICAL),
            (r'os\.system\(', 'os.system() usage', 'Command injection risk', SecurityIssue.HIGH),
            (r'subprocess\.(call|Popen).*shell=True', 'Shell=True in subprocess', 'Command injection', SecurityIssue.HIGH),
            (r'__import__\(', 'Dynamic import', 'Potential code injection', SecurityIssue.MEDIUM),
        ]

        for py_file in self.project_root.rglob('*.py'):
            if 'test' in str(py_file) or 'venv' in str(py_file):
                continue

            try:
                content = py_file.read_text()
                lines = content.split('\n')

                for pattern, title, desc, severity in dangerous_patterns:
                    for i, line in enumerate(lines, 1):
                        if re.search(pattern, line) and not line.strip().startswith('#'):
                            self.add_issue(SecurityIssue(
                                severity,
                                title,
                                desc,
                                str(py_file.relative_to(self.project_root)),
                                i,
                                "Remove or replace with safe alternative"
                            ))
            except:
                pass

    def scan_hardcoded_secrets(self):
        """Scan for hardcoded secrets"""
        print("🔍 Scanning for hardcoded secrets...")

        secret_patterns = [
            (r'password\s*=\s*[\'"][^\'"]+[\'"]', 'Hardcoded password', SecurityIssue.CRITICAL),
            (r'api[_-]?key\s*=\s*[\'"][^\'"]{16,}[\'"]', 'Hardcoded API key', SecurityIssue.CRITICAL),
            (r'secret[_-]?key\s*=\s*[\'"][^\'"]+[\'"]', 'Hardcoded secret', SecurityIssue.CRITICAL),
            (r'token\s*=\s*[\'"][A-Za-z0-9_-]{20,}[\'"]', 'Hardcoded token', SecurityIssue.HIGH),
            (r'(aws|azure|gcp)[_-]?(key|secret)\s*=\s*[\'"][^\'"]+[\'"]', 'Cloud credentials', SecurityIssue.CRITICAL),
        ]

        for file_path in self.project_root.rglob('*.py'):
            if 'test' in str(file_path) or 'venv' in str(file_path) or '.env' in str(file_path):
                continue

            try:
                content = file_path.read_text().lower()
                lines = content.split('\n')

                for pattern, title, severity in secret_patterns:
                    for i, line in enumerate(lines, 1):
                        if re.search(pattern, line) and not line.strip().startswith('#'):
                            # Exclude test/example values
                            if 'example' not in line and 'test' not in line and 'your_' not in line:
                                self.add_issue(SecurityIssue(
                                    severity,
                                    title,
                                    "Hardcoded secret found in code",
                                    str(file_path.relative_to(self.project_root)),
                                    i,
                                    "Move to environment variable or secrets manager"
                                ))
            except:
                pass

    def scan_sql_patterns(self):
        """Scan for SQL injection vulnerabilities"""
        print("🔍 Scanning for SQL injection risks...")

        # Bad: String formatting in SQL
        bad_patterns = [
            r'execute\([\'"].*\{.*[\'"]\.format\(',
            r'execute\([\'"].*%s.*[\'"]%',
            r'execute\(f[\'"]',
            r'cursor\.execute\([\'"].*\+',
        ]

        for py_file in self.project_root.rglob('*.py'):
            if 'test' in str(py_file) or 'venv' in str(py_file):
                continue

            try:
                content = py_file.read_text()
                lines = content.split('\n')

                for pattern in bad_patterns:
                    for i, line in enumerate(lines, 1):
                        if re.search(pattern, line) and not line.strip().startswith('#'):
                            self.add_issue(SecurityIssue(
                                SecurityIssue.CRITICAL,
                                "SQL Injection Risk",
                                "SQL query uses string formatting instead of parameterization",
                                str(py_file.relative_to(self.project_root)),
                                i,
                                "Use parameterized queries: execute('SELECT * FROM users WHERE id = ?', (user_id,))"
                            ))
            except:
                pass

    def scan_insecure_deserialization(self):
        """Scan for insecure deserialization"""
        print("🔍 Scanning for insecure deserialization...")

        patterns = [
            (r'pickle\.loads?\(', 'Pickle deserialization'),
            (r'yaml\.load\((?!.*Loader=yaml\.SafeLoader)', 'Unsafe YAML load'),
            (r'marshal\.loads?\(', 'Marshal deserialization'),
        ]

        for py_file in self.project_root.rglob('*.py'):
            if 'test' in str(py_file) or 'venv' in str(py_file):
                continue

            try:
                content = py_file.read_text()
                lines = content.split('\n')

                for pattern, title in patterns:
                    for i, line in enumerate(lines, 1):
                        if re.search(pattern, line) and not line.strip().startswith('#'):
                            self.add_issue(SecurityIssue(
                                SecurityIssue.CRITICAL,
                                f"Insecure Deserialization: {title}",
                                "Can lead to remote code execution",
                                str(py_file.relative_to(self.project_root)),
                                i,
                                "Use JSON or safe serialization format"
                            ))
            except:
                pass

    def scan_file_permissions(self):
        """Scan file permissions on sensitive files"""
        print("🔍 Scanning file permissions...")

        sensitive_patterns = ['*.key', '*.pem', '*.p12', '*.pfx', '.env*', '*secret*', '*password*']

        for pattern in sensitive_patterns:
            for file_path in self.project_root.rglob(pattern):
                if file_path.is_file():
                    try:
                        mode = file_path.stat().st_mode & 0o777

                        if mode & 0o077:  # Others or group have any permissions
                            self.add_issue(SecurityIssue(
                                SecurityIssue.HIGH,
                                "Insecure File Permissions",
                                f"File has permissions {oct(mode)}, should be 0o600",
                                str(file_path.relative_to(self.project_root)),
                                None,
                                f"Run: chmod 600 {file_path}"
                            ))
                    except:
                        pass

    def scan_environment_variables(self):
        """Check environment variable usage"""
        print("🔍 Scanning environment variable usage...")

        # Check if .env file exists and is in .gitignore
        env_file = self.project_root / '.env'
        gitignore = self.project_root / '.gitignore'

        if env_file.exists():
            if gitignore.exists():
                gitignore_content = gitignore.read_text()
                if '.env' not in gitignore_content:
                    self.add_issue(SecurityIssue(
                        SecurityIssue.CRITICAL,
                        ".env Not in .gitignore",
                        ".env file exists but not ignored by git",
                        ".gitignore",
                        None,
                        "Add .env to .gitignore immediately"
                    ))
            else:
                self.add_issue(SecurityIssue(
                    SecurityIssue.HIGH,
                    "Missing .gitignore",
                    ".gitignore file not found",
                    None,
                    None,
                    "Create .gitignore and add .env to it"
                ))

    def scan_dependencies(self):
        """Scan for known vulnerable dependencies"""
        print("🔍 Scanning dependencies...")

        requirements_files = list(self.project_root.glob('requirements*.txt'))

        if not requirements_files:
            self.add_issue(SecurityIssue(
                SecurityIssue.INFO,
                "No requirements.txt found",
                "Cannot check for vulnerable dependencies",
                None,
                None,
                "Create requirements.txt with: pip freeze > requirements.txt"
            ))
            return

        # Known vulnerable packages (examples)
        vulnerable_patterns = [
            (r'pyyaml\s*<\s*5\.4', 'PyYAML <5.4', 'YAML deserialization vulnerability'),
            (r'flask\s*<\s*2\.2', 'Flask <2.2', 'Multiple security fixes'),
            (r'requests\s*<\s*2\.31', 'Requests <2.31', 'SSRF and cert validation issues'),
        ]

        for req_file in requirements_files:
            try:
                content = req_file.read_text().lower()

                for pattern, pkg, vuln in vulnerable_patterns:
                    if re.search(pattern, content):
                        self.add_issue(SecurityIssue(
                            SecurityIssue.HIGH,
                            f"Vulnerable Dependency: {pkg}",
                            vuln,
                            str(req_file.relative_to(self.project_root)),
                            None,
                            f"Update {pkg} to latest version"
                        ))
            except:
                pass

    def scan_authentication(self):
        """Scan authentication implementation"""
        print("🔍 Scanning authentication...")

        # Check for JWT usage
        jwt_found = False
        for py_file in self.project_root.rglob('*.py'):
            try:
                content = py_file.read_text()
                if 'import jwt' in content or 'from jose import jwt' in content:
                    jwt_found = True
                    break
            except:
                pass

        if not jwt_found:
            self.add_issue(SecurityIssue(
                SecurityIssue.INFO,
                "JWT Not Detected",
                "No JWT authentication found",
                None,
                None,
                "Consider implementing JWT for API authentication"
            ))

    def scan_crypto_usage(self):
        """Scan cryptography usage"""
        print("🔍 Scanning cryptography usage...")

        weak_patterns = [
            (r'hashlib\.(md5|sha1)\(', 'Weak Hash Algorithm', 'MD5/SHA1 are deprecated', SecurityIssue.MEDIUM),
            (r'random\.random\(', 'Weak Random', 'Not cryptographically secure', SecurityIssue.MEDIUM),
            (r'Cipher\.new.*MODE_ECB', 'ECB Mode', 'Insecure encryption mode', SecurityIssue.HIGH),
        ]

        for py_file in self.project_root.rglob('*.py'):
            if 'test' in str(py_file) or 'venv' in str(py_file):
                continue

            try:
                content = py_file.read_text()
                lines = content.split('\n')

                for pattern, title, desc, severity in weak_patterns:
                    for i, line in enumerate(lines, 1):
                        if re.search(pattern, line) and not line.strip().startswith('#'):
                            self.add_issue(SecurityIssue(
                                severity,
                                title,
                                desc,
                                str(py_file.relative_to(self.project_root)),
                                i,
                                "Use secrets module for random, SHA256+ for hashing, CBC/GCM for encryption"
                            ))
            except:
                pass

    def scan_input_validation(self):
        """Check for input validation"""
        print("🔍 Scanning input validation...")

        # Check if InputValidator is used in Flask routes
        app_files = list(self.project_root.glob('app*.py'))

        for app_file in app_files:
            try:
                content = app_file.read_text()

                # Check if request.get_json() is used without validation
                if 'request.get_json()' in content:
                    if 'InputValidator' not in content and 'sanitize' not in content:
                        self.add_issue(SecurityIssue(
                            SecurityIssue.MEDIUM,
                            "Missing Input Validation",
                            "Flask routes use request.get_json() without validation",
                            str(app_file.relative_to(self.project_root)),
                            None,
                            "Use InputValidator to sanitize all user input"
                        ))
            except:
                pass

    def generate_report(self):
        """Generate security scan report"""
        print("\n" + "="*80)
        print(f"{BLUE}SECURITY SCAN REPORT{RESET}")
        print("="*80 + "\n")

        # Count by severity
        counts = {
            SecurityIssue.CRITICAL: 0,
            SecurityIssue.HIGH: 0,
            SecurityIssue.MEDIUM: 0,
            SecurityIssue.LOW: 0,
            SecurityIssue.INFO: 0,
        }

        for issue in self.issues:
            counts[issue.severity] += 1

        # Summary
        print(f"Total issues found: {len(self.issues)}\n")
        print(f"{RED}CRITICAL: {counts[SecurityIssue.CRITICAL]}{RESET}")
        print(f"{RED}HIGH:     {counts[SecurityIssue.HIGH]}{RESET}")
        print(f"{YELLOW}MEDIUM:   {counts[SecurityIssue.MEDIUM]}{RESET}")
        print(f"{BLUE}LOW:      {counts[SecurityIssue.LOW]}{RESET}")
        print(f"{GREEN}INFO:     {counts[SecurityIssue.INFO]}{RESET}")
        print()

        # Group issues by severity
        for severity in [SecurityIssue.CRITICAL, SecurityIssue.HIGH, SecurityIssue.MEDIUM,
                        SecurityIssue.LOW, SecurityIssue.INFO]:
            severity_issues = [i for i in self.issues if i.severity == severity]

            if severity_issues:
                print("="*80)
                print(f"{severity} ISSUES ({len(severity_issues)})")
                print("="*80 + "\n")

                for issue in severity_issues:
                    print(issue)

        # Final assessment
        print("="*80)
        if counts[SecurityIssue.CRITICAL] > 0 or counts[SecurityIssue.HIGH] > 0:
            print(f"{RED}🚨 CRITICAL ISSUES FOUND - DO NOT DEPLOY TO PRODUCTION!{RESET}")
            return 1
        elif counts[SecurityIssue.MEDIUM] > 0:
            print(f"{YELLOW}⚠️  Medium severity issues found - Review before production{RESET}")
            return 0
        else:
            print(f"{GREEN}✅ No critical security issues found!{RESET}")
            return 0


def main():
    """Run security scanner"""
    project_root = Path(__file__).parent.parent

    print("="*80)
    print(f"{BLUE}🔒 AUTOMATED SECURITY SCANNER{RESET}")
    print("2nd Brain Application")
    print("="*80 + "\n")

    scanner = SecurityScanner(project_root)
    scanner.scan_all()
    exit_code = scanner.generate_report()

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
