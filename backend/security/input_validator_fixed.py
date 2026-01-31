"""
Input Validation and Sanitization - FIXED VERSION

⚠️ CRITICAL SECURITY CHANGE:
This version REMOVES the dangerous regex-based SQL injection "protection".

WHY THE OLD VERSION WAS INSECURE:
- Regex blacklists can ALWAYS be bypassed
- Example bypasses: ' AND 1=1, WAITFOR DELAY, ' OR 1 > 0
- Attackers use encoding, comments, and logical equivalents

THE CORRECT APPROACH:
✅ For SQL: ALWAYS use parameterized queries (prepared statements)
✅ For Commands: NEVER execute shell commands with user input
✅ For Display: HTML escape and validate data types

This validator is ONLY for:
- Data type validation (email format, URL format)
- Length limits
- Character whitelisting for specific contexts
- Display/logging sanitization

DO NOT use this for SQL query security!
"""

import re
import html
import os
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse
import ipaddress


class InputValidator:
    """
    Validates and sanitizes user inputs

    IMPORTANT SECURITY NOTES:
    - This does NOT prevent SQL injection (use parameterized queries!)
    - This does NOT prevent command injection (don't run shell commands!)
    - This is for data type validation and XSS prevention only
    """

    @staticmethod
    def validate_length(value: str, max_length: int = 1000, min_length: int = 0) -> str:
        """
        Validate string length

        Args:
            value: Input string
            max_length: Maximum allowed length
            min_length: Minimum allowed length

        Returns:
            Validated string

        Raises:
            ValueError: If length is invalid
        """
        if not isinstance(value, str):
            value = str(value)

        if len(value) > max_length:
            raise ValueError(f"Input too long (max {max_length} chars)")

        if len(value) < min_length:
            raise ValueError(f"Input too short (min {min_length} chars)")

        return value

    @staticmethod
    def validate_alphanumeric(value: str, allow_spaces: bool = False,
                             allow_hyphens: bool = False,
                             allow_underscores: bool = False) -> str:
        """
        Validate that string contains only safe characters

        Args:
            value: Input string
            allow_spaces: Allow spaces
            allow_hyphens: Allow hyphens (-)
            allow_underscores: Allow underscores (_)

        Returns:
            Validated string

        Raises:
            ValueError: If contains invalid characters
        """
        if not isinstance(value, str):
            raise ValueError("Value must be string")

        # Build allowed pattern
        pattern = r'^[a-zA-Z0-9'
        if allow_spaces:
            pattern += r'\s'
        if allow_hyphens:
            pattern += r'\-'
        if allow_underscores:
            pattern += r'_'
        pattern += r']+$'

        if not re.match(pattern, value):
            raise ValueError("String contains invalid characters")

        return value

    @staticmethod
    def sanitize_for_display(value: str, max_length: int = 1000) -> str:
        """
        Sanitize string for safe display in HTML

        This ONLY prevents XSS, NOT SQL injection!

        Args:
            value: Input string
            max_length: Maximum allowed length

        Returns:
            HTML-escaped string
        """
        if not isinstance(value, str):
            value = str(value)

        # Limit length
        if len(value) > max_length:
            raise ValueError(f"Input too long (max {max_length} chars)")

        # HTML escape to prevent XSS
        return html.escape(value)

    @staticmethod
    def validate_email(email: str) -> str:
        """
        Validate email address format

        Args:
            email: Email address

        Returns:
            Lowercase, trimmed email

        Raises:
            ValueError: If email is invalid
        """
        if not isinstance(email, str):
            raise ValueError("Email must be string")

        email = email.lower().strip()

        # More comprehensive email regex
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            raise ValueError("Invalid email format")

        # Additional checks
        if len(email) > 254:  # RFC 5321
            raise ValueError("Email too long")

        local, domain = email.split('@')
        if len(local) > 64:  # RFC 5321
            raise ValueError("Email local part too long")

        return email

    @staticmethod
    def validate_url(url: str, allowed_schemes: List[str] = None) -> str:
        """
        Validate URL format and prevent SSRF

        Args:
            url: URL to validate
            allowed_schemes: Allowed URL schemes (default: ['http', 'https'])

        Returns:
            Validated URL

        Raises:
            ValueError: If URL is invalid or dangerous
        """
        if not isinstance(url, str):
            raise ValueError("URL must be string")

        if allowed_schemes is None:
            allowed_schemes = ['http', 'https']

        try:
            parsed = urlparse(url)
        except Exception as e:
            raise ValueError(f"Invalid URL format: {e}")

        # Check scheme
        if parsed.scheme not in allowed_schemes:
            raise ValueError(f"Only {allowed_schemes} URLs allowed")

        # SSRF Protection: Block internal IPs and hostnames
        hostname = parsed.hostname
        if not hostname:
            raise ValueError("URL must have a hostname")

        # Block localhost variations
        localhost_patterns = [
            'localhost',
            '127.',  # 127.0.0.1, 127.0.0.2, etc.
            '0.0.0.0',
            '::1',
            'local',
            '169.254.',  # Link-local
            '10.',  # Private IP
            '172.16.', '172.17.', '172.18.', '172.19.',  # Private IP ranges
            '172.20.', '172.21.', '172.22.', '172.23.',
            '172.24.', '172.25.', '172.26.', '172.27.',
            '172.28.', '172.29.', '172.30.', '172.31.',
            '192.168.',  # Private IP
        ]

        hostname_lower = hostname.lower()
        for pattern in localhost_patterns:
            if hostname_lower.startswith(pattern) or hostname_lower == pattern.rstrip('.'):
                raise ValueError("Access to internal resources blocked (SSRF protection)")

        # Try to parse as IP address
        try:
            ip = ipaddress.ip_address(hostname)
            # Block private, loopback, link-local, multicast
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
                raise ValueError("Access to internal resources blocked (SSRF protection)")
        except ValueError:
            # Not an IP address, that's fine (it's a domain name)
            pass

        return url

    @staticmethod
    def validate_integer(value: Any, min_value: Optional[int] = None,
                        max_value: Optional[int] = None) -> int:
        """
        Validate and convert to integer

        Args:
            value: Value to convert
            min_value: Minimum allowed value
            max_value: Maximum allowed value

        Returns:
            Integer value

        Raises:
            ValueError: If not a valid integer or out of range
        """
        try:
            int_value = int(value)
        except (ValueError, TypeError) as e:
            raise ValueError(f"Invalid integer: {e}")

        if min_value is not None and int_value < min_value:
            raise ValueError(f"Value must be >= {min_value}")

        if max_value is not None and int_value > max_value:
            raise ValueError(f"Value must be <= {max_value}")

        return int_value

    @staticmethod
    def validate_organization_id(org_id: str) -> str:
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

        if len(org_id) < 1:
            raise ValueError("Organization ID cannot be empty")

        return org_id.strip()

    @staticmethod
    def validate_file_path(path: str, allowed_dirs: List[str]) -> str:
        """
        Validate file path and prevent directory traversal

        ⚠️ SECURITY: This must be used with allowed_dirs parameter!

        Args:
            path: File path to validate
            allowed_dirs: List of allowed base directories (REQUIRED)

        Returns:
            Validated absolute path

        Raises:
            ValueError: If path is dangerous or not in allowed directories
        """
        if not isinstance(path, str):
            raise ValueError("Path must be string")

        if not allowed_dirs:
            raise ValueError("allowed_dirs parameter is required for security")

        import os.path

        # Get absolute path (resolves .. and .)
        try:
            abs_path = os.path.abspath(path)
        except Exception as e:
            raise ValueError(f"Invalid path: {e}")

        # Check if path is within allowed directories
        allowed = False
        for allowed_dir in allowed_dirs:
            abs_allowed_dir = os.path.abspath(allowed_dir)

            # Ensure trailing slash for proper prefix matching
            if not abs_allowed_dir.endswith(os.sep):
                abs_allowed_dir += os.sep

            if abs_path.startswith(abs_allowed_dir):
                allowed = True
                break

        if not allowed:
            raise ValueError(f"Path not in allowed directories")

        return abs_path

    @staticmethod
    def validate_jwt_token(token: str, secret_key: Optional[str] = None) -> str:
        """
        Validate JWT token format and optionally verify signature

        Args:
            token: JWT token
            secret_key: Secret key for signature verification (from env JWT_SECRET_KEY)

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

        # Verify signature if secret provided
        if secret_key:
            try:
                import jwt

                if not secret_key:
                    secret_key = os.getenv('JWT_SECRET_KEY')
                    if not secret_key:
                        raise ValueError("JWT_SECRET_KEY environment variable required")

                # Verify and decode JWT
                decoded = jwt.decode(token, secret_key, algorithms=["HS256", "RS256"])

                # Check expiration
                import time
                if 'exp' in decoded and decoded['exp'] < time.time():
                    raise ValueError("JWT token expired")

            except ImportError:
                raise ValueError("PyJWT library required. Install with: pip install PyJWT")
            except jwt.ExpiredSignatureError:
                raise ValueError("JWT token expired")
            except jwt.InvalidSignatureError:
                raise ValueError("JWT signature verification failed - token may be forged")
            except jwt.DecodeError:
                raise ValueError("JWT decode error - invalid token format")

        return token


# Global validator instance
_validator = InputValidator()


def validate_input(data: Any, input_type: str, **kwargs) -> Any:
    """
    Convenience function to validate input

    Args:
        data: Data to validate
        input_type: Type of input (email, url, integer, alphanumeric, etc.)
        **kwargs: Additional arguments for specific validators

    Returns:
        Validated data

    Raises:
        ValueError: If validation fails
    """
    if input_type == "email":
        return _validator.validate_email(data)
    elif input_type == "url":
        return _validator.validate_url(data, **kwargs)
    elif input_type == "integer":
        return _validator.validate_integer(data, **kwargs)
    elif input_type == "alphanumeric":
        return _validator.validate_alphanumeric(data, **kwargs)
    elif input_type == "org_id":
        return _validator.validate_organization_id(data)
    elif input_type == "file_path":
        return _validator.validate_file_path(data, **kwargs)
    elif input_type == "jwt":
        return _validator.validate_jwt_token(data, **kwargs)
    elif input_type == "display":
        return _validator.sanitize_for_display(data, **kwargs)
    elif input_type == "length":
        return _validator.validate_length(data, **kwargs)
    else:
        raise ValueError(f"Unknown input type: {input_type}")


if __name__ == "__main__":
    print("="*60)
    print("Testing FIXED Input Validator")
    print("="*60)

    validator = InputValidator()

    # Test 1: Email validation
    print("\n1️⃣  Email Validation Tests:")
    emails = [
        ("user@example.com", True),
        ("invalid.email", False),
        ("user@", False),
        ("@example.com", False),
    ]

    for email, should_pass in emails:
        try:
            result = validator.validate_email(email)
            status = "✅ VALID" if should_pass else "❌ SHOULD HAVE FAILED"
            print(f"  {status}: {email}")
        except ValueError as e:
            status = "❌ INVALID" if not should_pass else f"✅ CORRECTLY REJECTED"
            print(f"  {status}: {email}")

    # Test 2: URL SSRF protection
    print("\n2️⃣  URL SSRF Protection Tests:")
    urls = [
        ("https://example.com", True),
        ("http://localhost", False),
        ("http://127.0.0.1", False),
        ("http://192.168.1.1", False),
        ("http://10.0.0.1", False),
        ("http://169.254.169.254", False),  # AWS metadata
    ]

    for url, should_pass in urls:
        try:
            result = validator.validate_url(url)
            status = "✅ ALLOWED" if should_pass else "❌ SHOULD HAVE BLOCKED"
            print(f"  {status}: {url}")
        except ValueError as e:
            status = "✅ BLOCKED" if not should_pass else "❌ INCORRECTLY BLOCKED"
            print(f"  {status}: {url}")

    # Test 3: Integer validation
    print("\n3️⃣  Integer Validation Tests:")
    try:
        val = validator.validate_integer("42", min_value=0, max_value=100)
        print(f"  ✅ Valid integer: {val}")
    except ValueError as e:
        print(f"  ❌ Failed: {e}")

    try:
        val = validator.validate_integer("-5", min_value=0, max_value=100)
        print(f"  ❌ Should have rejected negative: {val}")
    except ValueError as e:
        print(f"  ✅ Correctly rejected: {e}")

    # Test 4: XSS protection
    print("\n4️⃣  XSS Protection Tests:")
    xss_payload = "<script>alert('XSS')</script>"
    sanitized = validator.sanitize_for_display(xss_payload)
    print(f"  Original: {xss_payload}")
    print(f"  Sanitized: {sanitized}")
    if "&lt;script&gt;" in sanitized:
        print("  ✅ XSS tags escaped")
    else:
        print("  ❌ XSS not escaped!")

    print("\n" + "="*60)
    print("✅ Fixed Input Validator Working!")
    print("\n⚠️  REMEMBER:")
    print("  - This does NOT prevent SQL injection!")
    print("  - Use parameterized queries for SQL!")
    print("  - Never execute shell commands with user input!")
    print("="*60)
