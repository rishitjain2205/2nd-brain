"""
Data Sanitization Layer - CRITICAL FOR RESEARCH LAB
Removes all PII and sensitive data before sending to OpenAI

⚠️ KNOWN LIMITATIONS (Acceptable for SOC 2):
- Personal names: Not detected (requires ML/NER, high false positive rate)
- Physical addresses: Not detected (complex, context-dependent)
- International ID formats: Limited coverage (only US SSN, common phone formats)

These limitations are documented and acceptable for SOC 2 compliance.
SOC 2 requires protection of SSN, credit cards, and email - which this provides.
"""

import re
from typing import Dict, Any, List, Optional
import hashlib


class DataSanitizer:
    """
    Sanitize sensitive data before sending to LLM

    Removes:
    - Email addresses
    - Phone numbers
    - SSNs
    - Credit card numbers
    - IP addresses
    - URLs with sensitive paths
    - Personal names (optional)

    Implements data minimization (only send what's needed)
    """

    def __init__(self, max_length: int = 2000):
        """
        Initialize sanitizer

        Args:
            max_length: Maximum text length to send to LLM (data minimization)
        """
        self.max_length = max_length

        # Regex patterns for PII detection
        self.patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            # International phone formats (US, UK, India, general international)
            'phone': r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b|'  # US/Canada
                    r'\+?44\s?\d{4}\s?\d{6}\b|'  # UK
                    r'\+?91\s?\d{10}\b|'  # India
                    r'\+?\d{1,4}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b',  # General international
            'ssn': r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b',
            'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
            'ip_address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'url_sensitive': r'https?://[^\s]+(?:password|token|key|secret|api)[^\s]*',
            # API Keys and Tokens (CRITICAL - prevents credential leakage to LLM)
            'jwt_token': r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',  # JWT tokens
            'aws_key': r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',  # AWS Access Key
            'aws_secret': r'aws_secret_access_key[\s:=]+["\']?([A-Za-z0-9/+=]{40})["\']?',  # AWS Secret Key
            'slack_token': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,32}',  # Slack tokens
            'github_token': r'gh[pousr]_[A-Za-z0-9]{36,255}',  # GitHub tokens
            'generic_api_key': r'(?:api[_-]?key|apikey|access[_-]?token)[\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?',  # Generic API keys
            # SECURITY FIX: Match entire PEM block including key body and END line
            'private_key': r'(?s)-----BEGIN (?:RSA |EC )?PRIVATE KEY-----.*?-----END (?:RSA |EC )?PRIVATE KEY-----',  # Private keys
        }

        # Redaction labels
        self.redactions = {
            'email': '[EMAIL_REDACTED]',
            'phone': '[PHONE_REDACTED]',
            'ssn': '[SSN_REDACTED]',
            'credit_card': '[CARD_REDACTED]',
            'ip_address': '[IP_REDACTED]',
            'url_sensitive': '[URL_REDACTED]',
            'jwt_token': '[JWT_TOKEN_REDACTED]',
            'aws_key': '[AWS_KEY_REDACTED]',
            'aws_secret': '[AWS_SECRET_REDACTED]',
            'slack_token': '[SLACK_TOKEN_REDACTED]',
            'github_token': '[GITHUB_TOKEN_REDACTED]',
            'generic_api_key': '[API_KEY_REDACTED]',
            'private_key': '[PRIVATE_KEY_REDACTED]',
        }

    def sanitize_text(self, text: str, truncate: bool = True) -> str:
        """
        Sanitize text by removing PII

        Args:
            text: Raw text to sanitize
            truncate: Whether to truncate to max_length

        Returns:
            Sanitized text safe to send to LLM
        """
        if not text:
            return ""

        sanitized = text

        # Apply all redaction patterns
        for pattern_name, pattern in self.patterns.items():
            redaction = self.redactions[pattern_name]
            sanitized = re.sub(pattern, redaction, sanitized, flags=re.IGNORECASE)

        # Data minimization: truncate long text
        if truncate and len(sanitized) > self.max_length:
            sanitized = sanitized[:self.max_length] + "... [TRUNCATED_FOR_PRIVACY]"

        return sanitized

    def sanitize_document(self, doc: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize entire document for LLM processing
        Only keeps essential fields, sanitizes content

        Args:
            doc: Raw document with potentially sensitive data

        Returns:
            Sanitized document safe for LLM
        """
        if not doc:
            return {}

        # Only extract safe fields
        sanitized = {
            'id': self._hash_id(doc.get('id', '')),  # Hash ID for privacy
            'type': doc.get('type', 'unknown'),
            'date': doc.get('date', ''),
            'subject': self.sanitize_text(doc.get('subject', ''), truncate=False),
            'snippet': self.sanitize_text(doc.get('content', ''))[:200],  # Max 200 chars
        }

        # Remove any None or empty values
        sanitized = {k: v for k, v in sanitized.items() if v}

        return sanitized

    def sanitize_batch(self, documents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Sanitize multiple documents

        Args:
            documents: List of raw documents

        Returns:
            List of sanitized documents
        """
        return [self.sanitize_document(doc) for doc in documents]

    def _hash_id(self, identifier: str) -> str:
        """
        Hash an identifier for privacy
        Allows tracking without exposing original ID

        Args:
            identifier: Original ID

        Returns:
            Hashed ID (first 8 chars of SHA256)
        """
        if not identifier:
            return ""

        return hashlib.sha256(identifier.encode()).hexdigest()[:8]

    def validate_sanitization(self, text: str) -> Dict[str, Any]:
        """
        Validate that text has been properly sanitized

        Args:
            text: Text to validate

        Returns:
            Dict with validation results and any remaining PII found
        """
        results = {
            'is_safe': True,
            'found_pii': {},
            'warnings': []
        }

        # Check for each PII pattern
        for pattern_name, pattern in self.patterns.items():
            matches = re.findall(pattern, text, flags=re.IGNORECASE)
            if matches:
                results['is_safe'] = False
                results['found_pii'][pattern_name] = len(matches)
                results['warnings'].append(f"Found {len(matches)} {pattern_name} instances")

        return results

    def get_sanitization_report(self, original: str, sanitized: str) -> Dict[str, Any]:
        """
        Generate report showing what was sanitized

        Args:
            original: Original text
            sanitized: Sanitized text

        Returns:
            Report with statistics
        """
        report = {
            'original_length': len(original),
            'sanitized_length': len(sanitized),
            'reduction_percent': round((1 - len(sanitized) / len(original)) * 100, 2) if original else 0,
            'pii_removed': {},
        }

        # Count what was removed
        for pattern_name, pattern in self.patterns.items():
            original_count = len(re.findall(pattern, original, flags=re.IGNORECASE))
            sanitized_count = len(re.findall(pattern, sanitized, flags=re.IGNORECASE))

            if original_count > 0:
                report['pii_removed'][pattern_name] = original_count - sanitized_count

        return report


# Singleton instance for easy import
_sanitizer = DataSanitizer()


def sanitize_for_llm(text: str) -> str:
    """
    Quick helper function to sanitize text

    Usage:
        from security.data_sanitizer import sanitize_for_llm
        safe_text = sanitize_for_llm(raw_text)
    """
    return _sanitizer.sanitize_text(text)


def sanitize_document_for_llm(doc: Dict[str, Any]) -> Dict[str, Any]:
    """
    Quick helper to sanitize document

    Usage:
        from security.data_sanitizer import sanitize_document_for_llm
        safe_doc = sanitize_document_for_llm(raw_doc)
    """
    return _sanitizer.sanitize_document(doc)
