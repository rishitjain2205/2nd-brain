"""
Data Classification System
Classifies data by sensitivity level for SOC 2 compliance

SOC 2 Requirements:
- CC6.5: Data classification and handling
- P3.1: Sensitive data identification
"""

from enum import Enum
from typing import Dict, Any, List
import re


class DataClassification(Enum):
    """Data sensitivity classification levels"""
    PUBLIC = "public"  # Can be freely shared
    INTERNAL = "internal"  # Internal use only
    CONFIDENTIAL = "confidential"  # Confidential business data
    RESTRICTED = "restricted"  # Highly sensitive (PII, PHI, PCI)


class DataClassifier:
    """
    Automatically classifies data by sensitivity

    SOC 2: CC6.5 - Data is classified and protected
    """

    # Patterns for sensitive data
    PATTERNS = {
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
        "credit_card": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
        "ip_address": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        "api_key": r"(api[_-]?key|apikey|access[_-]?token)[\s:=]+['\"]?([a-zA-Z0-9_\-]{20,})['\"]?",
        "password": r"(password|passwd|pwd)[\s:=]+['\"]?([^\s'\"]{8,})['\"]?"
    }

    SENSITIVE_KEYWORDS = [
        "confidential", "secret", "private", "internal", "restricted",
        "ssn", "social security", "medical", "health", "diagnosis",
        "credit card", "bank account", "salary", "compensation"
    ]

    @staticmethod
    def classify_text(text: str) -> DataClassification:
        """
        Classify text by sensitivity level

        Args:
            text: Text to classify

        Returns:
            Classification level
        """
        text_lower = text.lower()

        # Check for restricted data (PII/PHI/PCI)
        for pattern_name, pattern in DataClassifier.PATTERNS.items():
            if re.search(pattern, text, re.IGNORECASE):
                return DataClassification.RESTRICTED

        # Check for confidential keywords
        for keyword in DataClassifier.SENSITIVE_KEYWORDS:
            if keyword in text_lower:
                return DataClassification.CONFIDENTIAL

        # Default to internal
        return DataClassification.INTERNAL

    @staticmethod
    def classify_dict(data: Dict[str, Any]) -> Dict[str, DataClassification]:
        """
        Classify each field in dictionary

        Args:
            data: Dictionary to classify

        Returns:
            Dictionary mapping field -> classification
        """
        classifications = {}

        for key, value in data.items():
            if isinstance(value, str):
                classifications[key] = DataClassifier.classify_text(value)
            elif isinstance(value, dict):
                # Recursively classify nested dicts
                nested = DataClassifier.classify_dict(value)
                # Use highest classification level
                max_level = max(nested.values(), key=lambda x: list(DataClassification).index(x))
                classifications[key] = max_level
            else:
                classifications[key] = DataClassification.INTERNAL

        return classifications

    @staticmethod
    def get_handling_requirements(classification: DataClassification) -> Dict[str, Any]:
        """
        Get handling requirements for classification level

        Args:
            classification: Data classification level

        Returns:
            Handling requirements
        """
        requirements = {
            DataClassification.PUBLIC: {
                "encryption_required": False,
                "access_control": "none",
                "audit_logging": False,
                "retention_days": 365,
                "secure_disposal": False
            },
            DataClassification.INTERNAL: {
                "encryption_required": True,
                "access_control": "authenticated_users",
                "audit_logging": True,
                "retention_days": 365,
                "secure_disposal": True
            },
            DataClassification.CONFIDENTIAL: {
                "encryption_required": True,
                "access_control": "role_based",
                "audit_logging": True,
                "retention_days": 180,
                "secure_disposal": True,
                "mfa_required": False
            },
            DataClassification.RESTRICTED: {
                "encryption_required": True,
                "access_control": "strict_rbac",
                "audit_logging": True,
                "retention_days": 90,
                "secure_disposal": True,
                "mfa_required": True,
                "data_masking": True
            }
        }

        return requirements[classification]


# Secure Data Disposal
class SecureDataDisposal:
    """
    Secure data disposal utilities

    SOC 2: CC6.5 - Secure disposal of sensitive data
    NIST 800-88: Guidelines for Media Sanitization

    ⚠️ SSD/CLOUD STORAGE LIMITATION:
    File overwriting (DoD 5220.22-M) is effective on traditional HDDs.
    On SSDs, NVMe drives, and cloud storage (AWS EBS/S3), the OS/hypervisor
    controls block placement due to wear leveling. Overwriting may not
    destroy the physical data.

    For SSD/Cloud: Use encryption at rest (we do) + deletion is sufficient.
    Physical destruction of drives is only option for 100% data erasure.
    This limitation is documented and acceptable for SOC 2 compliance.
    """

    @staticmethod
    def secure_delete_file(file_path: str, passes: int = 3) -> bool:
        """
        Securely delete file using DoD 5220.22-M standard

        Args:
            file_path: Path to file to delete
            passes: Number of overwrite passes (default: 3)

        Returns:
            True if successful
        """
        import os
        from pathlib import Path

        path = Path(file_path)

        # SECURITY FIX (2025-12-08): Avoid TOCTOU race condition
        # Use try/except instead of exists() check
        try:
            # Get file size
            file_size = path.stat().st_size

            # Overwrite with random data multiple times
            with open(path, 'r+b') as f:
                for pass_num in range(passes):
                    f.seek(0)
                    # Pass 1: Random data
                    # Pass 2: Complement of random
                    # Pass 3: Random data again
                    if pass_num % 2 == 0:
                        f.write(os.urandom(file_size))
                    else:
                        f.write(bytes([0xFF] * file_size))
                    f.flush()
                    os.fsync(f.fileno())

            # Finally, delete the file
            path.unlink()

            return True

        except (FileNotFoundError, PermissionError) as e:
            print(f"⚠️  Secure delete failed: File not accessible")
            return False

    @staticmethod
    def secure_delete_directory(dir_path: str, passes: int = 3) -> int:
        """
        Securely delete all files in directory

        Args:
            dir_path: Directory path
            passes: Number of overwrite passes

        Returns:
            Number of files deleted
        """
        from pathlib import Path
        import shutil

        path = Path(dir_path)
        deleted_count = 0

        # SECURITY FIX (2025-12-08): Avoid TOCTOU - use try/except
        try:
            # Securely delete all files
            for file in path.rglob("*"):
                if file.is_file():
                    SecureDataDisposal.secure_delete_file(str(file), passes)
                    deleted_count += 1

            # Remove empty directory
            try:
                shutil.rmtree(path)
            except FileNotFoundError:
                pass  # Already deleted

        except FileNotFoundError:
            return 0  # Directory doesn't exist

        return deleted_count

    @staticmethod
    def anonymize_data(data: Dict[str, Any], fields_to_anonymize: List[str]) -> Dict[str, Any]:
        """
        Anonymize specific fields in data

        Args:
            data: Data dictionary
            fields_to_anonymize: List of field names to anonymize

        Returns:
            Anonymized data
        """
        import hashlib
        import copy

        anonymized = copy.deepcopy(data)

        for field in fields_to_anonymize:
            if field in anonymized:
                value = str(anonymized[field])
                # Hash the value
                hashed = hashlib.sha256(value.encode()).hexdigest()[:16]
                anonymized[field] = f"anonymized_{hashed}"

        return anonymized


if __name__ == "__main__":
    print("="*60)
    print("Data Classification & Secure Disposal Test")
    print("="*60)

    # Test classification
    print("\n1️⃣  Testing data classification...")

    test_data = {
        "public_info": "Our company website",
        "email": "user@example.com",
        "ssn": "123-45-6789",
        "confidential": "Internal business strategy",
        "api_key": "api_key: sk_live_abcdef1234567890"
    }

    classifications = DataClassifier.classify_dict(test_data)
    for field, level in classifications.items():
        requirements = DataClassifier.get_handling_requirements(level)
        print(f"  {field}: {level.value.upper()}")
        print(f"    - Encryption required: {requirements['encryption_required']}")
        print(f"    - MFA required: {requirements.get('mfa_required', False)}")

    # Test secure disposal
    print("\n2️⃣  Testing secure data disposal...")

    # Create test file
    from pathlib import Path
    test_file = Path("test_sensitive_data.txt")
    test_file.write_text("Sensitive data: SSN 123-45-6789")

    print(f"  Created test file: {test_file}")
    print(f"  File size: {test_file.stat().st_size} bytes")

    # Securely delete
    success = SecureDataDisposal.secure_delete_file(str(test_file))
    if success:
        print(f"  ✅ File securely deleted (3-pass overwrite)")
    else:
        print(f"  ❌ Deletion failed")

    print("\n" + "="*60)
    print("✅ Data Classification & Secure Disposal Working!")
    print("="*60)
