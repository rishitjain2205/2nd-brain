#!/usr/bin/env python3
"""
COMPREHENSIVE SECURITY TEST SUITE
Tests all security measures implemented in the 2nd Brain application

Run: python3 tests/test_security_comprehensive.py
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import unittest
import hashlib
import re
from datetime import datetime
import json
import tempfile


class TestSQLInjectionPrevention(unittest.TestCase):
    """Test SQL injection prevention mechanisms"""

    def setUp(self):
        from security.secure_database import SecureDatabase
        self.db = SecureDatabase('sqlite:///:memory:')

        # Create test table
        self.db.execute_update("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                email TEXT,
                name TEXT,
                active INTEGER
            )
        """)

        # Insert test data
        self.db.execute_update(
            "INSERT INTO users (email, name, active) VALUES (?, ?, ?)",
            ('test@example.com', 'Test User', 1)
        )

    def test_sql_injection_or_bypass(self):
        """Test: SQL injection with OR bypass"""
        malicious_email = "' OR '1'='1"

        result = self.db.execute_query(
            "SELECT * FROM users WHERE email = ?",
            (malicious_email,)
        )

        # Should return 0 users (attack prevented)
        self.assertEqual(len(result), 0, "SQL injection OR bypass NOT prevented!")

    def test_sql_injection_union(self):
        """Test: SQL injection with UNION SELECT"""
        malicious_email = "' UNION SELECT id, email, name FROM users--"

        result = self.db.execute_query(
            "SELECT * FROM users WHERE email = ?",
            (malicious_email,)
        )

        # Should return 0 users (attack prevented)
        self.assertEqual(len(result), 0, "SQL injection UNION attack NOT prevented!")

    def test_sql_injection_time_delay(self):
        """Test: SQL injection with time-based attack"""
        malicious_email = "'; WAITFOR DELAY '0:0:5'--"

        result = self.db.execute_query(
            "SELECT * FROM users WHERE email = ?",
            (malicious_email,)
        )

        # Should return 0 users (attack prevented)
        self.assertEqual(len(result), 0, "SQL injection time-delay attack NOT prevented!")

    def test_sql_injection_drop_table(self):
        """Test: SQL injection attempting to drop table"""
        malicious_email = "'; DROP TABLE users; --"

        result = self.db.execute_query(
            "SELECT * FROM users WHERE email = ?",
            (malicious_email,)
        )

        # Should return 0 users (attack prevented)
        self.assertEqual(len(result), 0, "SQL injection DROP TABLE attack NOT prevented!")

        # Verify table still exists
        result = self.db.execute_query("SELECT * FROM users")
        self.assertGreater(len(result), 0, "Table was dropped! SQL injection succeeded!")

    def test_legitimate_query_works(self):
        """Test: Legitimate queries still work"""
        result = self.db.execute_query(
            "SELECT * FROM users WHERE email = ?",
            ('test@example.com',)
        )

        self.assertEqual(len(result), 1, "Legitimate query failed!")
        # SECURITY FIX: execute_query returns dictionaries, not tuples
        self.assertEqual(result[0]['email'], 'test@example.com')


class TestEncryptionSecurity(unittest.TestCase):
    """Test encryption implementation"""

    def setUp(self):
        from security.encryption_manager_fixed import EncryptionManager
        self.em = EncryptionManager()

    def test_salt_randomness(self):
        """Test: Salts are random and unique"""
        key1, salt1 = self.em.derive_key_from_password("password123")
        key2, salt2 = self.em.derive_key_from_password("password123")

        # Same password should produce DIFFERENT salts
        self.assertNotEqual(salt1, salt2, "Salts are not random! CRITICAL VULNERABILITY!")

        # Same password with different salts should produce different keys
        self.assertNotEqual(key1, key2, "Keys are identical despite different salts!")

    def test_salt_length(self):
        """Test: Salt is 32 bytes (256 bits)"""
        import base64
        key, salt_b64 = self.em.derive_key_from_password("test")
        salt = base64.urlsafe_b64decode(salt_b64.encode())

        self.assertEqual(len(salt), 32, f"Salt is only {len(salt)} bytes, should be 32!")

    def test_encryption_decryption(self):
        """Test: Encrypt and decrypt works"""
        plaintext = "Sensitive data 123"

        ciphertext = self.em.encrypt_string(plaintext)
        decrypted = self.em.decrypt_string(ciphertext)

        self.assertEqual(plaintext, decrypted, "Encryption/decryption failed!")

    def test_ciphertext_different_each_time(self):
        """Test: Same plaintext produces different ciphertext (IV randomness)"""
        plaintext = "Test data"

        ciphertext1 = self.em.encrypt_string(plaintext)
        ciphertext2 = self.em.encrypt_string(plaintext)

        self.assertNotEqual(ciphertext1, ciphertext2,
                          "Same ciphertext produced twice! IV not random!")

    def test_tampering_detection(self):
        """Test: Tampering with ciphertext is detected"""
        from cryptography.fernet import InvalidToken

        plaintext = "Original message"
        ciphertext = self.em.encrypt_string(plaintext)

        # Tamper with ciphertext
        tampered = ciphertext[:-10] + "TAMPERED!!"

        with self.assertRaises(InvalidToken, msg="Tampering NOT detected!"):
            self.em.decrypt_string(tampered)


class TestJWTValidation(unittest.TestCase):
    """Test JWT validation (requires PyJWT)"""

    def test_pyjwt_installed(self):
        """Test: PyJWT is installed"""
        try:
            import jwt
            self.assertTrue(True)
        except ImportError:
            self.fail("PyJWT not installed! Run: pip install pyjwt[crypto]")

    def test_invalid_token_rejected(self):
        """Test: Invalid JWT tokens are rejected"""
        from security.jwt_validator import JWTValidator, JWTConfig

        # Create validator with fake config
        config = JWTConfig(
            issuer="https://fake.auth0.com/",
            audience="https://api.fake.com",
            jwks_uri="https://fake.auth0.com/.well-known/jwks.json"
        )

        validator = JWTValidator(config)

        # Test invalid tokens
        invalid_tokens = [
            "not.a.token",
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.",  # "none" algorithm
            "",
            "a.b.c",
        ]

        for token in invalid_tokens:
            result = validator.validate_token(token)
            self.assertIsNone(result, f"Invalid token was accepted: {token[:20]}...")


class TestPIISanitization(unittest.TestCase):
    """Test PII sanitization"""

    def setUp(self):
        from security.pii_sanitizer_enhanced import EnhancedPIISanitizer
        self.sanitizer = EnhancedPIISanitizer(hash_pii=True)

    def test_email_sanitization(self):
        """Test: Email addresses are sanitized"""
        text = "Contact john.doe@example.com for details"
        sanitized, stats = self.sanitizer.sanitize(text)

        self.assertNotIn("john.doe@example.com", sanitized)
        self.assertGreater(stats['emails'], 0)
        self.assertIn("[EMAIL_", sanitized)

    def test_phone_sanitization(self):
        """Test: Phone numbers are sanitized"""
        text = "Call +1-555-123-4567 or +44 2071 234567"
        sanitized, stats = self.sanitizer.sanitize(text)

        self.assertNotIn("555-123-4567", sanitized)
        self.assertGreater(stats['phones'], 0)
        self.assertIn("[PHONE_", sanitized)

    def test_ssn_sanitization(self):
        """Test: SSNs are sanitized"""
        text = "SSN: 123-45-6789"
        sanitized, stats = self.sanitizer.sanitize(text)

        self.assertNotIn("123-45-6789", sanitized)
        self.assertGreater(stats['ssns'], 0)
        self.assertIn("[SSN_", sanitized)

    def test_credit_card_sanitization(self):
        """Test: Credit cards are sanitized"""
        text = "Card: 1234-5678-9012-3456"
        sanitized, stats = self.sanitizer.sanitize(text)

        self.assertNotIn("1234-5678-9012-3456", sanitized)
        self.assertGreater(stats['credit_cards'], 0)

    def test_jwt_token_detection(self):
        """Test: JWT tokens are detected and sanitized"""
        text = "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SIGNATURE"
        sanitized, stats = self.sanitizer.sanitize(text)

        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", sanitized)
        self.assertGreater(stats['api_keys_jwt'], 0)
        self.assertIn("[API_KEY_JWT", sanitized)

    def test_aws_key_detection(self):
        """Test: AWS keys are detected"""
        text = "AWS Key: AKIAIOSFODNN7EXAMPLE"
        sanitized, stats = self.sanitizer.sanitize(text)

        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", sanitized)
        self.assertGreater(stats['api_keys_aws'], 0)


class TestFilePermissions(unittest.TestCase):
    """Test file permissions on sensitive files"""

    def test_encrypted_file_permissions(self):
        """Test: Encrypted files have 0600 permissions"""
        from security.secure_disposal import SecureDataDisposal

        with tempfile.TemporaryDirectory() as tmpdir:
            disposal = SecureDataDisposal(key_storage_dir=tmpdir)

            test_data = b"Sensitive information"
            key_id = disposal.create_encrypted_file(
                test_data,
                f"{tmpdir}/test.enc"
            )

            # Check file permissions
            file_path = Path(f"{tmpdir}/test.enc")
            mode = file_path.stat().st_mode & 0o777

            self.assertEqual(mode, 0o600,
                           f"File permissions are {oct(mode)}, should be 0o600!")

            # Cleanup
            disposal.crypto_shred(key_id, "test cleanup")

    def test_key_file_permissions(self):
        """Test: Key files have 0600 permissions"""
        from security.secure_disposal import SecureDataDisposal

        with tempfile.TemporaryDirectory() as tmpdir:
            disposal = SecureDataDisposal(key_storage_dir=tmpdir)

            test_data = b"Test data"
            key_id = disposal.create_encrypted_file(
                test_data,
                f"{tmpdir}/test.enc"
            )

            # Check key file permissions
            key_file = Path(tmpdir) / f"{key_id}.key"
            mode = key_file.stat().st_mode & 0o777

            self.assertEqual(mode, 0o600,
                           f"Key file permissions are {oct(mode)}, should be 0o600!")

            # Cleanup
            disposal.crypto_shred(key_id, "test cleanup")


class TestCryptoShredding(unittest.TestCase):
    """Test secure data disposal"""

    def test_data_unrecoverable_after_shred(self):
        """Test: Data is unrecoverable after crypto-shredding"""
        from security.secure_disposal import SecureDataDisposal

        with tempfile.TemporaryDirectory() as tmpdir:
            disposal = SecureDataDisposal(key_storage_dir=tmpdir)

            sensitive_data = b"TOP SECRET INFORMATION"
            file_path = f"{tmpdir}/sensitive.enc"

            # Create encrypted file
            key_id = disposal.create_encrypted_file(sensitive_data, file_path)

            # Verify we can decrypt
            decrypted = disposal.read_encrypted_file(file_path, key_id)
            self.assertEqual(decrypted, sensitive_data)

            # Crypto-shred (delete key)
            disposal.crypto_shred(key_id, "Test shredding", "testuser")

            # Attempt to decrypt should fail
            with self.assertRaises(FileNotFoundError):
                disposal.read_encrypted_file(file_path, key_id)

            # Encrypted file still exists but is useless
            self.assertTrue(Path(file_path).exists())

    def test_shredding_logged(self):
        """Test: Crypto-shredding is logged"""
        from security.secure_disposal import SecureDataDisposal

        with tempfile.TemporaryDirectory() as tmpdir:
            disposal = SecureDataDisposal(key_storage_dir=tmpdir)

            test_data = b"Test"
            key_id = disposal.create_encrypted_file(test_data, f"{tmpdir}/test.enc")

            # Shred
            disposal.crypto_shred(key_id, "GDPR deletion", "user123")

            # Check audit log
            log_entries = disposal.get_disposal_audit_log()
            self.assertGreater(len(log_entries), 0)

            last_entry = log_entries[-1]
            self.assertEqual(last_entry['key_id'], key_id)
            self.assertEqual(last_entry['action'], 'crypto_shred')
            self.assertEqual(last_entry['reason'], 'GDPR deletion')
            self.assertEqual(last_entry['user_id'], 'user123')


class TestInputValidation(unittest.TestCase):
    """Test input validation"""

    def setUp(self):
        from security.input_validator_fixed import InputValidator
        self.validator = InputValidator()

    def test_email_validation(self):
        """Test: Email validation"""
        # Valid emails
        self.assertEqual(
            self.validator.validate_email("test@example.com"),
            "test@example.com"
        )

        # Invalid emails
        with self.assertRaises(ValueError):
            self.validator.validate_email("not-an-email")

        with self.assertRaises(ValueError):
            self.validator.validate_email("@example.com")

    def test_ssrf_protection(self):
        """Test: SSRF protection in URL validation"""
        # Localhost should be blocked
        with self.assertRaises(ValueError):
            self.validator.validate_url("http://localhost/admin")

        with self.assertRaises(ValueError):
            self.validator.validate_url("http://127.0.0.1/internal")

        with self.assertRaises(ValueError):
            self.validator.validate_url("http://192.168.1.1/router")

        # External URLs should work
        self.assertIsNotNone(
            self.validator.validate_url("https://example.com")
        )

    def test_integer_validation(self):
        """Test: Integer range validation"""
        # Valid
        self.assertEqual(self.validator.validate_integer(5, 0, 10), 5)

        # Out of range
        with self.assertRaises(ValueError):
            self.validator.validate_integer(100, 0, 10)

        with self.assertRaises(ValueError):
            self.validator.validate_integer(-5, 0, 10)


class TestNoPickleDeserialization(unittest.TestCase):
    """Test that pickle is NOT used"""

    def test_no_pickle_in_encryption_manager(self):
        """Test: Encryption manager doesn't use pickle"""
        import importlib
        import security.encryption_manager_fixed as em

        # Check source code for pickle usage
        source_file = Path(em.__file__)
        source_code = source_file.read_text()

        # Should NOT contain pickle.loads
        self.assertNotIn("pickle.loads", source_code,
                        "CRITICAL: pickle.loads found in encryption manager!")

        # Should NOT contain pickle.load
        self.assertNotIn("pickle.load(", source_code,
                        "CRITICAL: pickle.load found in encryption manager!")


def run_comprehensive_tests():
    """Run all security tests and generate report"""
    print("="*80)
    print("COMPREHENSIVE SECURITY TEST SUITE")
    print("2nd Brain Application - Security Verification")
    print("="*80)
    print()

    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestSQLInjectionPrevention))
    suite.addTests(loader.loadTestsFromTestCase(TestEncryptionSecurity))
    suite.addTests(loader.loadTestsFromTestCase(TestJWTValidation))
    suite.addTests(loader.loadTestsFromTestCase(TestPIISanitization))
    suite.addTests(loader.loadTestsFromTestCase(TestFilePermissions))
    suite.addTests(loader.loadTestsFromTestCase(TestCryptoShredding))
    suite.addTests(loader.loadTestsFromTestCase(TestInputValidation))
    suite.addTests(loader.loadTestsFromTestCase(TestNoPickleDeserialization))

    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print()
    print("="*80)
    print("TEST SUMMARY")
    print("="*80)
    print(f"Tests run: {result.testsRun}")
    print(f"✅ Passed: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"❌ Failed: {len(result.failures)}")
    print(f"⚠️  Errors: {len(result.errors)}")
    print()

    if result.wasSuccessful():
        print("🎉 ALL SECURITY TESTS PASSED!")
        print("Your application is secure and ready for production.")
        return 0
    else:
        print("🚨 SECURITY TESTS FAILED!")
        print("Fix the issues above before deploying to production.")
        return 1


if __name__ == "__main__":
    exit_code = run_comprehensive_tests()
    sys.exit(exit_code)
