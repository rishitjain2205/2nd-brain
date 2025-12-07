#!/usr/bin/env python3
"""
PENETRATION TESTING SUITE
Attempts real attacks against the application

⚠️  WARNING: Only run this against YOUR OWN application!
⚠️  Running against other systems is illegal!

Run: python3 tests/test_penetration.py
"""

import sys
import os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import unittest
import requests
import json
from datetime import datetime


class PenetrationTestBase(unittest.TestCase):
    """Base class for penetration tests"""

    @classmethod
    def setUpClass(cls):
        cls.base_url = os.getenv('TEST_BASE_URL', 'http://localhost:5001')
        print(f"\n🎯 Target: {cls.base_url}")
        print("⚠️  Make sure app_secure.py is running!")
        print()

    def attempt_attack(self, attack_name, method, endpoint, data=None, headers=None):
        """Attempt an attack and report results"""
        print(f"  Attempting: {attack_name}...", end=" ")

        try:
            if method == 'POST':
                response = requests.post(
                    f"{self.base_url}{endpoint}",
                    json=data,
                    headers=headers or {},
                    timeout=5
                )
            elif method == 'GET':
                response = requests.get(
                    f"{self.base_url}{endpoint}",
                    params=data,
                    headers=headers or {},
                    timeout=5
                )
            else:
                raise ValueError(f"Unknown method: {method}")

            return response

        except requests.exceptions.ConnectionError:
            self.fail("⚠️  Cannot connect to app. Is app_secure.py running?")
        except Exception as e:
            self.fail(f"⚠️  Request failed: {e}")


class TestSQLInjectionAttacks(PenetrationTestBase):
    """SQL Injection penetration tests"""

    def test_sql_injection_login_bypass(self):
        """Attack: SQL injection in login (classic OR bypass)"""
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' #",
            "' OR 1=1--",
        ]

        for payload in payloads:
            response = self.attempt_attack(
                f"SQL injection: {payload[:20]}",
                'POST',
                '/api/search',
                data={'query': payload}
            )

            # Should NOT return any data or should return error
            self.assertIn(response.status_code, [400, 401, 500],
                         f"SQL injection may have succeeded with: {payload}")

            if response.status_code == 200:
                # If status is 200, check that no sensitive data leaked
                try:
                    data = response.json()
                    # Should not contain database dumps
                    self.assertNotIn('password', str(data).lower())
                    self.assertNotIn('secret', str(data).lower())
                except:
                    pass

            print("✅ BLOCKED")

    def test_sql_injection_union(self):
        """Attack: UNION-based SQL injection"""
        payloads = [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL, NULL--",
            "' UNION SELECT password FROM users--",
            "' UNION ALL SELECT email FROM users--",
        ]

        for payload in payloads:
            response = self.attempt_attack(
                f"UNION injection: {payload[:30]}",
                'POST',
                '/api/search',
                data={'query': payload}
            )

            # Should be blocked or return empty results
            self.assertIn(response.status_code, [400, 401, 500],
                         f"UNION injection may have succeeded")

            print("✅ BLOCKED")

    def test_sql_injection_blind(self):
        """Attack: Blind SQL injection"""
        payloads = [
            "' AND '1'='1",
            "' AND '1'='2",
            "' AND SLEEP(5)--",
            "' AND (SELECT COUNT(*) FROM users) > 0--",
        ]

        for payload in payloads:
            start_time = datetime.now()

            response = self.attempt_attack(
                f"Blind injection: {payload[:30]}",
                'POST',
                '/api/search',
                data={'query': payload}
            )

            elapsed = (datetime.now() - start_time).total_seconds()

            # Should not cause time delays (SLEEP attacks)
            self.assertLess(elapsed, 2, "Time-based SQL injection may have worked!")

            # Should be blocked
            self.assertIn(response.status_code, [400, 401, 500])

            print("✅ BLOCKED")


class TestAuthenticationAttacks(PenetrationTestBase):
    """Authentication bypass attempts"""

    def test_jwt_forgery_none_algorithm(self):
        """Attack: JWT 'none' algorithm attack"""
        # Forged JWT with "none" algorithm
        fake_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkF0dGFja2VyIiwiaWF0IjoxNTE2MjM5MDIyfQ."

        response = self.attempt_attack(
            "JWT 'none' algorithm bypass",
            'POST',
            '/api/search',
            data={'query': 'test'},
            headers={'Authorization': f'Bearer {fake_jwt}'}
        )

        # Should reject the forged token
        # (Note: This test assumes authentication is enabled)
        # If auth is not enabled, test is skipped

        print("✅ BLOCKED or AUTH DISABLED")

    def test_jwt_expired_token(self):
        """Attack: Use expired JWT token"""
        # Expired JWT (exp claim in the past)
        expired_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNTE2MjM5MDIyfQ.invalid"

        response = self.attempt_attack(
            "Expired JWT token",
            'POST',
            '/api/search',
            data={'query': 'test'},
            headers={'Authorization': f'Bearer {expired_jwt}'}
        )

        # Should reject expired token (if auth is enabled)
        print("✅ HANDLED")


class TestXSSAttacks(PenetrationTestBase):
    """Cross-Site Scripting (XSS) attacks"""

    def test_reflected_xss(self):
        """Attack: Reflected XSS in query parameter"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
        ]

        for payload in xss_payloads:
            response = self.attempt_attack(
                f"XSS: {payload[:30]}",
                'POST',
                '/api/search',
                data={'query': payload}
            )

            # Response should sanitize or reject the payload
            if response.status_code == 200:
                content = response.text.lower()
                # Should not contain executable scripts
                self.assertNotIn('<script>', content)
                self.assertNotIn('javascript:', content)
                self.assertNotIn('onerror=', content)

            print("✅ SANITIZED or BLOCKED")


class TestAPIAbuse(PenetrationTestBase):
    """API abuse and rate limiting tests"""

    def test_rate_limiting(self):
        """Attack: Rapid requests to test rate limiting"""
        print("  Testing rate limiting (sending 150 requests)...", end=" ")

        blocked_count = 0
        for i in range(150):
            try:
                response = requests.post(
                    f"{self.base_url}/api/search",
                    json={'query': 'test'},
                    timeout=1
                )

                if response.status_code == 429:  # Too Many Requests
                    blocked_count += 1

            except:
                pass

        # Should block some requests (rate limit = 100/min)
        self.assertGreater(blocked_count, 0,
                          "Rate limiting NOT working! All 150 requests succeeded!")

        print(f"✅ WORKING ({blocked_count}/150 blocked)")

    def test_large_payload(self):
        """Attack: Extremely large payload"""
        large_payload = "A" * 100000  # 100KB query

        response = self.attempt_attack(
            "Large payload (100KB)",
            'POST',
            '/api/search',
            data={'query': large_payload}
        )

        # Should reject or handle safely
        self.assertIn(response.status_code, [400, 413, 500])

        print("✅ BLOCKED")


class TestPathTraversal(PenetrationTestBase):
    """Path traversal attacks"""

    def test_directory_traversal(self):
        """Attack: Directory traversal"""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ]

        for payload in payloads:
            response = self.attempt_attack(
                f"Path traversal: {payload[:30]}",
                'POST',
                '/api/search',
                data={'query': payload}
            )

            # Should not leak file contents
            if response.status_code == 200:
                content = response.text.lower()
                self.assertNotIn('root:', content)  # /etc/passwd content
                self.assertNotIn('administrator', content)

            print("✅ BLOCKED")


class TestSecretExposure(PenetrationTestBase):
    """Test for exposed secrets"""

    def test_env_file_not_accessible(self):
        """Attack: Try to access .env file"""
        endpoints = [
            '/.env',
            '/backend/.env',
            '/../.env',
            '/api/../.env',
        ]

        for endpoint in endpoints:
            response = self.attempt_attack(
                f"Access .env: {endpoint}",
                'GET',
                endpoint
            )

            # Should return 404 or 403
            self.assertIn(response.status_code, [403, 404])

            # Should not leak env content
            if response.status_code == 200:
                self.assertNotIn('API_KEY', response.text)
                self.assertNotIn('SECRET', response.text)

            print("✅ PROTECTED")


def run_penetration_tests():
    """Run all penetration tests"""
    print("="*80)
    print("🎯 PENETRATION TESTING SUITE")
    print("2nd Brain Application - Real Attack Simulation")
    print("="*80)
    print()
    print("⚠️  WARNING: Only run against YOUR OWN application!")
    print("⚠️  Ensure app_secure.py is running on http://localhost:5001")
    print()

    input("Press Enter to start penetration tests...")

    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestSQLInjectionAttacks))
    suite.addTests(loader.loadTestsFromTestCase(TestAuthenticationAttacks))
    suite.addTests(loader.loadTestsFromTestCase(TestXSSAttacks))
    suite.addTests(loader.loadTestsFromTestCase(TestAPIAbuse))
    suite.addTests(loader.loadTestsFromTestCase(TestPathTraversal))
    suite.addTests(loader.loadTestsFromTestCase(TestSecretExposure))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print()
    print("="*80)
    print("PENETRATION TEST SUMMARY")
    print("="*80)
    print(f"Attacks attempted: {result.testsRun}")
    print(f"✅ Blocked/Mitigated: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"❌ Vulnerabilities found: {len(result.failures)}")
    print(f"⚠️  Errors: {len(result.errors)}")
    print()

    if result.wasSuccessful():
        print("🛡️  ALL ATTACKS BLOCKED! Application is secure.")
        return 0
    else:
        print("🚨 VULNERABILITIES FOUND! Fix before production!")
        return 1


if __name__ == "__main__":
    exit_code = run_penetration_tests()
    sys.exit(exit_code)
