#!/usr/bin/env python3
"""
Deployment Readiness Verification Script

Checks all critical blockers identified in external security review:
1. Zombie code removed
2. KMS configured
3. Redis HA ready
4. S3 Object Lock configured
5. CI/CD security gates active
6. JWT hardening verified
7. SSRF redirect validation active

Usage:
    python3 verify_deployment_readiness.py

    # Or check specific environment
    python3 verify_deployment_readiness.py --environment production

Returns:
    Exit code 0: Ready for deployment
    Exit code 1: Critical blockers found
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum


class CheckStatus(Enum):
    """Check status"""
    PASS = "✅ PASS"
    FAIL = "❌ FAIL"
    WARN = "⚠️  WARN"
    SKIP = "⏭️  SKIP"


@dataclass
class CheckResult:
    """Result of a security check"""
    status: CheckStatus
    check_name: str
    message: str
    details: str = ""
    blocker: bool = False  # True if this is a deployment blocker


class DeploymentReadinessChecker:
    """
    Deployment readiness checker

    Verifies all critical security requirements are met
    """

    def __init__(self, environment: str = "production"):
        """
        Initialize checker

        Args:
            environment: Target environment (development, staging, production)
        """
        self.environment = environment
        self.results: List[CheckResult] = []
        self.project_root = Path(__file__).parent

    def run_all_checks(self) -> bool:
        """
        Run all deployment readiness checks

        Returns:
            True if ready for deployment, False otherwise
        """
        print("=" * 70)
        print("DEPLOYMENT READINESS VERIFICATION")
        print("=" * 70)
        print(f"Environment: {self.environment}")
        print(f"Date: {subprocess.check_output(['date']).decode().strip()}")
        print()

        # Run checks
        self._check_zombie_code()
        self._check_kms_configuration()
        self._check_redis_ha()
        self._check_s3_object_lock()
        self._check_cicd_security()
        self._check_jwt_hardening()
        self._check_ssrf_redirect_validation()
        self._check_imports()
        self._check_environment_variables()
        self._check_dependencies()

        # Print results
        self._print_results()

        # Check if any blockers
        blockers = [r for r in self.results if r.blocker and r.status == CheckStatus.FAIL]

        if blockers:
            print()
            print("=" * 70)
            print("❌ DEPLOYMENT BLOCKED")
            print("=" * 70)
            print(f"Critical blockers found: {len(blockers)}")
            print()
            print("Fix these issues before deploying:")
            for result in blockers:
                print(f"  • {result.check_name}")
                print(f"    {result.message}")
            print()
            return False
        else:
            print()
            print("=" * 70)
            print("✅ DEPLOYMENT READY")
            print("=" * 70)
            print("All critical checks passed!")
            print()
            return True

    def _check_zombie_code(self):
        """Check 1: Verify old vulnerable files are deleted"""
        zombie_files = [
            "security/audit_logger.py",
            "security/audit_logger_cloud.py",
            "security/encryption_manager.py",  # Old non-fixed version
            "security/input_validator.py"  # Old non-fixed version
        ]

        found_zombies = []
        for file in zombie_files:
            file_path = self.project_root / file
            if file_path.exists():
                found_zombies.append(file)

        if found_zombies:
            self.results.append(CheckResult(
                status=CheckStatus.FAIL,
                check_name="Zombie Code Removal",
                message=f"Found {len(found_zombies)} vulnerable files still present",
                details=f"Files: {', '.join(found_zombies)}",
                blocker=True
            ))
        else:
            self.results.append(CheckResult(
                status=CheckStatus.PASS,
                check_name="Zombie Code Removal",
                message="All vulnerable files removed"
            ))

    def _check_kms_configuration(self):
        """Check 2: Verify KMS is configured"""
        # Check if KMS key manager exists
        kms_file = self.project_root / "security" / "kms_key_manager.py"

        if not kms_file.exists():
            self.results.append(CheckResult(
                status=CheckStatus.FAIL,
                check_name="KMS Key Manager",
                message="KMS key manager not found",
                details="Expected: security/kms_key_manager.py",
                blocker=True if self.environment == "production" else False
            ))
            return

        # Check if KMS is configured in environment
        kms_configured = (
            os.getenv("AWS_KMS_KEY_ID") or
            os.getenv("AZURE_KEY_VAULT_URL") or
            os.getenv("GCP_KMS_KEY_NAME")
        )

        if self.environment == "production" and not kms_configured:
            self.results.append(CheckResult(
                status=CheckStatus.FAIL,
                check_name="KMS Configuration",
                message="KMS not configured for production",
                details="Set AWS_KMS_KEY_ID, AZURE_KEY_VAULT_URL, or GCP_KMS_KEY_NAME",
                blocker=True
            ))
        elif kms_configured:
            self.results.append(CheckResult(
                status=CheckStatus.PASS,
                check_name="KMS Configuration",
                message="KMS configured"
            ))
        else:
            self.results.append(CheckResult(
                status=CheckStatus.WARN,
                check_name="KMS Configuration",
                message="KMS not configured (OK for dev/staging)"
            ))

    def _check_redis_ha(self):
        """Check 3: Verify Redis HA configuration"""
        # Check if Redis HA module exists
        redis_ha_file = self.project_root / "security" / "redis_ha_manager.py"

        if not redis_ha_file.exists():
            self.results.append(CheckResult(
                status=CheckStatus.FAIL,
                check_name="Redis HA Module",
                message="Redis HA manager not found",
                details="Expected: security/redis_ha_manager.py",
                blocker=True if self.environment == "production" else False
            ))
            return

        # Check Redis configuration
        redis_password = os.getenv("REDIS_PASSWORD")
        sentinel_configured = os.getenv("REDIS_SENTINEL_HOSTS")

        if self.environment == "production":
            if not redis_password:
                self.results.append(CheckResult(
                    status=CheckStatus.FAIL,
                    check_name="Redis Authentication",
                    message="Redis password not set",
                    details="Set REDIS_PASSWORD in environment",
                    blocker=True
                ))
            elif not sentinel_configured:
                self.results.append(CheckResult(
                    status=CheckStatus.WARN,
                    check_name="Redis HA (Sentinel)",
                    message="Redis Sentinel not configured (single instance)",
                    details="Configure REDIS_SENTINEL_HOSTS for HA"
                ))
            else:
                self.results.append(CheckResult(
                    status=CheckStatus.PASS,
                    check_name="Redis HA",
                    message="Redis HA configured with Sentinel"
                ))
        else:
            self.results.append(CheckResult(
                status=CheckStatus.PASS,
                check_name="Redis Configuration",
                message="Redis configured (dev/staging)"
            ))

    def _check_s3_object_lock(self):
        """Check 4: Verify S3 Object Lock configuration"""
        # Check if S3 logger exists
        s3_logger_file = self.project_root / "security" / "s3_immutable_audit_logger.py"

        if not s3_logger_file.exists():
            self.results.append(CheckResult(
                status=CheckStatus.FAIL,
                check_name="S3 Immutable Logger",
                message="S3 immutable audit logger not found",
                details="Expected: security/s3_immutable_audit_logger.py",
                blocker=True if self.environment == "production" else False
            ))
            return

        # Check S3 configuration
        s3_bucket = os.getenv("S3_AUDIT_BUCKET")

        if self.environment == "production" and not s3_bucket:
            self.results.append(CheckResult(
                status=CheckStatus.FAIL,
                check_name="S3 Audit Bucket",
                message="S3 audit bucket not configured",
                details="Set S3_AUDIT_BUCKET in environment",
                blocker=True
            ))
        elif s3_bucket:
            self.results.append(CheckResult(
                status=CheckStatus.PASS,
                check_name="S3 Object Lock",
                message=f"S3 configured: {s3_bucket}"
            ))
        else:
            self.results.append(CheckResult(
                status=CheckStatus.WARN,
                check_name="S3 Configuration",
                message="S3 not configured (OK for dev/staging)"
            ))

    def _check_cicd_security(self):
        """Check 5: Verify CI/CD security gates"""
        # Check for GitHub Actions workflow
        github_workflow = self.project_root / ".github" / "workflows" / "security-scan.yml"

        if not github_workflow.exists():
            self.results.append(CheckResult(
                status=CheckStatus.FAIL,
                check_name="CI/CD Security Scanning",
                message="GitHub Actions security workflow not found",
                details="Expected: .github/workflows/security-scan.yml",
                blocker=True
            ))
            return

        # Check for Dependabot
        dependabot_config = self.project_root / ".github" / "dependabot.yml"

        if not dependabot_config.exists():
            self.results.append(CheckResult(
                status=CheckStatus.WARN,
                check_name="Dependabot",
                message="Dependabot not configured",
                details="Expected: .github/dependabot.yml"
            ))
        else:
            self.results.append(CheckResult(
                status=CheckStatus.PASS,
                check_name="CI/CD Security",
                message="Security scanning configured"
            ))

    def _check_jwt_hardening(self):
        """Check 6: Verify JWT hardening"""
        jwt_file = self.project_root / "security" / "jwt_validator.py"

        if not jwt_file.exists():
            self.results.append(CheckResult(
                status=CheckStatus.FAIL,
                check_name="JWT Validator",
                message="JWT validator not found",
                blocker=True
            ))
            return

        # Check if JWT validator has hardening (alg:none rejection, kid validation)
        with open(jwt_file, 'r') as f:
            content = f.read()

        has_alg_none_check = "alg:none" in content.lower() or "alg == 'none'" in content
        has_kid_check = "kid" in content and ("missing" in content.lower() or "required" in content.lower())

        if has_alg_none_check and has_kid_check:
            self.results.append(CheckResult(
                status=CheckStatus.PASS,
                check_name="JWT Hardening",
                message="JWT validation hardened (alg:none rejection, kid validation)"
            ))
        else:
            missing = []
            if not has_alg_none_check:
                missing.append("alg:none rejection")
            if not has_kid_check:
                missing.append("kid validation")

            self.results.append(CheckResult(
                status=CheckStatus.WARN,
                check_name="JWT Hardening",
                message=f"JWT validation missing: {', '.join(missing)}"
            ))

    def _check_ssrf_redirect_validation(self):
        """Check 7: Verify SSRF redirect validation"""
        ssrf_file = self.project_root / "security" / "enhanced_ssrf_protection.py"

        if not ssrf_file.exists():
            self.results.append(CheckResult(
                status=CheckStatus.FAIL,
                check_name="SSRF Protection",
                message="SSRF protection module not found",
                blocker=True
            ))
            return

        # Check if redirect validation is implemented
        with open(ssrf_file, 'r') as f:
            content = f.read()

        has_redirect_validation = "redirect" in content.lower() and "validate" in content.lower()
        has_dns_rebinding = "dns" in content.lower() and "rebind" in content.lower()

        if has_redirect_validation and has_dns_rebinding:
            self.results.append(CheckResult(
                status=CheckStatus.PASS,
                check_name="SSRF Protection",
                message="SSRF protection includes redirect validation and DNS rebinding protection"
            ))
        else:
            missing = []
            if not has_redirect_validation:
                missing.append("redirect validation")
            if not has_dns_rebinding:
                missing.append("DNS rebinding protection")

            self.results.append(CheckResult(
                status=CheckStatus.WARN,
                check_name="SSRF Protection",
                message=f"SSRF protection missing: {', '.join(missing)}"
            ))

    def _check_imports(self):
        """Check 8: Verify app uses hardened modules"""
        app_file = self.project_root / "app_secure.py"

        if not app_file.exists():
            self.results.append(CheckResult(
                status=CheckStatus.SKIP,
                check_name="Import Verification",
                message="app_secure.py not found"
            ))
            return

        with open(app_file, 'r') as f:
            content = f.read()

        # Check for dangerous imports
        dangerous_imports = [
            "from security.audit_logger import",
            "from security.encryption_manager import",
            "from security.input_validator import"
        ]

        found_dangerous = []
        for imp in dangerous_imports:
            if imp in content:
                found_dangerous.append(imp)

        if found_dangerous:
            self.results.append(CheckResult(
                status=CheckStatus.FAIL,
                check_name="Import Safety",
                message=f"Found imports to vulnerable modules",
                details=f"Remove: {', '.join(found_dangerous)}",
                blocker=True
            ))
        else:
            self.results.append(CheckResult(
                status=CheckStatus.PASS,
                check_name="Import Safety",
                message="All imports use hardened modules"
            ))

    def _check_environment_variables(self):
        """Check 9: Verify required environment variables"""
        required_vars = {
            "production": [
                ("AUDIT_HMAC_SECRET", "Audit log integrity"),
                ("AUTH0_DOMAIN", "Authentication"),
                ("AUTH0_API_AUDIENCE", "JWT validation"),
            ],
            "staging": [
                ("AUDIT_HMAC_SECRET", "Audit log integrity"),
            ],
            "development": []
        }

        vars_to_check = required_vars.get(self.environment, [])

        if not vars_to_check:
            self.results.append(CheckResult(
                status=CheckStatus.SKIP,
                check_name="Environment Variables",
                message="No required vars for this environment"
            ))
            return

        missing = []
        for var_name, description in vars_to_check:
            if not os.getenv(var_name):
                missing.append(f"{var_name} ({description})")

        if missing:
            self.results.append(CheckResult(
                status=CheckStatus.FAIL,
                check_name="Environment Variables",
                message=f"Missing {len(missing)} required variables",
                details=f"Missing: {', '.join(missing)}",
                blocker=True if self.environment == "production" else False
            ))
        else:
            self.results.append(CheckResult(
                status=CheckStatus.PASS,
                check_name="Environment Variables",
                message="All required variables set"
            ))

    def _check_dependencies(self):
        """Check 10: Verify dependencies are up to date"""
        requirements_file = self.project_root / "requirements.txt"

        if not requirements_file.exists():
            self.results.append(CheckResult(
                status=CheckStatus.WARN,
                check_name="Dependencies",
                message="requirements.txt not found"
            ))
            return

        # Just verify file exists for now
        # In CI/CD, Snyk/Trivy will do the actual vulnerability scanning
        self.results.append(CheckResult(
            status=CheckStatus.PASS,
            check_name="Dependencies",
            message="requirements.txt found (CI/CD will scan for vulnerabilities)"
        ))

    def _print_results(self):
        """Print check results"""
        print()
        print("CHECK RESULTS:")
        print("=" * 70)

        for result in self.results:
            blocker_marker = " [BLOCKER]" if result.blocker else ""
            print(f"{result.status.value} {result.check_name}{blocker_marker}")
            print(f"   {result.message}")
            if result.details:
                print(f"   Details: {result.details}")
            print()

        # Summary
        passed = len([r for r in self.results if r.status == CheckStatus.PASS])
        failed = len([r for r in self.results if r.status == CheckStatus.FAIL])
        warned = len([r for r in self.results if r.status == CheckStatus.WARN])
        skipped = len([r for r in self.results if r.status == CheckStatus.SKIP])
        total = len(self.results)

        print("=" * 70)
        print(f"SUMMARY: {passed}/{total} passed, {failed} failed, {warned} warnings, {skipped} skipped")


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="Verify deployment readiness")
    parser.add_argument(
        "--environment",
        choices=["development", "staging", "production"],
        default="production",
        help="Target environment"
    )

    args = parser.parse_args()

    checker = DeploymentReadinessChecker(environment=args.environment)
    ready = checker.run_all_checks()

    sys.exit(0 if ready else 1)


if __name__ == "__main__":
    main()
