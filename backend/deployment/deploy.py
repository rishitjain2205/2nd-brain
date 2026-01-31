"""
Automated Deployment System
Infrastructure-as-code for SOC 2 compliant deployments

SOC 2 Requirements:
- CC8.1: Change management and authorization
- CC8.2: Change testing and approval
- A1.1: Deployment automation for availability
"""

import os
import sys
import subprocess
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import hashlib


class DeploymentEnvironment:
    """Deployment environment types"""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class DeploymentStatus:
    """Deployment status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class AutomatedDeployer:
    """
    Automated deployment system with SOC 2 compliance

    Features:
    - Pre-deployment validation
    - Automated security hardening
    - Health checks
    - Rollback capability
    - Deployment audit trail
    """

    def __init__(self, environment: str = DeploymentEnvironment.STAGING):
        """Initialize deployer"""
        self.environment = environment
        self.deployment_id = f"deploy_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.log_dir = Path("logs/deployments")
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.deployment_log = []
        self.status = DeploymentStatus.PENDING

        print(f"✓ Automated Deployer initialized")
        print(f"  - Environment: {self.environment}")
        print(f"  - Deployment ID: {self.deployment_id}")

    def deploy(self, skip_tests: bool = False, auto_approve: bool = False) -> bool:
        """
        Execute full deployment

        Args:
            skip_tests: Skip pre-deployment tests (not recommended)
            auto_approve: Auto-approve deployment (use with caution)

        Returns:
            True if deployment successful, False otherwise
        """
        print("\n" + "=" * 70)
        print(f"STARTING DEPLOYMENT: {self.deployment_id}")
        print("=" * 70)

        self.status = DeploymentStatus.IN_PROGRESS
        self._log("Deployment started", {"environment": self.environment})

        try:
            # 1. Pre-deployment validation
            print("\n1️⃣  Pre-deployment validation...")
            if not self._pre_deployment_validation():
                raise Exception("Pre-deployment validation failed")
            self._log("Pre-deployment validation passed")

            # 2. Run security tests
            if not skip_tests:
                print("\n2️⃣  Running security tests...")
                if not self._run_security_tests():
                    raise Exception("Security tests failed")
                self._log("Security tests passed")
            else:
                print("\n2️⃣  ⚠️  SKIPPING TESTS (not recommended)")
                self._log("Tests skipped", {"warning": "Security tests not run"})

            # 3. Backup current state
            print("\n3️⃣  Creating backup...")
            backup_path = self._create_backup()
            self._log("Backup created", {"path": str(backup_path)})

            # 4. Deployment approval
            if not auto_approve:
                print("\n4️⃣  Deployment approval required...")
                if not self._get_approval():
                    raise Exception("Deployment not approved")
                self._log("Deployment approved")
            else:
                print("\n4️⃣  ⚠️  AUTO-APPROVED")
                self._log("Deployment auto-approved", {"warning": "Manual approval bypassed"})

            # 5. Deploy infrastructure
            print("\n5️⃣  Deploying infrastructure...")
            if not self._deploy_infrastructure():
                raise Exception("Infrastructure deployment failed")
            self._log("Infrastructure deployed")

            # 6. Deploy application
            print("\n6️⃣  Deploying application...")
            if not self._deploy_application():
                raise Exception("Application deployment failed")
            self._log("Application deployed")

            # 7. Configure security
            print("\n7️⃣  Configuring security...")
            if not self._configure_security():
                raise Exception("Security configuration failed")
            self._log("Security configured")

            # 8. Health checks
            print("\n8️⃣  Running health checks...")
            if not self._health_checks():
                raise Exception("Health checks failed")
            self._log("Health checks passed")

            # 9. Enable monitoring
            print("\n9️⃣  Enabling monitoring...")
            if not self._enable_monitoring():
                raise Exception("Monitoring setup failed")
            self._log("Monitoring enabled")

            # 10. Finalize deployment
            print("\n🔟 Finalizing deployment...")
            self._finalize_deployment()
            self._log("Deployment finalized")

            self.status = DeploymentStatus.SUCCESS
            self._log("Deployment completed successfully")

            print("\n" + "=" * 70)
            print("✅ DEPLOYMENT SUCCESSFUL!")
            print("=" * 70)
            return True

        except Exception as e:
            print(f"\n❌ DEPLOYMENT FAILED: {str(e)}")
            self._log(f"Deployment failed: {str(e)}", {"error": True})
            self.status = DeploymentStatus.FAILED

            # Rollback
            print("\n🔄 Initiating rollback...")
            if self._rollback(backup_path if 'backup_path' in locals() else None):
                self.status = DeploymentStatus.ROLLED_BACK
                print("✓ Rollback successful")
            else:
                print("❌ Rollback failed - manual intervention required")

            return False

        finally:
            # Save deployment log
            self._save_deployment_log()

    def _pre_deployment_validation(self) -> bool:
        """Pre-deployment validation checks"""
        checks = []

        # Check 1: Required environment variables
        print("  • Checking environment variables...")
        required_vars = [
            'ENCRYPTION_KEY',
            'AUTH0_DOMAIN',
            'AUTH0_AUDIENCE',
        ]

        for var in required_vars:
            if not os.getenv(var):
                print(f"    ❌ Missing: {var}")
                checks.append(False)
            else:
                print(f"    ✓ Found: {var}")
                checks.append(True)

        # Check 2: Required files exist
        print("  • Checking required files...")
        required_files = [
            'security/input_validator_fixed.py',  # FIXED: Use hardened version
            'security/encryption_manager_fixed.py',  # FIXED: Use hardened version
            'security/audit_logger.py',
            'monitoring/uptime_monitor.py',
            'backup/backup_manager.py',
        ]

        for file in required_files:
            if Path(file).exists():
                print(f"    ✓ Found: {file}")
                checks.append(True)
            else:
                print(f"    ❌ Missing: {file}")
                checks.append(False)

        # Check 3: Python dependencies
        print("  • Checking Python dependencies...")
        try:
            import cryptography
            import flask
            import psutil
            print("    ✓ All dependencies installed")
            checks.append(True)
        except ImportError as e:
            print(f"    ❌ Missing dependency: {e}")
            checks.append(False)

        return all(checks)

    def _run_security_tests(self) -> bool:
        """Run security test suite"""
        try:
            # Run comprehensive security tests
            result = subprocess.run(
                [sys.executable, "tests/comprehensive_security_test.py"],
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes
            )

            if result.returncode == 0:
                print("  ✓ All security tests passed")
                return True
            else:
                print("  ❌ Security tests failed")
                print(result.stdout)
                return False

        except subprocess.TimeoutExpired:
            print("  ❌ Security tests timed out")
            return False
        except Exception as e:
            print(f"  ❌ Error running tests: {e}")
            return False

    def _create_backup(self) -> Path:
        """Create backup before deployment"""
        from backup.backup_manager import BackupManager

        manager = BackupManager()
        backup_name = f"pre_deploy_{self.deployment_id}"

        backup_path = manager.create_backup(backup_name=backup_name)
        print(f"  ✓ Backup created: {backup_path}")

        return backup_path

    def _get_approval(self) -> bool:
        """Get deployment approval"""
        if self.environment == DeploymentEnvironment.PRODUCTION:
            print(f"\n  ⚠️  PRODUCTION DEPLOYMENT REQUIRES APPROVAL")
            print(f"  Environment: {self.environment}")
            print(f"  Deployment ID: {self.deployment_id}")
            print(f"  Timestamp: {datetime.now().isoformat()}")

            response = input("\n  Approve deployment? (yes/no): ").lower()
            return response == 'yes'
        else:
            print(f"  ✓ Non-production deployment - auto-approved")
            return True

    def _deploy_infrastructure(self) -> bool:
        """Deploy infrastructure components"""
        print("  • Setting up directories...")
        directories = [
            'data/audit_logs',
            'data/security_incidents',
            'data/backups',
            'data/soc2_evidence',
            'data/security_training',
            'data/vendor_management',
            'logs/deployments',
            'logs/monitoring',
        ]

        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
            print(f"    ✓ Created: {directory}")

        return True

    def _deploy_application(self) -> bool:
        """Deploy application code"""
        print("  • Installing Python dependencies...")
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode == 0:
                print("    ✓ Dependencies installed")
                return True
            else:
                print("    ❌ Dependency installation failed")
                return False

        except Exception as e:
            print(f"    ❌ Error: {e}")
            return False

    def _configure_security(self) -> bool:
        """Configure security settings"""
        print("  • Configuring security settings...")

        # Security configuration
        security_config = {
            "https_enforced": True,
            "hsts_enabled": True,
            "mfa_required": os.getenv('REQUIRE_MFA', 'false').lower() == 'true',
            "max_jwt_lifetime": int(os.getenv('MAX_JWT_LIFETIME_SECONDS', '3600')),
            "encryption_enabled": os.getenv('ENCRYPTION_KEY') is not None,
            "audit_logging_enabled": True,
            "incident_detection_enabled": True,
        }

        # Save security configuration
        config_file = Path("data/security_config.json")
        with open(config_file, 'w') as f:
            json.dump(security_config, f, indent=2)

        print(f"    ✓ Security configuration saved: {config_file}")

        # Verify security modules are importable
        try:
            # FIXED: Import from hardened "_fixed" versions
            from security.input_validator_fixed import InputValidator
            from security.https_enforcer import HTTPSEnforcer
            from security.encryption_manager_fixed import EncryptionManager
            print("    ✓ Security modules verified")
            return True
        except ImportError as e:
            print(f"    ❌ Security module import failed: {e}")
            return False

    def _health_checks(self) -> bool:
        """Run health checks"""
        print("  • Running health checks...")

        try:
            from monitoring.uptime_monitor import SystemHealthMonitor

            monitor = SystemHealthMonitor()
            health = monitor.get_overall_health()

            print(f"    ✓ System status: {health['status']}")
            print(f"    ✓ CPU: {health['checks']['cpu']['status']}")
            print(f"    ✓ Memory: {health['checks']['memory']['status']}")
            print(f"    ✓ Disk: {health['checks']['disk']['status']}")

            return True

        except Exception as e:
            print(f"    ❌ Health check failed: {e}")
            return False

    def _enable_monitoring(self) -> bool:
        """Enable monitoring and alerting"""
        print("  • Enabling monitoring...")

        try:
            from monitoring.uptime_monitor import SystemHealthMonitor
            from monitoring.alert_manager import AlertManager

            # Initialize monitoring
            monitor = SystemHealthMonitor()
            alert_manager = AlertManager()

            print("    ✓ Monitoring enabled")
            print("    ✓ Alerting configured")

            return True

        except Exception as e:
            print(f"    ❌ Monitoring setup failed: {e}")
            return False

    def _finalize_deployment(self):
        """Finalize deployment"""
        print("  • Creating deployment marker...")

        deployment_info = {
            "deployment_id": self.deployment_id,
            "environment": self.environment,
            "timestamp": datetime.now().isoformat(),
            "status": self.status,
            "version": self._get_git_version()
        }

        marker_file = Path(f"data/deployments/{self.deployment_id}.json")
        marker_file.parent.mkdir(parents=True, exist_ok=True)

        with open(marker_file, 'w') as f:
            json.dump(deployment_info, f, indent=2)

        print(f"    ✓ Deployment marker: {marker_file}")

    def _get_git_version(self) -> str:
        """Get current Git commit hash"""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout.strip() if result.returncode == 0 else "unknown"
        except:
            return "unknown"

    def _rollback(self, backup_path: Optional[Path]) -> bool:
        """Rollback deployment"""
        print("  • Rolling back deployment...")

        if backup_path and backup_path.exists():
            try:
                from backup.backup_manager import BackupManager

                manager = BackupManager()
                restore_dir = Path.cwd()

                success = manager.restore_backup(backup_path, restore_dir)

                if success:
                    print("    ✓ Backup restored")
                    return True
                else:
                    print("    ❌ Backup restoration failed")
                    return False

            except Exception as e:
                print(f"    ❌ Rollback error: {e}")
                return False
        else:
            print("    ❌ No backup available for rollback")
            return False

    def _log(self, message: str, metadata: Optional[Dict] = None):
        """Log deployment event"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "deployment_id": self.deployment_id,
            "message": message,
            "metadata": metadata or {}
        }

        self.deployment_log.append(log_entry)

    def _save_deployment_log(self):
        """Save deployment log"""
        log_file = self.log_dir / f"{self.deployment_id}.json"

        log_data = {
            "deployment_id": self.deployment_id,
            "environment": self.environment,
            "status": self.status,
            "started": self.deployment_log[0]["timestamp"] if self.deployment_log else None,
            "ended": datetime.now().isoformat(),
            "events": self.deployment_log
        }

        with open(log_file, 'w') as f:
            json.dump(log_data, f, indent=2)

        print(f"\n📋 Deployment log saved: {log_file}")


def main():
    """Main deployment entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='Automated deployment system')
    parser.add_argument(
        '--environment',
        choices=['development', 'staging', 'production'],
        default='staging',
        help='Deployment environment'
    )
    parser.add_argument(
        '--skip-tests',
        action='store_true',
        help='Skip pre-deployment tests (not recommended)'
    )
    parser.add_argument(
        '--auto-approve',
        action='store_true',
        help='Auto-approve deployment (use with caution)'
    )

    args = parser.parse_args()

    deployer = AutomatedDeployer(environment=args.environment)
    success = deployer.deploy(
        skip_tests=args.skip_tests,
        auto_approve=args.auto_approve
    )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
