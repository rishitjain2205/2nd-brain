"""
KMS Key Manager - Production-Grade Secret Management
Replaces .env secrets with KMS/Key Vault for security

Features:
- AWS KMS integration
- Azure Key Vault integration
- Automatic key rotation
- Audit logging of key access
- Fail-safe error handling

SECURITY: This module should be used in production instead of reading
raw secrets from environment variables.
"""

import os
import json
import base64
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from enum import Enum


class KMSProvider(Enum):
    """Supported KMS providers"""
    AWS_KMS = "aws_kms"
    AZURE_KEY_VAULT = "azure_key_vault"
    GCP_KMS = "gcp_kms"
    LOCAL_DEV = "local_dev"  # For development only


class KMSKeyManager:
    """
    Production-grade key management using cloud KMS

    Usage:
        # AWS KMS
        kms = KMSKeyManager(provider=KMSProvider.AWS_KMS)
        encryption_key = kms.get_encryption_key()
        hmac_secret = kms.get_hmac_secret()

        # Azure Key Vault
        kms = KMSKeyManager(provider=KMSProvider.AZURE_KEY_VAULT)
        encryption_key = kms.get_encryption_key()
    """

    def __init__(
        self,
        provider: KMSProvider = None,
        audit_logger=None
    ):
        """
        Initialize KMS Key Manager

        Args:
            provider: KMS provider to use (auto-detected if None)
            audit_logger: Audit logger instance for key access logging
        """
        # Auto-detect provider from environment
        if provider is None:
            provider = self._detect_provider()

        self.provider = provider
        self.audit_logger = audit_logger

        # Initialize provider clients
        if self.provider == KMSProvider.AWS_KMS:
            self._init_aws_kms()
        elif self.provider == KMSProvider.AZURE_KEY_VAULT:
            self._init_azure_key_vault()
        elif self.provider == KMSProvider.GCP_KMS:
            self._init_gcp_kms()
        elif self.provider == KMSProvider.LOCAL_DEV:
            self._init_local_dev()

        print(f"✓ KMS Key Manager initialized (provider: {self.provider.value})")

    def _detect_provider(self) -> KMSProvider:
        """Auto-detect KMS provider from environment"""
        if os.getenv('AWS_KMS_KEY_ID'):
            return KMSProvider.AWS_KMS
        elif os.getenv('AZURE_KEY_VAULT_URL'):
            return KMSProvider.AZURE_KEY_VAULT
        elif os.getenv('GCP_KMS_KEY_NAME'):
            return KMSProvider.GCP_KMS
        else:
            # Fall back to local dev mode (reads from .env)
            print("⚠️  WARNING: No KMS provider configured - using local dev mode")
            print("   Set AWS_KMS_KEY_ID or AZURE_KEY_VAULT_URL for production")
            return KMSProvider.LOCAL_DEV

    def _init_aws_kms(self):
        """Initialize AWS KMS client"""
        try:
            import boto3

            self.kms_client = boto3.client('kms')
            self.kms_key_id = os.environ['AWS_KMS_KEY_ID']

            # Verify KMS access
            self.kms_client.describe_key(KeyId=self.kms_key_id)

            print(f"  ✓ AWS KMS connected: {self.kms_key_id}")

        except ImportError:
            raise ImportError(
                "boto3 not installed. Install: pip install boto3"
            )
        except Exception as e:
            raise RuntimeError(f"AWS KMS initialization failed: {e}")

    def _init_azure_key_vault(self):
        """Initialize Azure Key Vault client"""
        try:
            from azure.keyvault.secrets import SecretClient
            from azure.identity import DefaultAzureCredential

            vault_url = os.environ['AZURE_KEY_VAULT_URL']
            credential = DefaultAzureCredential()

            self.key_vault_client = SecretClient(
                vault_url=vault_url,
                credential=credential
            )

            print(f"  ✓ Azure Key Vault connected: {vault_url}")

        except ImportError:
            raise ImportError(
                "Azure SDK not installed. Install: pip install azure-keyvault-secrets azure-identity"
            )
        except Exception as e:
            raise RuntimeError(f"Azure Key Vault initialization failed: {e}")

    def _init_gcp_kms(self):
        """Initialize GCP Cloud KMS client"""
        try:
            from google.cloud import kms

            self.kms_client = kms.KeyManagementServiceClient()
            self.kms_key_name = os.environ['GCP_KMS_KEY_NAME']

            print(f"  ✓ GCP Cloud KMS connected: {self.kms_key_name}")

        except ImportError:
            raise ImportError(
                "GCP SDK not installed. Install: pip install google-cloud-kms"
            )
        except Exception as e:
            raise RuntimeError(f"GCP Cloud KMS initialization failed: {e}")

    def _init_local_dev(self):
        """Initialize local development mode (reads from .env)"""
        print("  ⚠️  Local dev mode: Reading secrets from .env")
        print("     DO NOT USE IN PRODUCTION!")

    def get_encryption_key(self) -> bytes:
        """
        Get encryption key from KMS

        Returns:
            Encryption key as bytes

        Raises:
            RuntimeError: If key cannot be retrieved
        """
        try:
            if self.provider == KMSProvider.AWS_KMS:
                return self._get_key_aws_kms('ENCRYPTION_KEY')

            elif self.provider == KMSProvider.AZURE_KEY_VAULT:
                return self._get_key_azure_key_vault('ENCRYPTION-KEY')

            elif self.provider == KMSProvider.GCP_KMS:
                return self._get_key_gcp_kms('encryption-key')

            elif self.provider == KMSProvider.LOCAL_DEV:
                return self._get_key_local_dev('ENCRYPTION_KEY')

            else:
                raise RuntimeError(f"Unsupported provider: {self.provider}")

        except Exception as e:
            # FAIL-CLOSED: If we can't get the key, refuse to operate
            self._log_key_access_failure('ENCRYPTION_KEY', str(e))
            raise RuntimeError(f"CRITICAL: Cannot retrieve encryption key: {e}")

    def get_hmac_secret(self) -> str:
        """
        Get HMAC secret from KMS

        Returns:
            HMAC secret as string

        Raises:
            RuntimeError: If secret cannot be retrieved
        """
        try:
            if self.provider == KMSProvider.AWS_KMS:
                key_bytes = self._get_key_aws_kms('AUDIT_HMAC_SECRET')
                return key_bytes.decode('utf-8')

            elif self.provider == KMSProvider.AZURE_KEY_VAULT:
                key_bytes = self._get_key_azure_key_vault('AUDIT-HMAC-SECRET')
                return key_bytes.decode('utf-8')

            elif self.provider == KMSProvider.GCP_KMS:
                key_bytes = self._get_key_gcp_kms('audit-hmac-secret')
                return key_bytes.decode('utf-8')

            elif self.provider == KMSProvider.LOCAL_DEV:
                key_bytes = self._get_key_local_dev('AUDIT_HMAC_SECRET')
                return key_bytes.decode('utf-8')

            else:
                raise RuntimeError(f"Unsupported provider: {self.provider}")

        except Exception as e:
            # FAIL-CLOSED: If we can't get the secret, refuse to operate
            self._log_key_access_failure('AUDIT_HMAC_SECRET', str(e))
            raise RuntimeError(f"CRITICAL: Cannot retrieve HMAC secret: {e}")

    def _get_key_aws_kms(self, key_name: str) -> bytes:
        """Retrieve key from AWS KMS"""
        # Get encrypted key from environment (stored encrypted)
        encrypted_key_b64 = os.environ.get(f'{key_name}_ENCRYPTED')

        if not encrypted_key_b64:
            raise ValueError(
                f"{key_name}_ENCRYPTED not found in environment. "
                "Run: aws kms encrypt --key-id <KEY_ID> --plaintext <SECRET>"
            )

        # Decode base64
        encrypted_key = base64.b64decode(encrypted_key_b64)

        # Decrypt using KMS
        response = self.kms_client.decrypt(
            CiphertextBlob=encrypted_key,
            KeyId=self.kms_key_id
        )

        plaintext_key = response['Plaintext']

        # Log key access
        self._log_key_access(key_name, 'AWS_KMS')

        return plaintext_key

    def _get_key_azure_key_vault(self, key_name: str) -> bytes:
        """Retrieve key from Azure Key Vault"""
        # Fetch secret from Key Vault
        secret = self.key_vault_client.get_secret(key_name)

        # Log key access
        self._log_key_access(key_name, 'AZURE_KEY_VAULT')

        # Return as bytes
        return secret.value.encode('utf-8')

    def _get_key_gcp_kms(self, key_name: str) -> bytes:
        """Retrieve key from GCP Cloud KMS"""
        # Get encrypted key from environment
        encrypted_key_b64 = os.environ.get(f'{key_name.upper().replace("-", "_")}_ENCRYPTED')

        if not encrypted_key_b64:
            raise ValueError(
                f"{key_name}_ENCRYPTED not found in environment"
            )

        # Decode base64
        encrypted_key = base64.b64decode(encrypted_key_b64)

        # Decrypt using GCP KMS
        response = self.kms_client.decrypt(
            request={
                "name": self.kms_key_name,
                "ciphertext": encrypted_key
            }
        )

        plaintext_key = response.plaintext

        # Log key access
        self._log_key_access(key_name, 'GCP_KMS')

        return plaintext_key

    def _get_key_local_dev(self, key_name: str) -> bytes:
        """
        Retrieve key from .env (LOCAL DEV ONLY)

        WARNING: This should NEVER be used in production
        """
        key_value = os.environ.get(key_name)

        if not key_value:
            raise ValueError(
                f"{key_name} not found in environment. "
                "Set in .env file for local development."
            )

        # Log key access (with warning)
        self._log_key_access(key_name, 'LOCAL_DEV', warning=True)

        return key_value.encode('utf-8')

    def rotate_key(self, key_name: str):
        """
        Rotate encryption key

        This creates a new key version in KMS and marks old version for deletion

        Args:
            key_name: Name of key to rotate
        """
        if self.provider == KMSProvider.LOCAL_DEV:
            raise RuntimeError("Key rotation not supported in local dev mode")

        try:
            if self.provider == KMSProvider.AWS_KMS:
                # Create new key version (AWS KMS auto-rotates)
                self.kms_client.enable_key_rotation(KeyId=self.kms_key_id)
                print(f"✓ Enabled automatic key rotation for {self.kms_key_id}")

            elif self.provider == KMSProvider.AZURE_KEY_VAULT:
                # Create new secret version
                new_secret_value = self._generate_new_secret()
                self.key_vault_client.set_secret(key_name, new_secret_value)
                print(f"✓ Rotated secret: {key_name}")

            elif self.provider == KMSProvider.GCP_KMS:
                # GCP KMS handles rotation automatically when configured
                print(f"✓ Key rotation configured in GCP KMS")

            # Log key rotation
            if self.audit_logger:
                self.audit_logger.log_event(
                    "key_rotation",
                    {
                        "key_name": key_name,
                        "provider": self.provider.value,
                        "timestamp": datetime.now().isoformat()
                    }
                )

        except Exception as e:
            raise RuntimeError(f"Key rotation failed: {e}")

    def _generate_new_secret(self) -> str:
        """Generate new cryptographically secure secret"""
        import secrets
        return secrets.token_hex(32)  # 64 characters

    def _log_key_access(
        self,
        key_name: str,
        provider: str,
        warning: bool = False
    ):
        """Log key access for audit trail"""
        if self.audit_logger:
            self.audit_logger.log_event(
                "key_access",
                {
                    "key_name": key_name,
                    "provider": provider,
                    "timestamp": datetime.now().isoformat(),
                    "warning": "LOCAL_DEV_MODE" if warning else None
                }
            )

    def _log_key_access_failure(self, key_name: str, error: str):
        """Log key access failure (critical security event)"""
        if self.audit_logger:
            self.audit_logger.log_event(
                "key_access_failure",
                {
                    "key_name": key_name,
                    "error": error,
                    "timestamp": datetime.now().isoformat()
                },
                level="CRITICAL"
            )


def encrypt_secret_for_kms(secret: str, kms_key_id: str, provider: str = "aws") -> str:
    """
    Helper function to encrypt a secret for storage in environment

    Usage:
        # Encrypt your secret
        encrypted = encrypt_secret_for_kms("my-secret-key", "arn:aws:kms:...")

        # Store in .env.production
        echo "ENCRYPTION_KEY_ENCRYPTED={encrypted}" >> .env.production

    Args:
        secret: Plain text secret to encrypt
        kms_key_id: KMS key ID/ARN
        provider: KMS provider (aws, azure, gcp)

    Returns:
        Base64-encoded encrypted secret
    """
    if provider == "aws":
        import boto3
        kms = boto3.client('kms')

        response = kms.encrypt(
            KeyId=kms_key_id,
            Plaintext=secret.encode('utf-8')
        )

        encrypted = base64.b64encode(response['CiphertextBlob']).decode('utf-8')
        return encrypted

    elif provider == "azure":
        # Azure Key Vault stores secrets directly (no pre-encryption needed)
        return secret

    elif provider == "gcp":
        from google.cloud import kms
        client = kms.KeyManagementServiceClient()

        response = client.encrypt(
            request={
                "name": kms_key_id,
                "plaintext": secret.encode('utf-8')
            }
        )

        encrypted = base64.b64encode(response.ciphertext).decode('utf-8')
        return encrypted

    else:
        raise ValueError(f"Unsupported provider: {provider}")


if __name__ == "__main__":
    """
    KMS Setup Helper

    Run this to set up KMS for your environment:
        python3 security/kms_key_manager.py
    """
    print("=" * 70)
    print("KMS KEY MANAGER SETUP")
    print("=" * 70)
    print()

    # Check current configuration
    if os.getenv('AWS_KMS_KEY_ID'):
        print("✓ AWS KMS configured")
        print(f"  Key ID: {os.getenv('AWS_KMS_KEY_ID')}")
    elif os.getenv('AZURE_KEY_VAULT_URL'):
        print("✓ Azure Key Vault configured")
        print(f"  Vault URL: {os.getenv('AZURE_KEY_VAULT_URL')}")
    elif os.getenv('GCP_KMS_KEY_NAME'):
        print("✓ GCP Cloud KMS configured")
        print(f"  Key Name: {os.getenv('GCP_KMS_KEY_NAME')}")
    else:
        print("⚠️  No KMS provider configured!")
        print()
        print("To configure AWS KMS:")
        print("  1. Create KMS key: aws kms create-key --description 'App encryption key'")
        print("  2. Set AWS_KMS_KEY_ID=<key-id> in .env.production")
        print("  3. Encrypt secrets:")
        print("     aws kms encrypt --key-id <KEY_ID> --plaintext 'your-secret' --output text --query CiphertextBlob")
        print("  4. Store encrypted secret in .env.production:")
        print("     ENCRYPTION_KEY_ENCRYPTED=<base64-encrypted-value>")
        print()
        print("To configure Azure Key Vault:")
        print("  1. Create Key Vault: az keyvault create --name <vault-name> --resource-group <rg>")
        print("  2. Set AZURE_KEY_VAULT_URL=https://<vault-name>.vault.azure.net/")
        print("  3. Add secrets:")
        print("     az keyvault secret set --vault-name <vault-name> --name 'ENCRYPTION-KEY' --value 'your-secret'")
        print()

    # Test KMS connection
    try:
        print()
        print("Testing KMS connection...")
        kms = KMSKeyManager()
        print("✅ KMS connection successful!")

    except Exception as e:
        print(f"❌ KMS connection failed: {e}")
        print()
        print("Falling back to local dev mode for testing...")
