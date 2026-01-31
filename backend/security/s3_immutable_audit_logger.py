"""
S3 Immutable Audit Logger with Object Lock (WORM)

CRITICAL SECURITY FIX:
- Before: Audit logs only stored locally (can be deleted by attacker with root access)
- After: Logs streamed to S3 with Object Lock (Write Once Read Many - immutable)

Features:
- AWS S3 Object Lock (GOVERNANCE/COMPLIANCE modes)
- Azure Blob Immutable Storage
- Real-time log streaming
- Automatic retention policies
- Tamper-proof storage
- Compliance-ready (SOC2, HIPAA, GDPR)
"""

import os
import json
import gzip
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from dataclasses import dataclass
from enum import Enum


class CloudProvider(Enum):
    """Supported cloud providers"""
    AWS_S3 = "aws_s3"
    AZURE_BLOB = "azure_blob"
    GCP_STORAGE = "gcp_storage"


class RetentionMode(Enum):
    """Object Lock retention modes"""
    GOVERNANCE = "GOVERNANCE"  # Can be overridden with special permissions
    COMPLIANCE = "COMPLIANCE"  # Cannot be overridden (recommended)


@dataclass
class ImmutableStorageConfig:
    """Immutable storage configuration"""
    # Provider
    provider: CloudProvider = CloudProvider.AWS_S3

    # AWS S3
    s3_bucket: Optional[str] = None
    s3_region: str = "us-east-1"
    s3_kms_key_id: Optional[str] = None  # For encryption at rest

    # Azure Blob
    azure_storage_account: Optional[str] = None
    azure_container: Optional[str] = None

    # GCP Storage
    gcp_bucket: Optional[str] = None

    # Retention settings
    retention_days: int = 2555  # 7 years (common for compliance)
    retention_mode: RetentionMode = RetentionMode.COMPLIANCE

    # Streaming settings
    stream_realtime: bool = True  # Stream immediately after each log entry
    batch_size: int = 100  # Batch uploads if stream_realtime=False
    compression: bool = True  # Gzip compression before upload

    # Encryption
    encryption_enabled: bool = True


class S3ImmutableAuditLogger:
    """
    Immutable audit log storage with S3 Object Lock

    Usage:
        # Initialize
        config = ImmutableStorageConfig(
            s3_bucket="audit-logs-company",
            retention_days=2555,  # 7 years
            retention_mode=RetentionMode.COMPLIANCE
        )

        logger = S3ImmutableAuditLogger(config)

        # Upload log entry
        logger.upload_log_entry({
            "timestamp": "2025-12-08T10:15:30Z",
            "event": "user_login",
            "user_id": "user123"
        })

        # Upload daily log file
        logger.upload_daily_log("data/audit_logs/audit_2025-12-08.jsonl")
    """

    def __init__(
        self,
        config: Optional[ImmutableStorageConfig] = None,
        audit_logger=None
    ):
        """
        Initialize S3 immutable audit logger

        Args:
            config: Immutable storage configuration
            audit_logger: Audit logger for tracking uploads
        """
        if config is None:
            config = ImmutableStorageConfig(
                s3_bucket=os.getenv("S3_AUDIT_BUCKET"),
                retention_days=int(os.getenv("AUDIT_RETENTION_DAYS", "2555"))
            )

        self.config = config
        self.audit_logger = audit_logger

        # Initialize cloud storage client
        if self.config.provider == CloudProvider.AWS_S3:
            self._init_s3()
        elif self.config.provider == CloudProvider.AZURE_BLOB:
            self._init_azure_blob()
        elif self.config.provider == CloudProvider.GCP_STORAGE:
            self._init_gcp_storage()

    def _init_s3(self):
        """Initialize AWS S3 client with Object Lock"""
        try:
            import boto3

            self.s3_client = boto3.client('s3', region_name=self.config.s3_region)

            # Verify bucket exists and has Object Lock enabled
            try:
                response = self.s3_client.get_object_lock_configuration(
                    Bucket=self.config.s3_bucket
                )

                if response['ObjectLockConfiguration']['ObjectLockEnabled'] == 'Enabled':
                    print(f"✅ S3 Immutable Audit Logger initialized")
                    print(f"   Bucket: {self.config.s3_bucket}")
                    print(f"   Object Lock: ENABLED")
                    print(f"   Retention: {self.config.retention_days} days ({self.config.retention_mode.value})")
                else:
                    print(f"⚠️  WARNING: Object Lock not enabled on bucket {self.config.s3_bucket}")
                    print("   Logs will not be immutable!")

            except Exception as e:
                print(f"⚠️  WARNING: Cannot verify Object Lock: {e}")
                print("   Bucket may not have Object Lock enabled")

        except ImportError:
            raise ImportError("boto3 not installed. Run: pip install boto3")
        except Exception as e:
            raise RuntimeError(f"S3 initialization failed: {e}")

    def _init_azure_blob(self):
        """Initialize Azure Blob Storage with Immutable Storage"""
        try:
            from azure.storage.blob import BlobServiceClient
            from azure.identity import DefaultAzureCredential

            credential = DefaultAzureCredential()

            self.blob_service_client = BlobServiceClient(
                account_url=f"https://{self.config.azure_storage_account}.blob.core.windows.net",
                credential=credential
            )

            # Get container client
            self.container_client = self.blob_service_client.get_container_client(
                self.config.azure_container
            )

            print(f"✅ Azure Immutable Audit Logger initialized")
            print(f"   Account: {self.config.azure_storage_account}")
            print(f"   Container: {self.config.azure_container}")
            print(f"   Retention: {self.config.retention_days} days")

        except ImportError:
            raise ImportError(
                "Azure SDK not installed. Run: pip install azure-storage-blob azure-identity"
            )
        except Exception as e:
            raise RuntimeError(f"Azure Blob initialization failed: {e}")

    def _init_gcp_storage(self):
        """Initialize GCP Cloud Storage with Retention Policy"""
        try:
            from google.cloud import storage

            self.storage_client = storage.Client()
            self.bucket = self.storage_client.bucket(self.config.gcp_bucket)

            # Check retention policy
            bucket_info = self.storage_client.get_bucket(self.config.gcp_bucket)

            if bucket_info.retention_policy_effective_time:
                print(f"✅ GCP Immutable Audit Logger initialized")
                print(f"   Bucket: {self.config.gcp_bucket}")
                print(f"   Retention Policy: LOCKED")
            else:
                print(f"⚠️  WARNING: No retention policy on bucket {self.config.gcp_bucket}")

        except ImportError:
            raise ImportError("GCP SDK not installed. Run: pip install google-cloud-storage")
        except Exception as e:
            raise RuntimeError(f"GCP Storage initialization failed: {e}")

    def upload_log_entry(self, log_entry: Dict[str, Any]) -> bool:
        """
        Upload a single log entry to immutable storage

        Args:
            log_entry: Log entry as dictionary

        Returns:
            True if uploaded successfully
        """
        try:
            # Generate key based on timestamp
            timestamp = log_entry.get('timestamp', datetime.now().isoformat())
            date = timestamp.split('T')[0]  # Extract date (YYYY-MM-DD)
            entry_id = log_entry.get('sequence_number', 0)

            key = f"logs/{date}/audit_{entry_id}.json"

            # Serialize log entry
            content = json.dumps(log_entry, indent=2)

            # Compress if enabled
            if self.config.compression:
                import gzip
                content = gzip.compress(content.encode('utf-8'))
                key += '.gz'
            else:
                content = content.encode('utf-8')

            # Upload to cloud storage
            if self.config.provider == CloudProvider.AWS_S3:
                return self._upload_to_s3(key, content)
            elif self.config.provider == CloudProvider.AZURE_BLOB:
                return self._upload_to_azure(key, content)
            elif self.config.provider == CloudProvider.GCP_STORAGE:
                return self._upload_to_gcp(key, content)

        except Exception as e:
            print(f"❌ Failed to upload log entry: {e}")
            if self.audit_logger:
                self.audit_logger.log_event(
                    "immutable_log_upload_failure",
                    {"error": str(e)},
                    level="CRITICAL"
                )
            return False

    def upload_daily_log(self, local_file_path: str) -> bool:
        """
        Upload entire daily log file to immutable storage

        Args:
            local_file_path: Path to local log file

        Returns:
            True if uploaded successfully
        """
        try:
            # Extract date from filename (e.g., audit_2025-12-08.jsonl)
            filename = os.path.basename(local_file_path)
            date = filename.split('_')[1].split('.')[0]  # Extract YYYY-MM-DD

            key = f"logs/{date}/{filename}"

            # Read file content
            with open(local_file_path, 'rb') as f:
                content = f.read()

            # Compress if enabled
            if self.config.compression:
                content = gzip.compress(content)
                key += '.gz'

            # Upload to cloud storage
            if self.config.provider == CloudProvider.AWS_S3:
                return self._upload_to_s3(key, content)
            elif self.config.provider == CloudProvider.AZURE_BLOB:
                return self._upload_to_azure(key, content)
            elif self.config.provider == CloudProvider.GCP_STORAGE:
                return self._upload_to_gcp(key, content)

        except Exception as e:
            print(f"❌ Failed to upload daily log: {e}")
            if self.audit_logger:
                self.audit_logger.log_event(
                    "daily_log_upload_failure",
                    {"file": local_file_path, "error": str(e)},
                    level="CRITICAL"
                )
            return False

    def _upload_to_s3(self, key: str, content: bytes) -> bool:
        """Upload to S3 with Object Lock"""
        try:
            # Calculate retention date
            retention_date = datetime.now() + timedelta(days=self.config.retention_days)

            # Upload with Object Lock
            self.s3_client.put_object(
                Bucket=self.config.s3_bucket,
                Key=key,
                Body=content,
                ObjectLockMode=self.config.retention_mode.value,
                ObjectLockRetainUntilDate=retention_date,
                ServerSideEncryption='aws:kms' if self.config.encryption_enabled else 'AES256',
                SSEKMSKeyId=self.config.s3_kms_key_id if self.config.s3_kms_key_id else None
            )

            print(f"✅ Uploaded to S3: s3://{self.config.s3_bucket}/{key}")
            print(f"   Object Lock: {self.config.retention_mode.value} until {retention_date.date()}")

            if self.audit_logger:
                self.audit_logger.log_event(
                    "immutable_log_uploaded",
                    {
                        "key": key,
                        "provider": "s3",
                        "retention_date": retention_date.isoformat()
                    }
                )

            return True

        except Exception as e:
            print(f"❌ S3 upload failed: {e}")
            return False

    def _upload_to_azure(self, key: str, content: bytes) -> bool:
        """Upload to Azure Blob with Immutable Storage"""
        try:
            # Get blob client
            blob_client = self.container_client.get_blob_client(key)

            # Upload blob
            blob_client.upload_blob(
                content,
                overwrite=False,  # Prevent overwrites
                immutability_policy={
                    "expiry_time": datetime.now() + timedelta(days=self.config.retention_days),
                    "policy_mode": "Unlocked" if self.config.retention_mode == RetentionMode.GOVERNANCE else "Locked"
                }
            )

            print(f"✅ Uploaded to Azure Blob: {key}")

            if self.audit_logger:
                self.audit_logger.log_event(
                    "immutable_log_uploaded",
                    {"key": key, "provider": "azure"}
                )

            return True

        except Exception as e:
            print(f"❌ Azure Blob upload failed: {e}")
            return False

    def _upload_to_gcp(self, key: str, content: bytes) -> bool:
        """Upload to GCP Storage with Retention Policy"""
        try:
            # Get blob
            blob = self.bucket.blob(key)

            # Upload with event-based hold (immutable)
            blob.upload_from_string(
                content,
                content_type='application/json'
            )

            # Apply event-based hold (makes it immutable until released)
            blob.event_based_hold = True
            blob.patch()

            print(f"✅ Uploaded to GCP Storage: gs://{self.config.gcp_bucket}/{key}")

            if self.audit_logger:
                self.audit_logger.log_event(
                    "immutable_log_uploaded",
                    {"key": key, "provider": "gcp"}
                )

            return True

        except Exception as e:
            print(f"❌ GCP Storage upload failed: {e}")
            return False

    def verify_log_integrity(self, key: str) -> Dict[str, Any]:
        """
        Verify that a log file is truly immutable

        Args:
            key: Object key to verify

        Returns:
            Dictionary with integrity status
        """
        try:
            if self.config.provider == CloudProvider.AWS_S3:
                # Check Object Lock status
                response = self.s3_client.get_object_retention(
                    Bucket=self.config.s3_bucket,
                    Key=key
                )

                return {
                    "immutable": True,
                    "mode": response['Retention']['Mode'],
                    "retain_until": response['Retention']['RetainUntilDate'].isoformat()
                }

            elif self.config.provider == CloudProvider.AZURE_BLOB:
                blob_client = self.container_client.get_blob_client(key)
                properties = blob_client.get_blob_properties()

                return {
                    "immutable": properties.immutability_policy is not None,
                    "policy": properties.immutability_policy
                }

            elif self.config.provider == CloudProvider.GCP_STORAGE:
                blob = self.bucket.blob(key)
                blob.reload()

                return {
                    "immutable": blob.event_based_hold or blob.temporary_hold,
                    "event_hold": blob.event_based_hold,
                    "temporary_hold": blob.temporary_hold
                }

        except Exception as e:
            return {
                "immutable": False,
                "error": str(e)
            }


if __name__ == "__main__":
    """Setup guide for immutable audit logging"""
    print("=" * 70)
    print("S3 IMMUTABLE AUDIT LOGGER - SETUP GUIDE")
    print("=" * 70)
    print()

    print("1. CREATE S3 BUCKET WITH OBJECT LOCK (AWS):")
    print("   # Create bucket with Object Lock")
    print("   aws s3api create-bucket \\")
    print("     --bucket audit-logs-your-company \\")
    print("     --region us-east-1 \\")
    print("     --object-lock-enabled-for-bucket")
    print()
    print("   # Configure default retention")
    print("   aws s3api put-object-lock-configuration \\")
    print("     --bucket audit-logs-your-company \\")
    print("     --object-lock-configuration '{")
    print('       "ObjectLockEnabled": "Enabled",')
    print('       "Rule": {')
    print('         "DefaultRetention": {')
    print('           "Mode": "COMPLIANCE",')
    print('           "Days": 2555')
    print("         }")
    print("       }")
    print("     }'")
    print()

    print("2. SET ENVIRONMENT VARIABLES:")
    print("   export S3_AUDIT_BUCKET=audit-logs-your-company")
    print("   export AUDIT_RETENTION_DAYS=2555")
    print()

    print("3. TEST UPLOAD:")
    try:
        config = ImmutableStorageConfig(
            s3_bucket=os.getenv("S3_AUDIT_BUCKET"),
            retention_days=2555,
            retention_mode=RetentionMode.COMPLIANCE
        )

        logger = S3ImmutableAuditLogger(config)

        # Test upload
        test_entry = {
            "timestamp": datetime.now().isoformat(),
            "event": "test_upload",
            "message": "Testing immutable audit log"
        }

        success = logger.upload_log_entry(test_entry)

        if success:
            print("   ✅ Test upload successful!")
        else:
            print("   ❌ Test upload failed")

    except Exception as e:
        print(f"   ❌ Error: {e}")
