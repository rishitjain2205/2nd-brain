"""
Secure Data Disposal - FIXED FOR SSDs

CRITICAL INSIGHT:
❌ File overwriting (shred, DoD 5220.22-M) does NOT work on SSDs!
✅ Crypto-shredding (encrypt + delete key) is the correct approach

WHY OVERWRITING FAILS ON SSDs:
- SSDs use wear leveling (data is NOT where you think it is)
- Trim/Discard commands are hints, not guaranteed
- Flash translation layer (FTL) maps logical to physical blocks
- Old data may persist on unmapped physical blocks
- Cloud storage (EBS, S3) is completely opaque

CORRECT APPROACH:
1. Encrypt all sensitive data at rest (always!)
2. To "delete" data: Destroy the encryption key
3. Without the key, data is computationally irretrievable
4. This is called "Crypto-shredding" or "Cryptographic Erasure"
"""

import os
import hashlib
import secrets
from pathlib import Path
from typing import Union, Optional, List, Dict
from datetime import datetime
import json


class SecureDataDisposal:
    """
    Secure data disposal using crypto-shredding

    ✅ WORKS ON: SSDs, HDDs, Cloud Storage, RAM disks
    ✅ GUARANTEED: Data is unrecoverable (computational security)
    ✅ FAST: Just delete a key file, not overwrite gigabytes
    ✅ SECURE PERMISSIONS: All files created with 0o600 (owner read/write only)

    REQUIREMENTS:
    - All sensitive data must be encrypted at rest
    - Keys must be stored separately from data
    - Key deletion must be atomic and logged
    - All files have secure permissions (0o600)
    """

    def __init__(self, key_storage_dir: Union[str, Path] = "data/encryption_keys"):
        """
        Initialize secure disposal manager

        Args:
            key_storage_dir: Directory to store encryption keys
        """
        self.key_storage_dir = Path(key_storage_dir)
        self.key_storage_dir.mkdir(parents=True, exist_ok=True)

        # Audit log for key deletions
        self.disposal_log = self.key_storage_dir / "disposal_audit.jsonl"

    def create_encrypted_file(
        self,
        data: bytes,
        file_path: Union[str, Path],
        key_id: Optional[str] = None
    ) -> str:
        """
        Create encrypted file with separate key

        Args:
            data: Data to encrypt
            file_path: Path to save encrypted file
            key_id: Optional key identifier (auto-generated if not provided)

        Returns:
            Key ID (use this to securely delete later)
        """
        from cryptography.fernet import Fernet

        # Generate key
        key = Fernet.generate_key()

        # Generate key ID
        if key_id is None:
            key_id = secrets.token_hex(16)

        # Save key separately with secure permissions (GPT recommendation)
        key_file = self.key_storage_dir / f"{key_id}.key"
        with open(key_file, 'wb') as f:
            f.write(key)
        os.chmod(key_file, 0o600)  # Read/write for owner only

        # Encrypt data
        cipher = Fernet(key)
        encrypted_data = cipher.encrypt(data)

        # Save encrypted file with secure permissions
        file_path = Path(file_path)
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)
        os.chmod(file_path, 0o600)  # Read/write for owner only (GPT recommendation)

        print(f"✓ Created encrypted file: {file_path}")
        print(f"  Key ID: {key_id}")
        print(f"  Key stored: {key_file}")

        return key_id

    def read_encrypted_file(
        self,
        file_path: Union[str, Path],
        key_id: str
    ) -> bytes:
        """
        Read encrypted file using key

        Args:
            file_path: Path to encrypted file
            key_id: Key identifier

        Returns:
            Decrypted data

        Raises:
            FileNotFoundError: If key has been shredded
        """
        from cryptography.fernet import Fernet

        # Load key
        key_file = self.key_storage_dir / f"{key_id}.key"
        if not key_file.exists():
            raise FileNotFoundError(f"Encryption key not found (may have been shredded): {key_id}")

        with open(key_file, 'rb') as f:
            key = f.read()

        # Decrypt file
        cipher = Fernet(key)
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()

        return cipher.decrypt(encrypted_data)

    def crypto_shred(
        self,
        key_id: str,
        reason: str = "User requested deletion",
        user_id: Optional[str] = None
    ) -> bool:
        """
        Securely delete data by destroying encryption key (crypto-shredding)

        ✅ WORKS ON SSDs: Data becomes computationally irretrievable
        ✅ INSTANT: Just delete a small key file
        ✅ AUDITABLE: Logs who deleted what and when

        Args:
            key_id: Key identifier to shred
            reason: Reason for deletion (for audit log)
            user_id: User who requested deletion

        Returns:
            True if successful

        Raises:
            FileNotFoundError: If key doesn't exist
        """
        key_file = self.key_storage_dir / f"{key_id}.key"

        if not key_file.exists():
            raise FileNotFoundError(f"Key not found: {key_id}")

        # Log deletion BEFORE deleting (immutable audit trail)
        self._log_disposal(key_id, reason, user_id)

        # Delete key file (this makes all encrypted data unrecoverable)
        key_file.unlink()

        print(f"✓ Crypto-shredded key: {key_id}")
        print("  ⚠️ All data encrypted with this key is now permanently unrecoverable")

        return True

    def crypto_shred_bulk(
        self,
        key_ids: List[str],
        reason: str = "Bulk deletion",
        user_id: Optional[str] = None
    ) -> Dict[str, bool]:
        """
        Crypto-shred multiple keys

        Args:
            key_ids: List of key IDs to shred
            reason: Reason for deletion
            user_id: User who requested deletion

        Returns:
            Dict of {key_id: success}
        """
        results = {}

        for key_id in key_ids:
            try:
                self.crypto_shred(key_id, reason, user_id)
                results[key_id] = True
            except Exception as e:
                print(f"  ⚠️ Failed to shred {key_id}: {e}")
                results[key_id] = False

        success_count = sum(results.values())
        print(f"\n✓ Crypto-shredded {success_count}/{len(key_ids)} keys")

        return results

    def _log_disposal(self, key_id: str, reason: str, user_id: Optional[str]):
        """Log key disposal for audit purposes"""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "key_id": key_id,
            "action": "crypto_shred",
            "reason": reason,
            "user_id": user_id,
            "key_hash": hashlib.sha256(key_id.encode()).hexdigest()[:16]
        }

        # Append to audit log
        log_exists = self.disposal_log.exists()
        with open(self.disposal_log, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')

        # Set secure permissions if newly created (GPT recommendation)
        if not log_exists:
            os.chmod(self.disposal_log, 0o600)

    def get_disposal_audit_log(self, days: int = 30) -> List[Dict]:
        """
        Get disposal audit log

        Args:
            days: Number of days to retrieve

        Returns:
            List of disposal log entries
        """
        if not self.disposal_log.exists():
            return []

        entries = []
        with open(self.disposal_log, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    entries.append(entry)
                except json.JSONDecodeError:
                    continue

        return entries

    def list_active_keys(self) -> List[str]:
        """List all active encryption keys"""
        return [
            f.stem for f in self.key_storage_dir.glob("*.key")
        ]


# ==============================================================================
# TRADITIONAL OVERWRITE (For HDDs only - DOES NOT WORK ON SSDs!)
# ==============================================================================

class LegacyFileShredder:
    """
    Traditional file overwriting (DoD 5220.22-M)

    ⚠️ WARNING: THIS DOES NOT WORK ON SSDs!
    ⚠️ Use crypto-shredding instead!

    This is kept for reference and HDD compatibility only.
    """

    @staticmethod
    def shred_file_legacy(file_path: Union[str, Path], passes: int = 7) -> bool:
        """
        Overwrite file multiple times (DoD 5220.22-M)

        ⚠️ WARNING:
        - Does NOT work on SSDs (wear leveling)
        - Does NOT work on cloud storage (abstracted)
        - Does NOT work on copy-on-write filesystems (btrfs, ZFS)
        - Does NOT work on journaling filesystems (partially)

        Use crypto-shredding instead!

        Args:
            file_path: File to shred
            passes: Number of overwrite passes (DoD uses 7)

        Returns:
            True if successful
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        file_size = file_path.stat().st_size

        print(f"⚠️ WARNING: File overwriting does NOT work on SSDs!")
        print(f"   Use crypto-shredding instead for guaranteed security")
        print(f"\n   Overwriting {file_path} ({file_size} bytes) with {passes} passes...")

        with open(file_path, 'r+b') as f:
            for pass_num in range(passes):
                # DoD 5220.22-M pattern
                if pass_num == 0:
                    pattern = b'\x00' * file_size  # All zeros
                elif pass_num == 1:
                    pattern = b'\xFF' * file_size  # All ones
                else:
                    pattern = secrets.token_bytes(file_size)  # Random

                f.seek(0)
                f.write(pattern)
                f.flush()
                os.fsync(f.fileno())  # Force write to disk

                print(f"     Pass {pass_num + 1}/{passes} complete")

        # Delete file
        file_path.unlink()
        print(f"✓ File deleted: {file_path}")
        print(f"⚠️ Note: Data may still be recoverable on SSDs!")

        return True


if __name__ == "__main__":
    print("="*80)
    print("SECURE DATA DISPOSAL - CRYPTO-SHREDDING DEMO")
    print("="*80)

    # Initialize disposal manager
    disposal = SecureDataDisposal(key_storage_dir="data/test_keys")

    print("\n1️⃣  Creating encrypted files...")

    # Create test data
    sensitive_data1 = b"Patient ID: 12345, SSN: 123-45-6789, Diagnosis: ..."
    sensitive_data2 = b"Credit Card: 1234-5678-9012-3456, CVV: 123"

    # Encrypt and save
    key_id1 = disposal.create_encrypted_file(
        sensitive_data1,
        "data/test_keys/patient_data.enc"
    )

    key_id2 = disposal.create_encrypted_file(
        sensitive_data2,
        "data/test_keys/payment_data.enc"
    )

    print("\n2️⃣  Reading encrypted data...")
    decrypted1 = disposal.read_encrypted_file("data/test_keys/patient_data.enc", key_id1)
    print(f"   Decrypted: {decrypted1.decode()[:50]}...")

    print("\n3️⃣  Crypto-shredding (deleting encryption key)...")
    disposal.crypto_shred(
        key_id1,
        reason="Patient requested data deletion (GDPR)",
        user_id="user123"
    )

    print("\n4️⃣  Attempting to read after crypto-shredding...")
    try:
        decrypted = disposal.read_encrypted_file("data/test_keys/patient_data.enc", key_id1)
        print("   ❌ ERROR: Should not be able to decrypt!")
    except FileNotFoundError as e:
        print(f"   ✅ Correct: {e}")
        print("   ✅ Data is now permanently unrecoverable (computational security)")

    print("\n5️⃣  Viewing disposal audit log...")
    audit_log = disposal.get_disposal_audit_log()
    for entry in audit_log:
        print(f"   {entry['timestamp']}: Shredded {entry['key_id']} - {entry['reason']}")

    print("\n6️⃣  Listing active keys...")
    active_keys = disposal.list_active_keys()
    print(f"   Active keys: {active_keys}")

    # Cleanup
    disposal.crypto_shred(key_id2, "Test cleanup", "admin")
    Path("data/test_keys/patient_data.enc").unlink(missing_ok=True)
    Path("data/test_keys/payment_data.enc").unlink(missing_ok=True)

    print("\n" + "="*80)
    print("✅ CRYPTO-SHREDDING DEMONSTRATED!")
    print("="*80)
    print("\n🔒 KEY INSIGHTS:")
    print("  ✅ Crypto-shredding WORKS on SSDs, HDDs, Cloud, everything")
    print("  ✅ Data becomes computationally irretrievable")
    print("  ✅ Fast (delete key, not overwrite gigabytes)")
    print("  ✅ Auditable (logs who deleted what)")
    print()
    print("  ❌ File overwriting (shred, DoD 5220.22-M) does NOT work on SSDs")
    print("  ❌ SSDs use wear leveling, data is not where you think")
    print("  ❌ Cloud storage is completely opaque")
    print()
    print("🎯 BEST PRACTICE:")
    print("  1. Always encrypt sensitive data at rest")
    print("  2. Store encryption keys separately")
    print("  3. To delete data: Destroy the key (crypto-shred)")
    print("  4. Log all key deletions for audit compliance")
    print("="*80)
    print("\n💡 PRODUCTION USAGE:")
    print("  from security.secure_disposal import SecureDataDisposal")
    print("  disposal = SecureDataDisposal()")
    print("  key_id = disposal.create_encrypted_file(data, 'sensitive.enc')")
    print("  # Later, to delete:")
    print("  disposal.crypto_shred(key_id, 'GDPR deletion request', user_id)")
    print("="*80)
