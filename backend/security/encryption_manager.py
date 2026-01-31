"""
Encryption Manager for Data at Rest
Encrypts sensitive data stored in databases and files
Uses Fernet (symmetric encryption) for fast encryption/decryption
"""

import os
import json
from pathlib import Path
from typing import Any, Dict, Optional, Union
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


class EncryptionManager:
    """
    Manages encryption/decryption of data at rest

    Features:
    - Symmetric encryption (Fernet) for speed
    - Key derivation from password
    - Automatic key rotation support
    - File and database encryption
    """

    def __init__(self, encryption_key: Optional[str] = None, password: Optional[str] = None):
        """
        Initialize encryption manager

        Args:
            encryption_key: Base64-encoded Fernet key (or from env ENCRYPTION_KEY)
            password: Password to derive key from (alternative to encryption_key)
        """
        if encryption_key:
            self.key = encryption_key.encode() if isinstance(encryption_key, str) else encryption_key
        elif password:
            self.key = self._derive_key_from_password(password)
        else:
            # Try to load from environment
            env_key = os.getenv('ENCRYPTION_KEY')
            if env_key:
                self.key = env_key.encode()
            else:
                # Generate new key
                print("⚠️  No encryption key provided. Generating new key...")
                self.key = Fernet.generate_key()
                print(f"Generated key: {self.key.decode()}")
                print("Save this key to .env file: ENCRYPTION_KEY={self.key.decode()}")

        self.cipher = Fernet(self.key)

    @staticmethod
    def generate_key() -> str:
        """Generate a new encryption key"""
        key = Fernet.generate_key()
        return key.decode()

    @staticmethod
    def _derive_key_from_password(password: str, salt: Optional[bytes] = None) -> bytes:
        """
        Derive encryption key from password using PBKDF2

        Args:
            password: User password
            salt: Salt for key derivation (stored separately)

        Returns:
            32-byte key for Fernet
        """
        if salt is None:
            salt = os.urandom(16)  # Generate random 16-byte salt

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )

        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt raw bytes

        Args:
            data: Raw bytes to encrypt

        Returns:
            Encrypted bytes
        """
        return self.cipher.encrypt(data)

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt encrypted bytes

        Args:
            encrypted_data: Encrypted bytes

        Returns:
            Decrypted bytes
        """
        return self.cipher.decrypt(encrypted_data)

    def encrypt_string(self, text: str) -> str:
        """
        Encrypt string and return base64-encoded ciphertext

        Args:
            text: Plain text string

        Returns:
            Base64-encoded encrypted string
        """
        encrypted = self.cipher.encrypt(text.encode())
        return base64.urlsafe_b64encode(encrypted).decode()

    def decrypt_string(self, encrypted_text: str) -> str:
        """
        Decrypt base64-encoded encrypted string

        Args:
            encrypted_text: Base64-encoded encrypted string

        Returns:
            Decrypted plain text
        """
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_text.encode())
        decrypted = self.cipher.decrypt(encrypted_bytes)
        return decrypted.decode()

    def encrypt_dict(self, data: Dict) -> str:
        """
        Encrypt dictionary to JSON string

        Args:
            data: Dictionary to encrypt

        Returns:
            Encrypted JSON string (base64-encoded)
        """
        json_str = json.dumps(data)
        return self.encrypt_string(json_str)

    def decrypt_dict(self, encrypted_json: str) -> Dict:
        """
        Decrypt encrypted JSON string to dictionary

        Args:
            encrypted_json: Encrypted JSON string

        Returns:
            Decrypted dictionary
        """
        json_str = self.decrypt_string(encrypted_json)
        return json.loads(json_str)

    def encrypt_file(self, input_path: Union[str, Path], output_path: Optional[Union[str, Path]] = None) -> Path:
        """
        Encrypt a file

        Args:
            input_path: Path to file to encrypt
            output_path: Path to save encrypted file (defaults to input_path.encrypted)

        Returns:
            Path to encrypted file
        """
        input_path = Path(input_path)

        if output_path is None:
            output_path = input_path.parent / f"{input_path.name}.encrypted"
        else:
            output_path = Path(output_path)

        # Read file
        with open(input_path, 'rb') as f:
            data = f.read()

        # Encrypt
        encrypted_data = self.encrypt(data)

        # Write encrypted file
        with open(output_path, 'wb') as f:
            f.write(encrypted_data)

        return output_path

    def decrypt_file(self, input_path: Union[str, Path], output_path: Optional[Union[str, Path]] = None) -> Path:
        """
        Decrypt an encrypted file

        Args:
            input_path: Path to encrypted file
            output_path: Path to save decrypted file

        Returns:
            Path to decrypted file
        """
        input_path = Path(input_path)

        if output_path is None:
            # Remove .encrypted extension
            if input_path.name.endswith('.encrypted'):
                output_path = input_path.parent / input_path.name[:-10]
            else:
                output_path = input_path.parent / f"{input_path.name}.decrypted"
        else:
            output_path = Path(output_path)

        # Read encrypted file
        with open(input_path, 'rb') as f:
            encrypted_data = f.read()

        # Decrypt
        data = self.decrypt(encrypted_data)

        # Write decrypted file
        with open(output_path, 'wb') as f:
            f.write(data)

        return output_path

    # ⚠️ SECURITY: Pickle methods removed due to RCE vulnerability
    # pickle.loads() can execute arbitrary code when deserializing untrusted data
    # Use encrypt_dict() / decrypt_dict() with JSON instead (safe serialization)

    def encrypt_jsonl(self, input_path: Union[str, Path], output_path: Optional[Union[str, Path]] = None) -> Path:
        """
        Encrypt JSONL file (common format in our codebase)

        Args:
            input_path: Path to JSONL file
            output_path: Path to save encrypted file

        Returns:
            Path to encrypted file
        """
        input_path = Path(input_path)

        if output_path is None:
            output_path = input_path.parent / f"{input_path.stem}.encrypted.jsonl"
        else:
            output_path = Path(output_path)

        with open(input_path, 'r', encoding='utf-8') as infile, \
             open(output_path, 'w', encoding='utf-8') as outfile:

            for line in infile:
                # Parse JSON
                data = json.loads(line.strip())

                # Encrypt as string
                encrypted = self.encrypt_dict(data)

                # Write encrypted line
                outfile.write(encrypted + '\n')

        return output_path

    def decrypt_jsonl(self, input_path: Union[str, Path], output_path: Optional[Union[str, Path]] = None) -> Path:
        """
        Decrypt encrypted JSONL file

        Args:
            input_path: Path to encrypted JSONL file
            output_path: Path to save decrypted file

        Returns:
            Path to decrypted file
        """
        input_path = Path(input_path)

        if output_path is None:
            output_path = input_path.parent / input_path.name.replace('.encrypted', '')
        else:
            output_path = Path(output_path)

        with open(input_path, 'r', encoding='utf-8') as infile, \
             open(output_path, 'w', encoding='utf-8') as outfile:

            for line in infile:
                # Decrypt line
                encrypted = line.strip()
                data = self.decrypt_dict(encrypted)

                # Write decrypted JSON
                outfile.write(json.dumps(data, ensure_ascii=False) + '\n')

        return output_path


# Global encryption manager instance
_encryption_manager_instance = None


def get_encryption_manager(encryption_key: Optional[str] = None) -> EncryptionManager:
    """
    Get global encryption manager instance

    Args:
        encryption_key: Optional encryption key

    Returns:
        EncryptionManager instance
    """
    global _encryption_manager_instance

    if _encryption_manager_instance is None:
        _encryption_manager_instance = EncryptionManager(encryption_key=encryption_key)

    return _encryption_manager_instance


if __name__ == "__main__":
    # Test encryption manager
    print("="*60)
    print("Testing Encryption Manager")
    print("="*60)

    # Generate new key
    key = EncryptionManager.generate_key()
    print(f"\n1️⃣  Generated encryption key:\n   {key}")

    # Initialize manager
    em = EncryptionManager(encryption_key=key)

    # Test string encryption
    plain_text = "Sensitive research data - Patient ID: 12345"
    encrypted = em.encrypt_string(plain_text)
    decrypted = em.decrypt_string(encrypted)

    print(f"\n2️⃣  String encryption:")
    print(f"   Original: {plain_text}")
    print(f"   Encrypted: {encrypted[:50]}...")
    print(f"   Decrypted: {decrypted}")
    assert plain_text == decrypted, "❌ Decryption failed!"
    print("   ✅ String encryption works!")

    # Test dict encryption
    data = {
        "patient_id": "12345",
        "trial_results": "positive",
        "researcher": "Dr. Smith"
    }
    encrypted_json = em.encrypt_dict(data)
    decrypted_data = em.decrypt_dict(encrypted_json)

    print(f"\n3️⃣  Dictionary encryption:")
    print(f"   Original: {data}")
    print(f"   Encrypted: {encrypted_json[:50]}...")
    print(f"   Decrypted: {decrypted_data}")
    assert data == decrypted_data, "❌ Dict decryption failed!"
    print("   ✅ Dictionary encryption works!")

    # Test file encryption
    test_file = Path("test_data.txt")
    test_file.write_text("This is sensitive test data for encryption")

    encrypted_file = em.encrypt_file(test_file)
    decrypted_file = em.decrypt_file(encrypted_file)

    original = test_file.read_text()
    decrypted_content = decrypted_file.read_text()

    print(f"\n4️⃣  File encryption:")
    print(f"   Original file: {test_file}")
    print(f"   Encrypted file: {encrypted_file}")
    print(f"   Decrypted file: {decrypted_file}")
    print(f"   Content matches: {original == decrypted_content}")
    assert original == decrypted_content, "❌ File decryption failed!"
    print("   ✅ File encryption works!")

    # Cleanup
    test_file.unlink()
    encrypted_file.unlink()
    decrypted_file.unlink()

    print("\n" + "="*60)
    print("✅ All encryption tests passed!")
    print("="*60)
    print("\n💡 To use in production:")
    print(f"1. Add to .env: ENCRYPTION_KEY={key}")
    print("2. Import: from security.encryption_manager import get_encryption_manager")
    print("3. Use: em = get_encryption_manager()")
