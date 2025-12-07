"""
Encryption Manager for Data at Rest - FIXED VERSION

SECURITY FIXES:
✅ Proper salt handling (random per encryption, stored with ciphertext)
✅ No default/static salts
✅ Key rotation support
✅ Secure key derivation (PBKDF2 with 310,000 iterations - OWASP 2023)
✅ NO PICKLE - Uses JSON only (GPT recommendation)

⚠️ CRITICAL: NO pickle.loads() usage!
   - pickle.loads() can execute arbitrary code (RCE vulnerability)
   - This implementation uses JSON only (safe serialization)
   - Never deserialize untrusted data with pickle!

Uses Fernet (symmetric encryption) for fast encryption/decryption
Fernet = AES-128-CBC + HMAC-SHA256 (authenticated encryption)
"""

import os
import json
from pathlib import Path
from typing import Any, Dict, Optional, Union, Tuple
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import secrets


class EncryptionManager:
    """
    Manages encryption/decryption of data at rest

    Features:
    - Fernet (AES-128-CBC + HMAC-SHA256)
    - Random salt per password derivation
    - Secure key derivation (PBKDF2 with 310,000 iterations)
    - Key rotation support
    - No default/static secrets
    """

    def __init__(self, encryption_key: Optional[str] = None):
        """
        Initialize encryption manager

        Args:
            encryption_key: Base64-encoded Fernet key (or from env ENCRYPTION_KEY)

        Raises:
            ValueError: If no encryption key provided
        """
        if encryption_key:
            self.key = encryption_key.encode() if isinstance(encryption_key, str) else encryption_key
        else:
            # Load from environment
            env_key = os.getenv('ENCRYPTION_KEY')
            if not env_key:
                raise ValueError(
                    "⚠️ SECURITY ERROR: ENCRYPTION_KEY environment variable must be set!\n"
                    "Generate one with: python3 -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"\n"
                    "Then set: export ENCRYPTION_KEY='<generated_key>'"
                )
            self.key = env_key.encode()

        try:
            self.cipher = Fernet(self.key)
        except Exception as e:
            raise ValueError(f"Invalid encryption key format: {e}")

        # Key rotation support (optional secondary keys)
        self._rotation_keys = []

    @staticmethod
    def generate_key() -> str:
        """
        Generate a new Fernet encryption key

        Returns:
            Base64-encoded Fernet key
        """
        key = Fernet.generate_key()
        return key.decode()

    @staticmethod
    def derive_key_from_password(password: str) -> Tuple[str, str]:
        """
        Derive encryption key from password using PBKDF2

        ✅ SECURITY IMPROVEMENTS:
        - Random salt (32 bytes) generated each time
        - 310,000 iterations (OWASP 2023 recommendation)
        - Salt is returned to be stored with ciphertext

        Args:
            password: User password

        Returns:
            Tuple of (base64_key, base64_salt)
            Store BOTH - you need the salt to derive the same key later!

        Example:
            # Encryption:
            key, salt = EncryptionManager.derive_key_from_password("mypassword")
            # Store salt in database or prepend to ciphertext

            # Decryption (need same salt):
            key = EncryptionManager.derive_key_from_password_with_salt("mypassword", salt)
        """
        # Generate random salt (32 bytes = 256 bits)
        salt = secrets.token_bytes(32)

        # PBKDF2 with 310,000 iterations (OWASP 2023)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 32 bytes for Fernet
            salt=salt,
            iterations=310000  # OWASP 2023 recommendation (was 100,000)
        )

        # Derive key
        key_bytes = kdf.derive(password.encode())
        key = base64.urlsafe_b64encode(key_bytes)

        # Return key and salt (both base64 encoded)
        return key.decode(), base64.urlsafe_b64encode(salt).decode()

    @staticmethod
    def derive_key_from_password_with_salt(password: str, salt_b64: str) -> str:
        """
        Derive encryption key from password using stored salt

        Args:
            password: User password
            salt_b64: Base64-encoded salt (from derive_key_from_password)

        Returns:
            Base64-encoded Fernet key
        """
        # Decode salt
        salt = base64.urlsafe_b64decode(salt_b64.encode())

        # PBKDF2 with same parameters
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=310000
        )

        # Derive key
        key_bytes = kdf.derive(password.encode())
        key = base64.urlsafe_b64encode(key_bytes)

        return key.decode()

    def add_rotation_key(self, old_key: str):
        """
        Add old key for decryption during key rotation

        Args:
            old_key: Old Fernet key (base64-encoded)

        Example:
            # Rotate to new key but keep old for decryption
            em = EncryptionManager(new_key)
            em.add_rotation_key(old_key)

            # Can now decrypt old data with old key
            # New encryptions use new key
        """
        old_cipher = Fernet(old_key.encode() if isinstance(old_key, str) else old_key)
        self._rotation_keys.append(old_cipher)

    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt raw bytes

        Args:
            data: Raw bytes to encrypt

        Returns:
            Encrypted bytes (includes timestamp, IV, ciphertext, HMAC)
        """
        return self.cipher.encrypt(data)

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt encrypted bytes

        Supports key rotation - tries current key, then rotation keys

        Args:
            encrypted_data: Encrypted bytes

        Returns:
            Decrypted bytes

        Raises:
            InvalidToken: If decryption fails with all keys
        """
        # Try current key first
        try:
            return self.cipher.decrypt(encrypted_data)
        except InvalidToken:
            # Try rotation keys
            for old_cipher in self._rotation_keys:
                try:
                    return old_cipher.decrypt(encrypted_data)
                except InvalidToken:
                    continue

            # All keys failed
            raise InvalidToken("Decryption failed - invalid key or corrupted data")

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
        decrypted = self.decrypt(encrypted_bytes)  # Use decrypt() for rotation support
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

    def encrypt_file(self, input_path: Union[str, Path],
                    output_path: Optional[Union[str, Path]] = None) -> Path:
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

    def decrypt_file(self, input_path: Union[str, Path],
                    output_path: Optional[Union[str, Path]] = None) -> Path:
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

    def encrypt_jsonl(self, input_path: Union[str, Path],
                     output_path: Optional[Union[str, Path]] = None) -> Path:
        """
        Encrypt JSONL file line-by-line

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

    def decrypt_jsonl(self, input_path: Union[str, Path],
                     output_path: Optional[Union[str, Path]] = None) -> Path:
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
    print("="*80)
    print("TESTING FIXED ENCRYPTION MANAGER")
    print("="*80)

    # Test 1: Key generation
    print("\n1️⃣  Key Generation:")
    key = EncryptionManager.generate_key()
    print(f"   Generated key: {key[:40]}...")
    print("   ✅ Save to .env: ENCRYPTION_KEY={key}")

    # Test 2: Password derivation with salt
    print("\n2️⃣  Password Derivation (with salt):")
    password = "MySecurePassword123!"
    derived_key, salt = EncryptionManager.derive_key_from_password(password)
    print(f"   Password: {password}")
    print(f"   Derived key: {derived_key[:40]}...")
    print(f"   Salt: {salt[:40]}...")
    print("   ⚠️  IMPORTANT: Store BOTH key and salt!")

    # Test 3: Derive same key with salt
    print("\n3️⃣  Derive Same Key (using stored salt):")
    same_key = EncryptionManager.derive_key_from_password_with_salt(password, salt)
    print(f"   Same key? {derived_key == same_key}")
    assert derived_key == same_key, "❌ Keys don't match!"
    print("   ✅ Password derivation with salt works!")

    # Test 4: Different salt = different key
    print("\n4️⃣  Different Salt = Different Key:")
    key2, salt2 = EncryptionManager.derive_key_from_password(password)
    print(f"   Same password, different salt")
    print(f"   Key 1: {derived_key[:40]}...")
    print(f"   Key 2: {key2[:40]}...")
    print(f"   Keys different? {derived_key != key2}")
    assert derived_key != key2, "❌ Keys should be different with different salts!"
    print("   ✅ Random salts working correctly!")

    # Test 5: String encryption
    print("\n5️⃣  String Encryption:")
    em = EncryptionManager(encryption_key=key)
    plain_text = "Sensitive patient data - PII removed"
    encrypted = em.encrypt_string(plain_text)
    decrypted = em.decrypt_string(encrypted)
    print(f"   Original:  {plain_text}")
    print(f"   Encrypted: {encrypted[:50]}...")
    print(f"   Decrypted: {decrypted}")
    assert plain_text == decrypted, "❌ Decryption failed!"
    print("   ✅ String encryption works!")

    # Test 6: Key rotation
    print("\n6️⃣  Key Rotation:")
    old_key = EncryptionManager.generate_key()
    new_key = EncryptionManager.generate_key()

    # Encrypt with old key
    em_old = EncryptionManager(encryption_key=old_key)
    old_ciphertext = em_old.encrypt_string("Encrypted with old key")

    # Create new manager with rotation support
    em_new = EncryptionManager(encryption_key=new_key)
    em_new.add_rotation_key(old_key)

    # Can decrypt old data
    decrypted_old = em_new.decrypt_string(old_ciphertext)
    print(f"   Old data decrypted: {decrypted_old}")

    # New encryptions use new key
    new_ciphertext = em_new.encrypt_string("Encrypted with new key")
    decrypted_new = em_new.decrypt_string(new_ciphertext)
    print(f"   New data decrypted: {decrypted_new}")
    print("   ✅ Key rotation works!")

    # Test 7: Dictionary encryption
    print("\n7️⃣  Dictionary Encryption:")
    data = {
        "user_id": "12345",
        "email": "user@example.com",
        "metadata": {"role": "admin"}
    }
    encrypted_json = em.encrypt_dict(data)
    decrypted_data = em.decrypt_dict(encrypted_json)
    print(f"   Original: {data}")
    print(f"   Decrypted: {decrypted_data}")
    assert data == decrypted_data, "❌ Dict decryption failed!"
    print("   ✅ Dictionary encryption works!")

    print("\n" + "="*80)
    print("✅ ALL TESTS PASSED!")
    print("="*80)
    print("\n🔒 SECURITY IMPROVEMENTS:")
    print("  ✅ Random salts (32 bytes) for each password derivation")
    print("  ✅ 310,000 PBKDF2 iterations (OWASP 2023)")
    print("  ✅ Salt returned and must be stored with ciphertext")
    print("  ✅ No static/default salts")
    print("  ✅ Key rotation support")
    print("  ✅ Proper error handling for missing keys")
    print("="*80)
    print("\n💡 USAGE:")
    print("  1. Generate key: python3 -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"")
    print("  2. Set in .env: ENCRYPTION_KEY=<generated_key>")
    print("  3. Import: from security.encryption_manager_fixed import get_encryption_manager")
    print("  4. Use: em = get_encryption_manager()")
    print("="*80)
