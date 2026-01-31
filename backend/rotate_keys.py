#!/usr/bin/env python3
"""
Security Key Rotation Script
Generates new security keys for 2nd Brain application

Usage:
    python3 rotate_keys.py

This will generate new keys and provide instructions for updating .env
"""

import secrets
from cryptography.fernet import Fernet
import os
from pathlib import Path


def generate_keys():
    """Generate new security keys"""

    print("\n" + "="*80)
    print("2ND BRAIN - SECURITY KEY ROTATION")
    print("="*80)
    print("\n🔑 Generating new security keys...\n")

    # Generate keys
    jwt_secret = secrets.token_hex(32)
    hmac_secret = secrets.token_hex(32)
    encryption_key = Fernet.generate_key().decode()

    # Display keys
    print("="*80)
    print("NEW SECURITY KEYS - COPY THESE TO YOUR .env FILE")
    print("="*80)
    print()
    print(f"JWT_SECRET_KEY={jwt_secret}")
    print(f"AUDIT_HMAC_SECRET={hmac_secret}")
    print(f"ENCRYPTION_KEY={encryption_key}")
    print()
    print("="*80)
    print()

    # Check if .env exists
    env_file = Path(__file__).parent / ".env"

    if env_file.exists():
        print("📝 INSTRUCTIONS:")
        print()
        print("1. Open your .env file:")
        print(f"   nano {env_file}")
        print()
        print("2. Replace the old keys with the new ones above")
        print()
        print("3. Save and exit (Ctrl+X, then Y, then Enter)")
        print()
        print("4. Restart your application:")
        print("   python3 app_secure.py")
        print()

        # Ask if user wants to update .env automatically
        try:
            response = input("Would you like me to update .env automatically? (y/n): ")

            if response.lower() == 'y':
                update_env_file(env_file, jwt_secret, hmac_secret, encryption_key)
            else:
                print("\n✓ Keys generated. Please update .env manually.")
        except KeyboardInterrupt:
            print("\n\n✓ Keys generated. Please update .env manually.")
    else:
        print("⚠️  .env file not found!")
        print()
        print("📝 INSTRUCTIONS:")
        print()
        print("1. Copy .env.production.template to .env:")
        print(f"   cp {Path(__file__).parent}/.env.production.template {env_file}")
        print()
        print("2. Edit .env and paste the keys above")
        print()
        print("3. Fill in other required values (Azure OpenAI key, etc.)")
        print()

    print("\n" + "="*80)
    print("⚠️  IMPORTANT: Also rotate your Azure API keys!")
    print("="*80)
    print()
    print("1. Go to: https://portal.azure.com")
    print("2. Navigate to: Your Resource > Keys and Endpoint")
    print("3. Click 'Regenerate Key 1' or 'Regenerate Key 2'")
    print("4. Update AZURE_OPENAI_API_KEY in .env")
    print("5. Repeat for AZURE_ANTHROPIC_API_KEY if used")
    print()
    print("="*80)
    print()


def update_env_file(env_file, jwt_secret, hmac_secret, encryption_key):
    """Update .env file with new keys"""

    print("\n📝 Updating .env file...")

    try:
        # Read current .env
        with open(env_file, 'r') as f:
            lines = f.readlines()

        # Update keys
        updated_lines = []
        keys_updated = []

        for line in lines:
            if line.startswith('JWT_SECRET_KEY='):
                updated_lines.append(f'JWT_SECRET_KEY={jwt_secret}\n')
                keys_updated.append('JWT_SECRET_KEY')
            elif line.startswith('AUDIT_HMAC_SECRET='):
                updated_lines.append(f'AUDIT_HMAC_SECRET={hmac_secret}\n')
                keys_updated.append('AUDIT_HMAC_SECRET')
            elif line.startswith('ENCRYPTION_KEY='):
                updated_lines.append(f'ENCRYPTION_KEY={encryption_key}\n')
                keys_updated.append('ENCRYPTION_KEY')
            else:
                updated_lines.append(line)

        # Backup original
        backup_file = env_file.parent / ".env.backup"
        with open(backup_file, 'w') as f:
            f.writelines(lines)

        print(f"✓ Backup created: {backup_file}")

        # Write updated .env
        with open(env_file, 'w') as f:
            f.writelines(updated_lines)

        print(f"✓ Updated {len(keys_updated)} keys: {', '.join(keys_updated)}")
        print()
        print("="*80)
        print("✅ .env file updated successfully!")
        print("="*80)
        print()
        print("⚠️  NEXT STEPS:")
        print("1. Verify the changes in .env")
        print("2. Rotate your Azure API keys (see instructions above)")
        print("3. Restart your application: python3 app_secure.py")
        print()

    except Exception as e:
        print(f"\n❌ Error updating .env: {e}")
        print("Please update manually using the keys displayed above.")


if __name__ == "__main__":
    try:
        generate_keys()
    except KeyboardInterrupt:
        print("\n\n✓ Key generation cancelled.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
