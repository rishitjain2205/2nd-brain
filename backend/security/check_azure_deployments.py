"""
Helper script to check Azure OpenAI deployments
Run this to find your correct deployment name
"""

import os
from dotenv import load_dotenv
import requests

load_dotenv()

api_key = os.getenv('AZURE_OPENAI_API_KEY')
endpoint = os.getenv('AZURE_OPENAI_ENDPOINT')
api_version = "2023-03-15-preview"

print("\n" + "="*60)
print("🔍 Checking Azure OpenAI Deployments")
print("="*60)

print(f"\nEndpoint: {endpoint}")
print(f"API Key: {'*' * 20}{api_key[-4:] if api_key else 'NOT SET'}")

# Try to list deployments
url = f"{endpoint}openai/deployments?api-version={api_version}"

headers = {
    "api-key": api_key
}

print(f"\n📡 Calling: {url}")

try:
    # SECURITY FIX: Add timeout to prevent indefinite blocking
    response = requests.get(url, headers=headers, timeout=10)

    if response.status_code == 200:
        data = response.json()
        deployments = data.get('data', [])

        print(f"\n✅ Found {len(deployments)} deployment(s):")
        print("─" * 60)

        for dep in deployments:
            print(f"\n📦 Deployment: {dep.get('id')}")
            print(f"   Model: {dep.get('model')}")
            print(f"   Status: {dep.get('status')}")
            print(f"   Scale Type: {dep.get('scale_settings', {}).get('scale_type')}")

        if deployments:
            print("\n" + "="*60)
            print("💡 UPDATE YOUR .env FILE:")
            print("="*60)
            print(f"AZURE_OPENAI_DEPLOYMENT={deployments[0].get('id')}")
            print("\nUse the deployment ID above in your .env file")
    else:
        print(f"\n❌ Error: HTTP {response.status_code}")
        print(f"Response: {response.text}")

        print("\n" + "="*60)
        print("🔧 HOW TO FIX THIS:")
        print("="*60)
        print("1. Go to Azure Portal: https://portal.azure.com")
        print("2. Navigate to your Azure OpenAI resource")
        print("3. Go to 'Model deployments' or 'Deployments'")
        print("4. Find a deployment with model: gpt-4o-mini or gpt-4")
        print("5. Copy the DEPLOYMENT NAME (not the model name)")
        print("6. Update .env file:")
        print("   AZURE_OPENAI_DEPLOYMENT=your-deployment-name")

except Exception as e:
    print(f"\n❌ Error: {str(e)}")

    print("\n" + "="*60)
    print("🔧 MANUAL STEPS TO FIND DEPLOYMENT:")
    print("="*60)
    print("1. Go to: https://portal.azure.com")
    print("2. Find your Azure OpenAI resource: rishi-mihfdoty-eastus2")
    print("3. Click 'Model deployments' in the left menu")
    print("4. You should see a list of deployments")
    print("5. Look for a deployment with model type 'gpt-4o-mini' or 'gpt-4'")
    print("6. Copy the DEPLOYMENT NAME (e.g., 'my-gpt4-deployment')")
    print("7. Update your .env file:")
    print("   AZURE_OPENAI_DEPLOYMENT=your-deployment-name")
