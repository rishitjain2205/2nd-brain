#!/usr/bin/env python3
"""
Azure OpenAI AI Helper
Uses your Azure OpenAI API instead of Claude Code credits
"""

import os
from dotenv import load_dotenv
from openai import AzureOpenAI

# Load environment variables
load_dotenv()

class AzureAIHelper:
    """Helper class for Azure OpenAI API calls"""

    def __init__(self):
        """Initialize Azure OpenAI client"""
        self.api_key = os.getenv('AZURE_OPENAI_API_KEY')
        self.endpoint = os.getenv('AZURE_OPENAI_ENDPOINT')
        self.deployment = os.getenv('AZURE_OPENAI_DEPLOYMENT', 'gpt-5-chat')
        self.api_version = os.getenv('AZURE_OPENAI_API_VERSION', '2024-02-15-preview')

        if not self.api_key or not self.endpoint:
            raise ValueError("AZURE_OPENAI_API_KEY and AZURE_OPENAI_ENDPOINT must be set in .env file")

        # Initialize client
        self.client = AzureOpenAI(
            api_key=self.api_key,
            api_version=self.api_version,
            azure_endpoint=self.endpoint
        )

        print(f"✓ Azure OpenAI client initialized")
        print(f"  Endpoint: {self.endpoint}")
        print(f"  Deployment: {self.deployment}")

    def chat(self, prompt: str, system_message: str = None, max_tokens: int = 2000) -> str:
        """
        Send chat request to Azure OpenAI

        Args:
            prompt: User prompt
            system_message: Optional system message
            max_tokens: Maximum tokens in response

        Returns:
            AI response text
        """
        messages = []

        if system_message:
            messages.append({"role": "system", "content": system_message})

        messages.append({"role": "user", "content": prompt})

        print(f"\n📤 Sending request to Azure OpenAI...")

        response = self.client.chat.completions.create(
            model=self.deployment,
            messages=messages,
            max_tokens=max_tokens,
            temperature=0.7
        )

        result = response.choices[0].message.content

        print(f"✓ Response received ({response.usage.total_tokens} tokens)")

        return result

    def code_review(self, code: str, language: str = "python") -> str:
        """
        Review code for security issues

        Args:
            code: Code to review
            language: Programming language

        Returns:
            Security review results
        """
        system_message = f"""You are a security expert reviewing {language} code.
Focus on:
- SQL injection vulnerabilities
- XSS vulnerabilities
- Authentication/authorization issues
- Cryptographic issues
- Input validation issues
- OWASP Top 10 vulnerabilities

Provide specific line-by-line feedback with severity ratings (CRITICAL, HIGH, MEDIUM, LOW)."""

        prompt = f"""Review this {language} code for security vulnerabilities:

```{language}
{code}
```

Provide detailed security analysis."""

        return self.chat(prompt, system_message, max_tokens=4000)

    def generate_documentation(self, code: str) -> str:
        """
        Generate documentation for code

        Args:
            code: Code to document

        Returns:
            Generated documentation
        """
        system_message = "You are a technical writer creating clear, concise documentation."

        prompt = f"""Generate comprehensive documentation for this code:

```python
{code}
```

Include:
- Overview and purpose
- Function/class descriptions
- Parameters and return values
- Usage examples
- Security considerations"""

        return self.chat(prompt, system_message, max_tokens=3000)

    def refactor_code(self, code: str, instructions: str) -> str:
        """
        Refactor code according to instructions

        Args:
            code: Code to refactor
            instructions: Refactoring instructions

        Returns:
            Refactored code
        """
        system_message = "You are an expert programmer. Provide only the refactored code, no explanations."

        prompt = f"""Refactor this code according to these instructions:

INSTRUCTIONS:
{instructions}

CODE:
```python
{code}
```

Provide the complete refactored code."""

        return self.chat(prompt, system_message, max_tokens=4000)


def main():
    """Demo usage"""
    print("="*70)
    print("Azure OpenAI AI Helper - Demo")
    print("="*70)

    # Initialize helper
    helper = AzureAIHelper()

    # Example 1: Simple chat
    print("\n1️⃣  Simple Chat Example:")
    response = helper.chat("Explain what SQL injection is in 2 sentences.")
    print(f"\nResponse:\n{response}")

    # Example 2: Code review
    print("\n\n2️⃣  Code Review Example:")
    vulnerable_code = '''
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    return cursor.fetchone()
'''

    review = helper.code_review(vulnerable_code)
    print(f"\nSecurity Review:\n{review}")

    # Example 3: Documentation
    print("\n\n3️⃣  Documentation Example:")
    code_to_document = '''
def sanitize_string(value: str, max_length: int = 1000) -> str:
    """Sanitize string input"""
    if len(value) > max_length:
        raise ValueError(f"Input too long (max {max_length} chars)")

    # Check for SQL injection
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            raise ValueError(f"SQL injection detected: {pattern}")

    return html.escape(value)
'''

    docs = helper.generate_documentation(code_to_document)
    print(f"\nGenerated Documentation:\n{docs}")

    print("\n" + "="*70)
    print("✅ Demo Complete!")
    print("="*70)
    print("\nUsage in your own scripts:")
    print("""
from azure_ai_helper import AzureAIHelper

helper = AzureAIHelper()
response = helper.chat("Your prompt here")
print(response)
""")


if __name__ == "__main__":
    main()
