#!/usr/bin/env python3
"""
Azure Claude Terminal
Claude Code-like interface using your Azure Anthropic credits

Usage:
    python3 azure_claude_terminal.py
"""

import os
import sys
import json
from pathlib import Path
from anthropic import Anthropic
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# Azure Anthropic Configuration (from .env file)
AZURE_API_KEY = os.getenv('AZURE_ANTHROPIC_API_KEY')
AZURE_ENDPOINT = os.getenv('AZURE_ANTHROPIC_ENDPOINT', 'https://rishi-mihfdoty-eastus2.services.ai.azure.com/anthropic')
MODEL = os.getenv('AZURE_ANTHROPIC_MODEL', 'claude-opus-4-5')


class AzureClaudeTerminal:
    """Claude Code-like terminal using Azure Anthropic API"""

    def __init__(self):
        """Initialize Azure Claude client"""
        if not AZURE_API_KEY:
            print("❌ Error: AZURE_ANTHROPIC_API_KEY not found in .env file")
            print("\nPlease add to .env:")
            print("AZURE_ANTHROPIC_API_KEY=your_api_key_here")
            print("AZURE_ANTHROPIC_ENDPOINT=https://your-endpoint.services.ai.azure.com/anthropic")
            print("AZURE_ANTHROPIC_MODEL=claude-opus-4-5")
            sys.exit(1)

        self.client = Anthropic(
            api_key=AZURE_API_KEY,
            base_url=AZURE_ENDPOINT
        )
        self.conversation_history = []
        self.working_dir = Path.cwd()

        print("=" * 70)
        print("🤖 Azure Claude Terminal (Using Your Azure Credits)")
        print("=" * 70)
        print(f"Model: {MODEL}")
        print(f"Working Directory: {self.working_dir}")
        print("\nCommands:")
        print("  /read <file>    - Read a file")
        print("  /edit <file>    - Edit a file")
        print("  /ls [dir]       - List files")
        print("  /cd <dir>       - Change directory")
        print("  /pwd            - Print working directory")
        print("  /clear          - Clear conversation history")
        print("  /exit           - Exit terminal")
        print("  /help           - Show this help")
        print("\nOr just type your question/request!")
        print("=" * 70)

    def read_file(self, file_path: str) -> str:
        """Read file contents"""
        try:
            path = Path(file_path)
            if not path.is_absolute():
                path = self.working_dir / path

            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()

            return f"✓ Read {path}\n\n{content}"
        except Exception as e:
            return f"❌ Error reading {file_path}: {e}"

    def write_file(self, file_path: str, content: str) -> str:
        """Write to file"""
        try:
            path = Path(file_path)
            if not path.is_absolute():
                path = self.working_dir / path

            path.parent.mkdir(parents=True, exist_ok=True)

            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)

            return f"✓ Wrote to {path}"
        except Exception as e:
            return f"❌ Error writing to {file_path}: {e}"

    def list_files(self, directory: str = ".") -> str:
        """List files in directory"""
        try:
            path = Path(directory)
            if not path.is_absolute():
                path = self.working_dir / path

            files = []
            for item in sorted(path.iterdir()):
                prefix = "📁" if item.is_dir() else "📄"
                files.append(f"{prefix} {item.name}")

            return f"✓ Contents of {path}:\n" + "\n".join(files)
        except Exception as e:
            return f"❌ Error listing {directory}: {e}"

    def change_directory(self, directory: str) -> str:
        """Change working directory"""
        try:
            path = Path(directory)
            if not path.is_absolute():
                path = self.working_dir / path

            path = path.resolve()

            if not path.exists():
                return f"❌ Directory does not exist: {path}"

            if not path.is_dir():
                return f"❌ Not a directory: {path}"

            self.working_dir = path
            return f"✓ Changed to {self.working_dir}"
        except Exception as e:
            return f"❌ Error changing directory: {e}"

    def execute_command(self, user_input: str) -> str:
        """Execute special commands"""
        parts = user_input.strip().split(maxsplit=1)
        command = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        if command == "/read":
            if not args:
                return "❌ Usage: /read <file_path>"
            return self.read_file(args)

        elif command == "/ls":
            return self.list_files(args if args else ".")

        elif command == "/cd":
            if not args:
                return "❌ Usage: /cd <directory>"
            return self.change_directory(args)

        elif command == "/pwd":
            return f"Working directory: {self.working_dir}"

        elif command == "/clear":
            self.conversation_history = []
            return "✓ Conversation history cleared"

        elif command == "/help":
            return """Commands:
  /read <file>    - Read a file
  /edit <file>    - Edit a file (with Claude's help)
  /ls [dir]       - List files
  /cd <dir>       - Change directory
  /pwd            - Print working directory
  /clear          - Clear conversation history
  /exit           - Exit terminal
  /help           - Show this help"""

        elif command == "/exit":
            return "EXIT"

        else:
            return None

    def chat(self, user_input: str, include_context: bool = True) -> str:
        """Send message to Azure Claude"""

        # Build messages
        messages = []

        if include_context:
            messages.extend(self.conversation_history)

        messages.append({
            "role": "user",
            "content": user_input
        })

        # Add system context
        system_message = f"""You are Claude Code running in a terminal.
Working directory: {self.working_dir}

You can help with:
- Code review and security analysis
- File editing and refactoring
- Debugging and troubleshooting
- Documentation
- General programming questions

When asked to edit files, provide the exact content to write.
Be concise and helpful."""

        print("\n🤔 Thinking...\n")

        try:
            response = self.client.messages.create(
                model=MODEL,
                max_tokens=4096,
                system=system_message,
                messages=messages
            )

            assistant_message = response.content[0].text

            # Save to conversation history
            self.conversation_history.append({
                "role": "user",
                "content": user_input
            })
            self.conversation_history.append({
                "role": "assistant",
                "content": assistant_message
            })

            # Show token usage
            usage = response.usage
            print(f"[Tokens: {usage.input_tokens} in, {usage.output_tokens} out, {usage.input_tokens + usage.output_tokens} total]")

            return assistant_message

        except Exception as e:
            return f"❌ Error calling Azure Claude API: {e}"

    def run(self):
        """Main terminal loop"""
        while True:
            try:
                # Get user input
                user_input = input(f"\n💬 You ({self.working_dir.name})> ").strip()

                if not user_input:
                    continue

                # Check for commands
                if user_input.startswith("/"):
                    result = self.execute_command(user_input)

                    if result == "EXIT":
                        print("\n👋 Goodbye!")
                        break

                    if result:
                        print(f"\n{result}")
                        continue

                # Check for file editing request
                if "/edit" in user_input.lower():
                    parts = user_input.split(maxsplit=1)
                    if len(parts) > 1:
                        file_path = parts[1].strip()

                        # Read current file
                        current_content = self.read_file(file_path)

                        # Ask Claude how to edit
                        edit_prompt = f"""I want to edit this file: {file_path}

Current content:
{current_content}

Please provide the complete updated file content."""

                        response = self.chat(edit_prompt, include_context=False)
                        print(f"\n🤖 Claude:\n{response}")

                        # Ask for confirmation
                        confirm = input("\n✅ Apply this edit? (yes/no): ").strip().lower()

                        if confirm == "yes":
                            # Extract code if in code blocks
                            if "```" in response:
                                lines = response.split("\n")
                                in_code = False
                                code_lines = []

                                for line in lines:
                                    if line.strip().startswith("```"):
                                        in_code = not in_code
                                        continue
                                    if in_code:
                                        code_lines.append(line)

                                new_content = "\n".join(code_lines)
                            else:
                                new_content = response

                            result = self.write_file(file_path, new_content)
                            print(f"\n{result}")
                        else:
                            print("\n❌ Edit cancelled")

                        continue

                # Regular chat
                response = self.chat(user_input)
                print(f"\n🤖 Claude:\n{response}")

            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"\n❌ Error: {e}")


def main():
    """Entry point"""
    terminal = AzureClaudeTerminal()
    terminal.run()


if __name__ == "__main__":
    main()
