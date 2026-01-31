# Azure Claude Terminal - Quick Start Guide

## 🚀 Use Claude Code with YOUR Azure Credits (Not Claude Code Credits)

Your Azure Anthropic API is now configured to use Claude Opus 4.5 with your own credits.

---

## Installation

```bash
cd /Users/badri/Documents/Clustering/2nd-brain/backend

# Install dependencies
pip3 install -r requirements.txt
```

---

## Usage

### Start Azure Claude Terminal

```bash
python3 azure_claude_terminal.py
```

You'll see:
```
======================================================================
🤖 Azure Claude Terminal (Using Your Azure Credits)
======================================================================
Model: claude-opus-4-5
Working Directory: /Users/badri/Documents/Clustering/2nd-brain/backend

Commands:
  /read <file>    - Read a file
  /edit <file>    - Edit a file
  /ls [dir]       - List files
  /cd <dir>       - Change directory
  /pwd            - Print working directory
  /clear          - Clear conversation history
  /exit           - Exit terminal
  /help           - Show this help

Or just type your question/request!
======================================================================

💬 You (backend)>
```

---

## Examples

### 1. Ask Questions

```
💬 You> How do I fix SQL injection vulnerabilities in Python?

🤔 Thinking...

🤖 Claude:
To fix SQL injection vulnerabilities in Python, use parameterized queries...
```

### 2. Read Files

```
💬 You> /read security/input_validator.py

✓ Read /Users/badri/.../security/input_validator.py

"""
Input Validation and Sanitization
...
"""
```

### 3. Edit Files (with Claude's Help)

```
💬 You> /edit test.py

[Claude will read current content, suggest edits]

🤖 Claude:
Here's the improved version:

```python
# Updated code here
```

✅ Apply this edit? (yes/no): yes

✓ Wrote to test.py
```

### 4. Code Review

```
💬 You> Review this code for security issues:

def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}'"
    cursor.execute(query)

🤖 Claude:
🚨 CRITICAL: SQL Injection vulnerability detected!
...
```

### 5. File Navigation

```
💬 You> /ls

✓ Contents of /Users/badri/.../backend:
📁 security
📁 monitoring
📁 backup
📄 azure_claude_terminal.py
📄 requirements.txt
...

💬 You> /cd security

✓ Changed to /Users/badri/.../security

💬 You> /pwd

Working directory: /Users/badri/.../security
```

---

## Features

✅ **Uses YOUR Azure Credits** - Not Claude Code credits
✅ **Full Claude Opus 4.5** - Most powerful Claude model
✅ **File Operations** - Read, edit, navigate files
✅ **Code Review** - Security analysis and best practices
✅ **Conversation History** - Maintains context across messages
✅ **Token Usage Tracking** - See exactly what you're using

---

## Commands Reference

| Command | Description | Example |
|---------|-------------|---------|
| `/read <file>` | Read file contents | `/read test.py` |
| `/edit <file>` | Edit file with Claude's help | `/edit config.json` |
| `/ls [dir]` | List files in directory | `/ls security/` |
| `/cd <dir>` | Change working directory | `/cd ../` |
| `/pwd` | Print working directory | `/pwd` |
| `/clear` | Clear conversation history | `/clear` |
| `/exit` | Exit terminal | `/exit` |
| `/help` | Show help message | `/help` |

---

## Token Usage

Each interaction shows token usage:
```
[Tokens: 150 in, 420 out, 570 total]
```

- **Input tokens**: Your prompt + context
- **Output tokens**: Claude's response
- **Total**: Combined usage

**Azure Anthropic Pricing** (approximate):
- Input: ~$15 per 1M tokens
- Output: ~$75 per 1M tokens

Example conversation (10 messages) ≈ 5,000 tokens ≈ $0.40

---

## Tips

### Efficient Usage

1. **Use `/clear` to reset context** - Saves tokens on unrelated questions
2. **Be specific in prompts** - Get better answers with fewer follow-ups
3. **Use for complex tasks** - Code review, refactoring, security analysis
4. **Keep sessions focused** - One topic per session

### Best Use Cases

✅ **Code review** - "Review this file for security issues"
✅ **Debugging** - "Why is this function failing?"
✅ **Refactoring** - "Improve this code's performance"
✅ **Security analysis** - "Find vulnerabilities in this code"
✅ **Documentation** - "Document this function"

❌ **Simple questions** - Use free resources (Google, Stack Overflow)
❌ **Repetitive tasks** - Write scripts instead

---

## Comparison: Azure Claude vs Claude Code

| Feature | Azure Claude Terminal | Claude Code (This Session) |
|---------|----------------------|---------------------------|
| **Cost** | Your Azure credits | Claude Code credits |
| **Model** | Claude Opus 4.5 | Claude Sonnet 4.5 |
| **Capabilities** | Chat, code review, file ops | Full IDE integration |
| **Best For** | Questions, reviews, refactoring | Complex multi-file edits |
| **Token Limit** | 200k context | 200k context |

---

## Troubleshooting

### Error: API Key Invalid
```bash
# Check your .env file
cat .env | grep AZURE_ANTHROPIC

# Should see something like:
AZURE_ANTHROPIC_API_KEY=your_api_key_here
AZURE_ANTHROPIC_ENDPOINT=https://your-endpoint.services.ai.azure.com/anthropic
AZURE_ANTHROPIC_MODEL=claude-opus-4-5
```

If missing, add to `.env`:
```bash
# Azure Anthropic API Configuration
AZURE_ANTHROPIC_API_KEY=your_api_key_here
AZURE_ANTHROPIC_ENDPOINT=https://your-endpoint.services.ai.azure.com/anthropic
AZURE_ANTHROPIC_MODEL=claude-opus-4-5
```

### Error: Module Not Found
```bash
pip3 install -r requirements.txt
```

### Exit Terminal
```
💬 You> /exit

👋 Goodbye!
```

Or press `Ctrl+C`

---

## Security Notes

⚠️ **API Key Security**:
- ✅ API key is in `.env` (not committed to GitHub)
- ✅ `.gitignore` protects `.env` from being uploaded
- ❌ Never share your API key publicly
- ❌ Never commit `.env` to GitHub

---

## Support

For issues:
1. Check `.env` file has correct API key
2. Verify `pip3 install -r requirements.txt` ran successfully
3. Ensure you're in the correct directory
4. Check Azure Anthropic quota/billing

---

## Next Steps

Start the terminal:
```bash
python3 azure_claude_terminal.py
```

Try it out:
```
💬 You> Explain the security fixes we made today

🤖 Claude:
[Detailed explanation using your Azure credits]
```

Enjoy using Claude Code with YOUR Azure credits! 🎉
