# Security Testing Suite

Comprehensive security testing for the 2nd Brain application.

## 🚀 Quick Start

### Run Complete Security Audit (Recommended)

```bash
python3 run_security_audit.py
```

This runs ALL security tests and generates a comprehensive report with:
- File verification
- Automated vulnerability scanning
- Unit tests
- Security score (0-100)
- Detailed recommendations

---

## 📋 Individual Test Suites

### 1. Comprehensive Security Tests

**File:** `tests/test_security_comprehensive.py`

**What it tests:**
- ✅ SQL injection prevention (5 attack types)
- ✅ Encryption security (salt randomness, tampering detection)
- ✅ JWT validation
- ✅ PII sanitization (emails, phones, SSN, API keys)
- ✅ File permissions
- ✅ Crypto-shredding
- ✅ Input validation
- ✅ No pickle deserialization

**Run:**
```bash
python3 tests/test_security_comprehensive.py
```

**Example Output:**
```
test_sql_injection_or_bypass ... ok
test_encryption_decryption ... ok
test_jwt_token_detection ... ok
test_file_permissions ... ok
✅ All tests passed!
```

---

### 2. Penetration Testing Suite

**File:** `tests/test_penetration.py`

**What it tests (REAL ATTACKS):**
- 🎯 SQL injection attacks (OR bypass, UNION, blind)
- 🎯 JWT forgery attempts
- 🎯 XSS attacks
- 🎯 Rate limiting bypass
- 🎯 Path traversal
- 🎯 Secret exposure

**Requirements:**
- `app_secure.py` must be running on `http://localhost:5001`
- `requests` library installed: `pip install requests`

**Run:**
```bash
# Terminal 1: Start the app
python3 app_secure.py

# Terminal 2: Run penetration tests
python3 tests/test_penetration.py
```

**Example Output:**
```
Attempting: SQL injection: ' OR '1'='1... ✅ BLOCKED
Attempting: XSS: <script>alert... ✅ SANITIZED
🛡️  ALL ATTACKS BLOCKED! Application is secure.
```

---

### 3. Automated Security Scanner

**File:** `tests/security_scanner.py`

**What it scans:**
- 🔍 Dangerous functions (eval, exec, pickle)
- 🔍 Hardcoded secrets
- 🔍 SQL injection patterns
- 🔍 Insecure deserialization
- 🔍 File permissions
- 🔍 Environment variables (.env in .gitignore)
- 🔍 Vulnerable dependencies
- 🔍 Weak cryptography
- 🔍 Missing input validation

**Run:**
```bash
python3 tests/security_scanner.py
```

**Example Output:**
```
🔍 Scanning for dangerous functions...
🔍 Scanning for hardcoded secrets...
🔍 Scanning SQL injection risks...

[CRITICAL] Pickle deserialization
  Location: old_code.py:45
  Fix: Remove or replace with safe alternative

✅ No critical security issues found!
```

---

## 📊 Test Coverage

| Security Area | Tests | Coverage |
|--------------|-------|----------|
| **SQL Injection** | 5 attack types | 100% |
| **Encryption** | 5 tests | 100% |
| **JWT** | 3 tests | 100% |
| **PII Sanitization** | 8 data types | 100% |
| **File Security** | Permissions, disposal | 100% |
| **Input Validation** | Email, URL, SSRF | 100% |
| **Code Scanning** | 10 categories | Static analysis |
| **Penetration** | 20+ attacks | Live testing |

---

## 🎯 Interpreting Results

### Security Score

- **90-100**: Excellent - Ready for production
- **70-89**: Good - Address remaining issues
- **50-69**: Fair - Improvements needed
- **0-49**: Poor - DO NOT DEPLOY

### Issue Severity

- **CRITICAL**: Fix immediately - exploitable vulnerability
- **HIGH**: Fix before production
- **MEDIUM**: Fix when possible
- **LOW**: Nice to have
- **INFO**: Informational only

---

## 🛠️ Fixing Common Issues

### SQL Injection

**Bad:**
```python
query = f"SELECT * FROM users WHERE email = '{email}'"
cursor.execute(query)
```

**Good:**
```python
from security.secure_database import SecureDatabase
db = SecureDatabase('sqlite:///app.db')
result = db.execute_query(
    "SELECT * FROM users WHERE email = ?",
    (email,)
)
```

### Hardcoded Secrets

**Bad:**
```python
API_KEY = "sk_live_1234567890abcdef"
```

**Good:**
```python
import os
API_KEY = os.getenv('API_KEY')
```

### Pickle Deserialization

**Bad:**
```python
import pickle
data = pickle.loads(user_input)  # RCE!
```

**Good:**
```python
import json
data = json.loads(user_input)  # Safe
```

### Weak Encryption

**Bad:**
```python
key, salt = derive_key("password")  # Static salt
```

**Good:**
```python
from security.encryption_manager_fixed import EncryptionManager
em = EncryptionManager()
key, salt = em.derive_key_from_password("password")  # Random salt!
```

---

## 🔄 CI/CD Integration

Add to your CI pipeline:

```yaml
# .github/workflows/security.yml
name: Security Tests

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
      - name: Run Security Tests
        run: |
          python3 tests/test_security_comprehensive.py
      - name: Run Security Scanner
        run: |
          python3 tests/security_scanner.py
```

---

## 📝 Adding New Tests

### 1. Add to Comprehensive Tests

```python
# tests/test_security_comprehensive.py

class TestMyNewFeature(unittest.TestCase):
    """Test my new security feature"""

    def test_feature_works(self):
        """Test: Feature prevents XYZ attack"""
        # Your test here
        self.assertTrue(feature_is_secure())
```

### 2. Add to Scanner

```python
# tests/security_scanner.py

def scan_my_check(self):
    """Scan for my vulnerability"""
    for py_file in self.project_root.rglob('*.py'):
        # Your check here
        if has_vulnerability(py_file):
            self.add_issue(SecurityIssue(
                SecurityIssue.HIGH,
                "My Vulnerability",
                "Description",
                str(py_file),
                line_number,
                "How to fix"
            ))
```

---

## 🚨 Production Checklist

Before deploying to production, ensure:

- [ ] `python3 run_security_audit.py` shows 90+ score
- [ ] All CRITICAL and HIGH issues fixed
- [ ] Penetration tests all pass
- [ ] API keys rotated (use `rotate_keys.py`)
- [ ] .env not in git (check `.gitignore`)
- [ ] HTTPS enforced
- [ ] Auth0/JWT configured
- [ ] Cloud audit logging enabled
- [ ] Rate limiting active
- [ ] File permissions correct (0600 on keys)

---

## 🆘 Getting Help

**Tests failing?**

1. Read the error message carefully
2. Check the "Fix" recommendation
3. Review the documentation in `/backend/SECURITY_*.md`
4. Run individual tests for more detail

**Scanner finding issues?**

1. Check severity (CRITICAL/HIGH should be fixed immediately)
2. Follow the recommendation
3. Re-run scanner to verify fix

**Penetration tests succeeding?**

1. You have a vulnerability!
2. Check which attack succeeded
3. Review the corresponding security module
4. Ensure you're using the secure implementation

---

## 📚 Documentation

- `CRITICAL_SECURITY_VULNERABILITIES_FIXED.md` - What was fixed and why
- `SECURITY_MIGRATION_GUIDE.md` - How to migrate old code
- `SECURITY_PROCEDURES.md` - Production deployment procedures
- `QUICK_START_SECURITY.md` - 20-minute quick start
- `SECURITY_QUICK_REFERENCE.md` - Quick reference card

---

**Last Updated:** December 7, 2025
**Maintained By:** Security Team
**Contact:** See main README
