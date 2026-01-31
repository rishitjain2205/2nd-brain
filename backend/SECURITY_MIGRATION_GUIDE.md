# Security Migration Guide - Use This Instead

**Quick Reference:** What to use instead of vulnerable code

---

## 🔄 FILE REPLACEMENTS

| Old File (❌ Vulnerable) | New File (✅ Secure) | What Changed |
|-------------------------|---------------------|--------------|
| `security/input_validator.py` | `security/input_validator_fixed.py` | Removed SQL injection regex |
| `app.py` | `app_secure.py` | Added all security features |
| N/A (missing) | `security/secure_database.py` | New: Parameterized queries |

---

## 🔒 CODE MIGRATIONS

### 1. SQL Queries - CRITICAL CHANGE

**❌ OLD (VULNERABLE):**
```python
from security.input_validator import InputValidator
validator = InputValidator()

# Try to "sanitize" input
email = validator.sanitize_string(user_input)

# Still vulnerable!
query = f"SELECT * FROM users WHERE email = '{email}'"
cursor.execute(query)
```

**✅ NEW (SECURE):**
```python
from security.secure_database import SecureDatabase

db = SecureDatabase('sqlite:///mydb.db')

# Use parameterized query - SQL injection IMPOSSIBLE
result = db.execute_query(
    "SELECT * FROM users WHERE email = ?",
    (user_input,)  # Automatically escaped
)
```

---

### 2. Input Validation

**❌ OLD (FALSE SENSE OF SECURITY):**
```python
from security.input_validator import InputValidator
validator = InputValidator()

# This does NOT prevent SQL injection!
clean_input = validator.sanitize_string(user_input)
query = f"SELECT * FROM users WHERE name = '{clean_input}'"  # Still vulnerable!
```

**✅ NEW (CORRECT USAGE):**
```python
from security.input_validator_fixed import InputValidator
validator = InputValidator()

# Use for DATA TYPE validation only
email = validator.validate_email(user_input)  # Format check
age = validator.validate_integer(user_input, min_value=0, max_value=120)  # Range check

# Then use parameterized queries for SQL
db.execute_query("SELECT * FROM users WHERE email = ?", (email,))
```

---

### 3. User Repository Pattern

**❌ OLD (STRING CONCATENATION):**
```python
def get_user(email):
    query = f"SELECT * FROM users WHERE email = '{email}'"
    cursor.execute(query)
    return cursor.fetchone()
```

**✅ NEW (PARAMETERIZED):**
```python
from security.secure_database import SecureDatabase, UserRepository
from security.input_validator_fixed import InputValidator

db = SecureDatabase('sqlite:///mydb.db')
repo = UserRepository(db)

# All methods use parameterized queries internally
user = repo.get_user_by_email(email)  # Safe!
```

---

### 4. Search Queries with LIKE

**❌ OLD (VULNERABLE):**
```python
search_term = request.args.get('search')
query = f"SELECT * FROM users WHERE name LIKE '%{search_term}%'"
cursor.execute(query)
```

**✅ NEW (SECURE):**
```python
from security.secure_database import UserRepository

repo = UserRepository(db)

# Parameterized LIKE query
results = repo.search_users(search_term, limit=10)
```

Or manually:
```python
search_pattern = f"%{search_term}%"  # Build pattern in Python
results = db.execute_query(
    "SELECT * FROM users WHERE name LIKE ?",
    (search_pattern,)  # Parameterized
)
```

---

### 5. Bulk Operations

**❌ OLD (VULNERABLE):**
```python
users = [('alice@example.com', 'Alice'), ('bob@example.com', 'Bob')]
for email, name in users:
    query = f"INSERT INTO users (email, name) VALUES ('{email}', '{name}')"
    cursor.execute(query)
```

**✅ NEW (SECURE):**
```python
users = [('alice@example.com', 'Alice'), ('bob@example.com', 'Bob')]

db.execute_many(
    "INSERT INTO users (email, name) VALUES (?, ?)",
    users  # All parameterized
)
```

---

### 6. Flask App Security

**❌ OLD (app.py):**
```python
from flask import Flask, request, jsonify
import pickle

app = Flask(__name__)

@app.route('/api/search', methods=['POST'])
def search():
    query = request.json.get('query')

    # No auth, no validation, no rate limiting
    results = search_documents(query)
    return jsonify(results)

# Pickle deserialization - RCE vulnerability!
with open('index.pkl', 'rb') as f:
    search_index = pickle.load(f)

# Debug mode enabled - exposes stack traces!
app.run(debug=True, host='0.0.0.0')
```

**✅ NEW (app_secure.py):**
```python
from flask import Flask, request, jsonify, g
from security.input_validator_fixed import InputValidator
from auth.auth0_handler import Auth0Handler, RateLimiter

app = Flask(__name__)
app.config['DEBUG'] = False  # Disabled!

auth = Auth0Handler()
rate_limiter = RateLimiter(requests_per_minute=100)
validator = InputValidator()

@app.route('/api/search', methods=['POST'])
@auth.requires_auth  # Authentication required
@rate_limiter.rate_limit()  # Rate limited
def search():
    query = request.json.get('query')

    # Input validation
    clean_query = validator.sanitize_for_display(query, max_length=500)

    # Audit logging
    user_id = g.current_user.id
    audit_logger.log_rag_query(user_id, query_hash, response_hash)

    results = search_documents(clean_query)
    return jsonify(results)

# Build index from JSON (no pickle!)
search_index = build_search_index_safe()

# Bind to localhost only
app.run(debug=False, host='127.0.0.1')
```

---

## 📝 IMPORT CHANGES

### Update Your Imports:

```python
# ❌ OLD:
from security.input_validator import InputValidator, sanitize_input

# ✅ NEW:
from security.input_validator_fixed import InputValidator, validate_input

# ✅ ADD:
from security.secure_database import SecureDatabase, UserRepository
```

---

## 🧪 TESTING YOUR MIGRATION

### Step 1: Find All SQL Queries

```bash
cd /Users/badri/Documents/Clustering/2nd-brain/backend

# Find all SQL queries in your code
grep -r "cursor.execute" . --include="*.py" | grep -v "__pycache__"
grep -r "\.execute(" . --include="*.py" | grep -v "__pycache__"
```

### Step 2: Check for String Formatting in SQL

```bash
# Find potentially vulnerable SQL
grep -r "f\".*SELECT\|INSERT\|UPDATE\|DELETE" . --include="*.py"
grep -r "f'.*SELECT\|INSERT\|UPDATE\|DELETE" . --include="*.py"
grep -r "% .*SELECT\|INSERT\|UPDATE\|DELETE" . --include="*.py"
```

### Step 3: Replace With Parameterized Queries

For each match, convert to:
```python
# Before:
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# After:
db.execute_query("SELECT * FROM users WHERE id = ?", (user_id,))
```

---

## ✅ VERIFICATION CHECKLIST

After migration, verify:

- [ ] No f-strings or % formatting in SQL queries
- [ ] All `cursor.execute()` calls use parameterized queries
- [ ] No `pickle.load()` or `pickle.loads()` for untrusted data
- [ ] Flask app uses `app_secure.py`
- [ ] `DEBUG = False` in production
- [ ] Input validation uses `input_validator_fixed.py`
- [ ] Auth0 decorators added to API routes
- [ ] Rate limiting enabled
- [ ] HTTPS enforced

---

## 🔍 COMMON MISTAKES TO AVOID

### Mistake 1: Using Validation Instead of Parameterization

```python
# ❌ WRONG:
email = validator.validate_email(user_input)
query = f"SELECT * FROM users WHERE email = '{email}'"  # Still vulnerable!

# ✅ RIGHT:
email = validator.validate_email(user_input)  # Format check
db.execute_query("SELECT * FROM users WHERE email = ?", (email,))  # Parameterized
```

### Mistake 2: Parameterizing Column Names

```python
# ❌ WRONG - You cannot parameterize column names:
db.execute_query("SELECT ? FROM users", (column_name,))

# ✅ RIGHT - Whitelist allowed columns:
allowed_columns = ['id', 'email', 'name']
if column_name not in allowed_columns:
    raise ValueError("Invalid column")
query = f"SELECT {column_name} FROM users"  # Safe after whitelist
```

### Mistake 3: Parameterizing LIMIT

```python
# ❌ WRONG - LIMIT cannot be parameterized in some databases:
db.execute_query("SELECT * FROM users LIMIT ?", (limit,))

# ✅ RIGHT - Validate as integer first:
clean_limit = validator.validate_integer(limit, min_value=1, max_value=100)
db.execute_query(f"SELECT * FROM users LIMIT {clean_limit}")  # Safe after validation
```

---

## 📞 NEED HELP?

**Documentation Files:**
- `CRITICAL_SECURITY_VULNERABILITIES_FIXED.md` - Detailed vulnerability analysis
- `SECURITY_PROCEDURES.md` - Complete security procedures
- `QUICK_START_SECURITY.md` - 20-minute quick start

**Example Code:**
- `security/secure_database.py` - Run to see SQL injection prevention demo
- `security/input_validator_fixed.py` - Run to test validation

**Get Help:**
```bash
# Run SQL injection demonstration
python3 security/secure_database.py

# Test input validation
python3 security/input_validator_fixed.py

# Start secure app
python3 app_secure.py
```

---

## 🎯 PRIORITY ORDER

1. **CRITICAL (Do Today):**
   - Replace all SQL queries with parameterized versions
   - Use `app_secure.py` instead of `app.py`

2. **HIGH (This Week):**
   - Rotate exposed API keys
   - Set up external log shipping
   - Enable Auth0 authentication

3. **MEDIUM (This Month):**
   - Improve PII sanitization (add NER)
   - Set up monitoring/alerting
   - Schedule penetration test

---

**Last Updated:** December 7, 2024
**Migration Status:** Ready for deployment
