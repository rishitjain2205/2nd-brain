# 2nd Brain - Security Procedures

**Date:** December 7, 2024
**Status:** 🔴 **IMMEDIATE ACTION REQUIRED**

---

## 🚨 CRITICAL: API Keys Exposed to Git

Your API keys were committed to git history. **You must rotate them immediately.**

### Exposed Keys (Found in Git Commits):
1. ✅ `AZURE_OPENAI_API_KEY` - **ROTATE NOW**
2. ✅ `JWT_SECRET_KEY` - **ROTATE NOW**
3. ✅ `ENCRYPTION_KEY` - **ROTATE NOW**
4. ✅ `AUDIT_HMAC_SECRET` - **ROTATE NOW**
5. ✅ `AZURE_ANTHROPIC_API_KEY` - **ROTATE NOW**

---

## 📋 IMMEDIATE ACTION CHECKLIST

### Step 1: Rotate Azure OpenAI API Key (5 minutes)

```bash
# 1. Go to Azure Portal
open https://portal.azure.com

# 2. Navigate to: Your Resource > Keys and Endpoint
# 3. Click "Regenerate Key1" or "Regenerate Key2"
# 4. Copy the new key
# 5. Update your .env file:
nano .env

# Replace:
AZURE_OPENAI_API_KEY=YOUR_NEW_KEY_HERE
```

### Step 2: Rotate Azure Anthropic API Key (5 minutes)

```bash
# Same process as Azure OpenAI
# Go to your Azure Anthropic resource and regenerate keys
```

### Step 3: Generate New Security Keys (2 minutes)

```bash
# 1. Generate new JWT secret
python3 -c "import secrets; print('JWT_SECRET_KEY=' + secrets.token_hex(32))"

# 2. Generate new HMAC secret
python3 -c "import secrets; print('AUDIT_HMAC_SECRET=' + secrets.token_hex(32))"

# 3. Generate new encryption key
python3 -c "from cryptography.fernet import Fernet; print('ENCRYPTION_KEY=' + Fernet.generate_key().decode())"

# 4. Update .env with the new values
```

### Step 4: Verify .env is Not Tracked (1 minute)

```bash
# Check git status
cd /Users/badri/Documents/Clustering/2nd-brain/backend
git status

# Verify .env is NOT listed
# If it is listed, add it to .gitignore:
echo ".env" >> .gitignore
git rm --cached .env  # Remove from git (keeps local file)
git commit -m "Remove .env from version control"
```

### Step 5: Clean Git History (OPTIONAL - Advanced)

⚠️ **WARNING**: This rewrites git history and breaks existing clones!

```bash
# Use BFG Repo-Cleaner to remove secrets from history
brew install bfg  # macOS
# or download from: https://rtyley.github.io/bfg-repo-cleaner/

# Create a file with secrets to remove
cat > secrets.txt <<EOF
AZURE_OPENAI_API_KEY
YOUR_EXPOSED_AZURE_KEY_HERE_REDACTED
YOUR_EXPOSED_JWT_SECRET_HERE_REDACTED
YOUR_EXPOSED_HMAC_SECRET_HERE_REDACTED
YOUR_EXPOSED_ENCRYPTION_KEY_HERE_REDACTED
EOF

# Clean the repo
cd /Users/badri/Documents/Clustering/2nd-brain
bfg --replace-text secrets.txt .git
git reflog expire --expire=now --all
git gc --prune=now --aggressive

# Force push (WARNING: breaks others' clones)
git push origin --force --all
```

---

## 🔒 Production Deployment Checklist

### 1. Environment Configuration

```bash
# Copy production template
cp .env.production.template .env

# Edit with new keys (from Step 3 above)
nano .env

# Verify permissions (only you can read)
chmod 600 .env
ls -la .env  # Should show: -rw-------
```

### 2. Switch to Secure App

```bash
# Backup current app
cp app.py app_insecure_backup.py

# Use secure version
cp app_secure.py app.py

# Or run secure app directly:
python3 app_secure.py
```

### 3. Configure Auth0 (Optional but Recommended)

```bash
# Sign up: https://auth0.com

# Create new API:
# - Name: 2nd Brain API
# - Identifier: https://api.2ndbrain.com

# Get credentials and add to .env:
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_API_AUDIENCE=https://api.2ndbrain.com
AUTH0_CLIENT_ID=<from Auth0 dashboard>
AUTH0_CLIENT_SECRET=<from Auth0 dashboard>
```

### 4. Enable Authentication on Routes

Edit `app_secure.py`:

```python
# Find this line:
@app.route('/api/search', methods=['POST'])
@rate_limiter.rate_limit()
def api_search():

# Add authentication:
@app.route('/api/search', methods=['POST'])
@auth.requires_auth  # Add this line
@rate_limiter.rate_limit()
def api_search():
```

### 5. Set Up HTTPS Reverse Proxy

**Option A: nginx**

```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:5001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Option B: Apache**

```apache
<VirtualHost *:443>
    ServerName yourdomain.com

    SSLEngine on
    SSLCertificateFile /path/to/cert.pem
    SSLCertificateKeyFile /path/to/key.pem

    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:5001/
    ProxyPassReverse / http://127.0.0.1:5001/
</VirtualHost>
```

### 6. Run Production Server

```bash
# Set production environment
export ENVIRONMENT=production

# Run with gunicorn (production WSGI server)
pip install gunicorn

gunicorn \
    --bind 127.0.0.1:5001 \
    --workers 4 \
    --timeout 120 \
    --access-logfile logs/access.log \
    --error-logfile logs/error.log \
    app_secure:app
```

### 7. Set Up Systemd Service (Linux)

Create `/etc/systemd/system/2ndbrain.service`:

```ini
[Unit]
Description=2nd Brain API Server
After=network.target

[Service]
Type=notify
User=your_user
WorkingDirectory=/Users/badri/Documents/Clustering/2nd-brain/backend
Environment="ENVIRONMENT=production"
ExecStart=/usr/bin/gunicorn \
    --bind 127.0.0.1:5001 \
    --workers 4 \
    app_secure:app

Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start
sudo systemctl enable 2ndbrain
sudo systemctl start 2ndbrain
sudo systemctl status 2ndbrain
```

---

## 🛡️ Security Hardening Checklist

### Application Security

- [x] Disable Flask debug mode
- [x] Input validation on all endpoints
- [x] Rate limiting (100 req/min)
- [x] CORS protection
- [x] HTTPS enforcement
- [x] Security headers (HSTS, CSP, etc.)
- [x] Audit logging (encrypted)
- [ ] Enable Auth0 authentication
- [x] Remove pickle deserialization
- [x] Validate file paths (prevent path traversal)
- [x] Sanitize error messages

### Infrastructure Security

- [ ] Set up HTTPS reverse proxy (nginx/Apache)
- [ ] SSL/TLS certificates (Let's Encrypt)
- [ ] Firewall rules (allow only 443, 80)
- [ ] Bind Flask to 127.0.0.1 (not 0.0.0.0)
- [ ] Use strong server passwords
- [ ] Set up fail2ban (brute force protection)
- [ ] Enable automatic security updates
- [ ] Set up log monitoring (Datadog/Splunk)

### Data Security

- [x] Rotate all exposed API keys
- [x] Use Azure OpenAI (zero retention)
- [x] Encrypt sensitive data at rest
- [x] Encrypted audit logs with HMAC
- [ ] Regular backups
- [ ] Backup encryption
- [ ] Data retention policy
- [ ] Secure data disposal procedures

### Access Control

- [ ] Enable MFA for all accounts
- [ ] Strong password policy
- [ ] Regular access reviews
- [ ] Principle of least privilege
- [ ] SSH key-based authentication
- [ ] Disable root SSH login

---

## 📊 Security Monitoring

### Log Locations

```bash
# Application logs
tail -f /Users/badri/Documents/Clustering/2nd-brain/backend/data/logs/app.log

# Audit logs (encrypted)
ls -la /Users/badri/Documents/Clustering/2nd-brain/backend/data/audit_logs/

# System logs
tail -f /var/log/syslog  # Linux
tail -f /var/log/system.log  # macOS
```

### Security Audit Commands

```bash
# Check for exposed secrets in code
cd /Users/badri/Documents/Clustering/2nd-brain/backend
grep -r "api_key\|secret\|password" . --exclude-dir=node_modules --exclude-dir=.git

# Check file permissions
find . -type f -perm -004  # World-readable files
find . -type f -perm -002  # World-writable files

# Check for security updates
pip list --outdated

# Run security audit
pip install safety
safety check

# Check for vulnerable dependencies
pip install pip-audit
pip-audit
```

---

## 🚨 Incident Response

### If You Detect a Security Breach:

1. **Immediate Actions:**
   ```bash
   # Stop the application
   sudo systemctl stop 2ndbrain  # or Ctrl+C

   # Rotate all keys immediately
   # (Follow steps in "IMMEDIATE ACTION CHECKLIST" above)

   # Review audit logs
   cd data/audit_logs
   python3 -c "from security.audit_logger import AuditLogger; logger = AuditLogger(); print(logger.get_audit_summary(days=7))"
   ```

2. **Investigation:**
   - Check access logs for suspicious activity
   - Review audit logs for unauthorized queries
   - Check system logs for intrusion attempts

3. **Recovery:**
   - Patch vulnerabilities
   - Restore from clean backup if compromised
   - Update all credentials
   - Notify affected users (if applicable)

4. **Post-Incident:**
   - Document the incident
   - Update security procedures
   - Run security audit
   - Conduct training if needed

---

## 📚 Security Resources

### Documentation
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Flask Security Best Practices](https://flask.palletsprojects.com/en/3.0.x/security/)
- [Auth0 Documentation](https://auth0.com/docs)
- [Azure Security Best Practices](https://learn.microsoft.com/en-us/azure/security/)

### Tools
- [safety](https://pypi.org/project/safety/) - Python dependency vulnerability scanner
- [bandit](https://github.com/PyCQA/bandit) - Python security linter
- [BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/) - Remove secrets from git
- [git-secrets](https://github.com/awslabs/git-secrets) - Prevent committing secrets

---

## ✅ Monthly Security Checklist

- [ ] Review audit logs
- [ ] Check for dependency updates
- [ ] Run security scans
- [ ] Test backups
- [ ] Review access controls
- [ ] Update security documentation
- [ ] Test incident response procedures

---

**Last Updated:** December 7, 2024
**Next Review:** January 7, 2025
