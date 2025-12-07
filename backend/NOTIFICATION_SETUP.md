# Desktop Notifications Setup

Get notified when git push fails or needs your attention!

## 🚀 Quick Start (30 seconds)

### Option 1: Use the notification wrapper

```bash
# Instead of: git push origin main
# Use:
./git-push-notify.sh main
```

**What happens:**
- ✅ Success → Pleasant notification + sound
- ❌ Failure → Alert notification + voice alert
- 🚨 Secret detected → **CRITICAL ALERT** (requires your click to dismiss)

### Option 2: Create a git alias

```bash
# Add to your .gitconfig or run:
git config --global alias.pn '!bash git-push-notify.sh'

# Now you can use:
git pn main
```

---

## 📢 Notification Types

### 1. Success Notification
```
✅ Git Push
Git push completed successfully!
Sound: Glass
```

### 2. Failure Notification
```
❌ Git Push Failed
Push failed. Check terminal for details.
Sound: Basso
Voice: "Push failed. Check terminal."
```

### 3. Secret Detected (URGENT)
```
🚨 GIT PUSH BLOCKED
⚠️ GITHUB DETECTED A SECRET! Action required.
Sound: Basso (loud)
Voice: "Attention! GitHub detected a secret..."
Alert Dialog: Requires click to dismiss
```

---

## 🔧 Advanced Usage

### Test notifications

```bash
# Test a simple notification
./notify.sh "Test" "Hello World"

# Test an urgent notification
./notify.sh "🚨 URGENT" "Action required!"

# Test with Python (cross-platform)
python3 desktop_notify.py "Test" "Hello World"
python3 desktop_notify.py "URGENT" "Action required!" --urgent
```

### Use in your own scripts

```bash
#!/bin/bash
# Your script here
if [ $? -ne 0 ]; then
    ./notify.sh "🚨 Build Failed" "Check the logs!" "Basso"
fi
```

### Python integration

```python
import subprocess

def notify_user(title, message, urgent=False):
    cmd = ['python3', 'desktop_notify.py', title, message]
    if urgent:
        cmd.append('--urgent')
    subprocess.run(cmd)

# Usage
notify_user("🚨 API Key Rotation", "Rotate your keys NOW!", urgent=True)
```

---

## 🎨 Customization

### Change sounds (macOS)

Available sounds:
- `Glass` (default, pleasant)
- `Basso` (alert, louder)
- `Blow` (notification)
- `Bottle` (subtle)
- `Frog` (fun)
- `Funk` (distinctive)
- `Hero` (triumphant)
- `Morse` (technical)
- `Ping` (attention)
- `Pop` (quick)
- `Purr` (subtle)
- `Sosumi` (classic)
- `Submarine` (deep)
- `Tink` (light)

Edit `git-push-notify.sh` line 14:
```bash
osascript -e 'display notification "..." sound name "Funk"'
```

### Disable voice alerts

Comment out lines with `say`:
```bash
# say "Push successful"  # Commented out
```

---

## 🔔 Auto-watch for approvals (Advanced)

Create a wrapper that monitors Claude Code sessions:

```bash
# watch-claude.sh
#!/bin/bash
while true; do
    if pgrep -f "claude" > /dev/null; then
        # Check if waiting for input
        if lsof -p $(pgrep -f claude) | grep -q "LISTEN"; then
            ./notify.sh "⏳ Claude Waiting" "Approval needed!"
        fi
    fi
    sleep 5
done
```

---

## 📱 Mobile Notifications (Optional)

### Option 1: Use Pushover (iOS/Android)

```bash
# Install
pip install pushover-complete

# Send notification
python3 << EOF
from pushover import Client
client = Client("YOUR_USER_KEY", api_token="YOUR_API_TOKEN")
client.send_message("Git push blocked!", title="🚨 Action Required")
EOF
```

### Option 2: Use IFTTT Webhooks

```bash
# Send to IFTTT
curl -X POST https://maker.ifttt.com/trigger/git_push_failed/with/key/YOUR_KEY \
  -d '{"value1":"Secret detected"}'
```

---

## 🚨 Recommended Setup

Add this to your `~/.zshrc` or `~/.bashrc`:

```bash
# Git push with notifications
alias gp='bash ~/Documents/Clustering/2nd-brain/backend/git-push-notify.sh'

# Quick notify command
alias notify='python3 ~/Documents/Clustering/2nd-brain/backend/desktop_notify.py'
```

Now you can use:
```bash
gp main  # Push with notifications
notify "Done" "Task completed!"  # Send notification
```

---

## ⚙️ Troubleshooting

### macOS: Notifications not showing

1. Check System Preferences → Notifications
2. Allow notifications for "Script Editor" or "Terminal"
3. Try: `osascript -e 'display notification "test"'`

### Linux: notify-send not found

```bash
sudo apt-get install libnotify-bin  # Debian/Ubuntu
sudo yum install libnotify           # RedHat/CentOS
```

### Windows: Notifications not working

Run PowerShell as Administrator and enable toast notifications:
```powershell
Set-ExecutionPolicy RemoteSigned
```

---

## 📖 Files Created

- `git-push-notify.sh` - Git push with notifications
- `notify.sh` - Simple notification helper (bash)
- `desktop_notify.py` - Cross-platform notifications (Python)
- `NOTIFICATION_SETUP.md` - This file

---

## 🎯 Quick Reference

```bash
# Push with notifications (recommended)
./git-push-notify.sh main

# Send notification
./notify.sh "Title" "Message"

# Send urgent notification
python3 desktop_notify.py "Title" "Message" --urgent

# Test your setup
./notify.sh "✅ Setup Complete" "Notifications working!"
```

---

**Never miss an important git push failure again!** 🎉
