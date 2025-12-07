#!/bin/bash
# Git Push with Desktop Notifications
# Usage: ./git-push-notify.sh [branch]

BRANCH="${1:-main}"

echo "🚀 Pushing to origin/$BRANCH..."

# Try to push
OUTPUT=$(git push origin "$BRANCH" 2>&1)
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    # Success - NO NOTIFICATION (user doesn't want alerts for success)
    echo "✅ Push successful!"

else
    # Failure - need attention!
    echo "❌ Push failed!"
    echo "$OUTPUT"

    # Check if it's a secret/push protection issue - NEEDS USER ACTION
    if echo "$OUTPUT" | grep -q "GITHUB PUSH PROTECTION\|secret"; then
        # URGENT: Secret detected - USER MUST FIX THIS
        osascript -e 'display notification "⚠️ GITHUB DETECTED A SECRET! You need to fix the commit." with title "🚨 ACTION REQUIRED" sound name "Basso"'

        # Voice alert
        say "Action required! GitHub detected a secret."

        # Show critical alert dialog that requires click
        osascript -e 'display alert "🚨 ACTION REQUIRED" message "GitHub detected a secret in your commit.\n\nYou must fix this before pushing can continue.\n\nCheck your terminal for details." as critical'

    # Note: No notification for other errors - user said only alert when action needed
    fi

    exit $EXIT_CODE
fi
