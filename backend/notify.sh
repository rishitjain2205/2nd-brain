#!/bin/bash
# Universal notification helper
# Usage: ./notify.sh "Title" "Message" [sound]

TITLE="$1"
MESSAGE="$2"
SOUND="${3:-Glass}"  # Default sound: Glass

# Desktop notification (macOS)
osascript -e "display notification \"$MESSAGE\" with title \"$TITLE\" sound name \"$SOUND\""

# Optional: Say it out loud (uncomment if you want)
# say "$MESSAGE"

# For urgent alerts, use critical alert
if [[ "$TITLE" == *"🚨"* ]] || [[ "$TITLE" == *"URGENT"* ]]; then
    osascript -e "display alert \"$TITLE\" message \"$MESSAGE\" as critical"
fi
