#!/usr/bin/env python3
"""
Cross-platform desktop notifications
Works on macOS, Linux, and Windows

Usage:
    python3 desktop_notify.py "Title" "Message" --urgent
    python3 desktop_notify.py "Git Push" "Action required!"
"""

import sys
import platform
import subprocess
import argparse


def notify_macos(title, message, sound="Glass", urgent=False):
    """Send notification on macOS"""
    try:
        # Escape quotes and special characters for AppleScript
        title_escaped = title.replace('"', '\\"').replace('\\', '\\\\')
        message_escaped = message.replace('"', '\\"').replace('\\', '\\\\')

        # Display notification
        script = f'display notification "{message_escaped}" with title "{title_escaped}" sound name "{sound}"'
        subprocess.run(['osascript', '-e', script], check=True)

        # For urgent, show alert dialog
        if urgent:
            alert_script = f'display alert "{title_escaped}" message "{message_escaped}" as critical'
            subprocess.run(['osascript', '-e', alert_script], check=True)

            # Say it out loud
            subprocess.run(['say', message], check=False)

        return True
    except Exception as e:
        print(f"⚠️  Notification failed: {e}")
        return False


def notify_linux(title, message, urgent=False):
    """Send notification on Linux using notify-send"""
    try:
        urgency = "critical" if urgent else "normal"
        subprocess.run([
            'notify-send',
            '-u', urgency,
            title,
            message
        ], check=True)

        # For urgent, also try to beep
        if urgent:
            subprocess.run(['paplay', '/usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga'], check=False)

        return True
    except FileNotFoundError:
        print("⚠️  notify-send not found. Install: sudo apt-get install libnotify-bin")
        return False
    except Exception as e:
        print(f"⚠️  Notification failed: {e}")
        return False


def notify_windows(title, message, urgent=False):
    """Send notification on Windows using PowerShell"""
    try:
        # Windows 10+ Toast notification
        script = f"""
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.UI.Notifications.ToastNotification, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

$template = @"
<toast>
    <visual>
        <binding template="ToastText02">
            <text id="1">{title}</text>
            <text id="2">{message}</text>
        </binding>
    </visual>
</toast>
"@

$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml($template)
$toast = New-Object Windows.UI.Notifications.ToastNotification $xml
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Python").Show($toast)
"""
        subprocess.run(['powershell', '-Command', script], check=True)
        return True
    except Exception as e:
        print(f"⚠️  Notification failed: {e}")
        return False


def send_notification(title, message, urgent=False):
    """Send notification based on platform"""
    system = platform.system()

    if system == "Darwin":
        return notify_macos(title, message, urgent=urgent)
    elif system == "Linux":
        return notify_linux(title, message, urgent=urgent)
    elif system == "Windows":
        return notify_windows(title, message, urgent=urgent)
    else:
        print(f"⚠️  Notifications not supported on {system}")
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send desktop notifications")
    parser.add_argument("title", help="Notification title")
    parser.add_argument("message", help="Notification message")
    parser.add_argument("--urgent", "-u", action="store_true", help="Mark as urgent (critical alert)")
    parser.add_argument("--sound", "-s", default="Glass", help="Sound to play (macOS only)")

    args = parser.parse_args()

    success = send_notification(args.title, args.message, urgent=args.urgent)
    sys.exit(0 if success else 1)
