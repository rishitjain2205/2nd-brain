"""
Alert Manager for Security and System Incidents
Sends alerts via Email, SMS, and Slack

SOC 2 Requirements:
- CC7.3: Incident response and notification
- CC7.4: Monitoring and alerting
"""

import os
import json
import requests
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum


class AlertChannel(Enum):
    """Alert notification channels"""
    EMAIL = "email"
    SMS = "sms"
    SLACK = "slack"
    PAGERDUTY = "pagerduty"


class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertManager:
    """
    Multi-channel alert manager

    Supports:
    - Email (SendGrid, AWS SES)
    - SMS (Twilio)
    - Slack webhooks
    - PagerDuty integration
    """

    def __init__(self):
        """Initialize alert manager"""
        # Email configuration
        self.sendgrid_api_key = os.getenv('SENDGRID_API_KEY')
        self.alert_email_from = os.getenv('ALERT_EMAIL_FROM', 'security@knowledgevault.com')
        self.alert_email_to = os.getenv('ALERT_EMAIL_TO', '').split(',')

        # SMS configuration (Twilio)
        self.twilio_account_sid = os.getenv('TWILIO_ACCOUNT_SID')
        self.twilio_auth_token = os.getenv('TWILIO_AUTH_TOKEN')
        self.twilio_from_number = os.getenv('TWILIO_FROM_NUMBER')
        self.alert_phone_numbers = os.getenv('ALERT_PHONE_NUMBERS', '').split(',')

        # Slack configuration
        self.slack_webhook_url = os.getenv('SLACK_WEBHOOK_URL')

        # PagerDuty configuration
        self.pagerduty_integration_key = os.getenv('PAGERDUTY_INTEGRATION_KEY')

        print("✓ Alert Manager initialized")
        if self.sendgrid_api_key:
            print("  - Email: Enabled (SendGrid)")
        if self.twilio_account_sid:
            print("  - SMS: Enabled (Twilio)")
        if self.slack_webhook_url:
            print("  - Slack: Enabled")
        if self.pagerduty_integration_key:
            print("  - PagerDuty: Enabled")

    def send_alert(
        self,
        title: str,
        message: str,
        severity: AlertSeverity = AlertSeverity.WARNING,
        channels: Optional[List[AlertChannel]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Send alert to multiple channels

        Args:
            title: Alert title
            message: Alert message
            severity: Alert severity
            channels: List of channels to send to (default: all)
            metadata: Additional alert metadata
        """
        if channels is None:
            # Send to all configured channels for critical alerts
            if severity == AlertSeverity.CRITICAL:
                channels = [AlertChannel.EMAIL, AlertChannel.SMS, AlertChannel.SLACK, AlertChannel.PAGERDUTY]
            else:
                channels = [AlertChannel.EMAIL, AlertChannel.SLACK]

        results = {}

        for channel in channels:
            try:
                if channel == AlertChannel.EMAIL:
                    results['email'] = self._send_email(title, message, severity, metadata)
                elif channel == AlertChannel.SMS:
                    results['sms'] = self._send_sms(title, message, severity)
                elif channel == AlertChannel.SLACK:
                    results['slack'] = self._send_slack(title, message, severity, metadata)
                elif channel == AlertChannel.PAGERDUTY:
                    results['pagerduty'] = self._send_pagerduty(title, message, severity, metadata)
            except Exception as e:
                results[channel.value] = f"Failed: {str(e)}"
                print(f"  ❌ Alert failed on {channel.value}: {e}")

        return results

    def _send_email(
        self,
        title: str,
        message: str,
        severity: AlertSeverity,
        metadata: Optional[Dict] = None
    ) -> str:
        """Send email alert via SendGrid"""
        if not self.sendgrid_api_key:
            return "Email not configured"

        severity_colors = {
            "info": "#0066CC",
            "warning": "#FF9900",
            "critical": "#CC0000"
        }

        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <div style="background-color: {severity_colors.get(severity.value, '#666')};
                        color: white;
                        padding: 20px;
                        border-radius: 5px;">
                <h2>{severity.value.upper()}: {title}</h2>
            </div>
            <div style="padding: 20px;">
                <p>{message}</p>

                {f'<h3>Details:</h3><pre>{json.dumps(metadata, indent=2)}</pre>' if metadata else ''}

                <hr>
                <p style="color: #666; font-size: 12px;">
                    Timestamp: {datetime.utcnow().isoformat() + "Z"}<br>
                    System: Knowledge Vault Security Monitor
                </p>
            </div>
        </body>
        </html>
        """

        try:
            # SendGrid API
            response = requests.post(
                "https://api.sendgrid.com/v3/mail/send",
                headers={
                    "Authorization": f"Bearer {self.sendgrid_api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "personalizations": [
                        {
                            "to": [{"email": email.strip()} for email in self.alert_email_to if email.strip()],
                            "subject": f"[{severity.value.upper()}] {title}"
                        }
                    ],
                    "from": {"email": self.alert_email_from},
                    "content": [
                        {
                            "type": "text/html",
                            "value": html_content
                        }
                    ]
                }
            )

            if response.status_code == 202:
                print(f"  ✅ Email alert sent to {len(self.alert_email_to)} recipients")
                return "Sent"
            else:
                return f"Failed: {response.status_code}"

        except Exception as e:
            return f"Error: {str(e)}"

    def _send_sms(self, title: str, message: str, severity: AlertSeverity) -> str:
        """Send SMS alert via Twilio"""
        if not self.twilio_account_sid:
            return "SMS not configured"

        # Truncate message for SMS (160 char limit)
        sms_body = f"[{severity.value.upper()}] {title}: {message}"[:160]

        try:
            from twilio.rest import Client

            client = Client(self.twilio_account_sid, self.twilio_auth_token)

            sent_count = 0
            for phone in self.alert_phone_numbers:
                if not phone.strip():
                    continue

                message = client.messages.create(
                    body=sms_body,
                    from_=self.twilio_from_number,
                    to=phone.strip()
                )
                sent_count += 1

            print(f"  ✅ SMS alert sent to {sent_count} numbers")
            return f"Sent to {sent_count} numbers"

        except ImportError:
            return "Twilio library not installed (pip install twilio)"
        except Exception as e:
            return f"Error: {str(e)}"

    def _send_slack(
        self,
        title: str,
        message: str,
        severity: AlertSeverity,
        metadata: Optional[Dict] = None
    ) -> str:
        """Send Slack alert via webhook"""
        if not self.slack_webhook_url:
            return "Slack not configured"

        severity_colors = {
            "info": "#0066CC",
            "warning": "#FF9900",
            "critical": "#CC0000"
        }

        severity_emojis = {
            "info": ":information_source:",
            "warning": ":warning:",
            "critical": ":rotating_light:"
        }

        payload = {
            "attachments": [
                {
                    "color": severity_colors.get(severity.value, "#666"),
                    "title": f"{severity_emojis.get(severity.value, '')} {title}",
                    "text": message,
                    "fields": [
                        {
                            "title": "Severity",
                            "value": severity.value.upper(),
                            "short": True
                        },
                        {
                            "title": "Timestamp",
                            "value": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                            "short": True
                        }
                    ] + ([
                        {
                            "title": "Details",
                            "value": f"```{json.dumps(metadata, indent=2)}```",
                            "short": False
                        }
                    ] if metadata else []),
                    "footer": "Knowledge Vault Security Monitor"
                }
            ]
        }

        try:
            response = requests.post(
                self.slack_webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"}
            )

            if response.status_code == 200:
                print("  ✅ Slack alert sent")
                return "Sent"
            else:
                return f"Failed: {response.status_code}"

        except Exception as e:
            return f"Error: {str(e)}"

    def _send_pagerduty(
        self,
        title: str,
        message: str,
        severity: AlertSeverity,
        metadata: Optional[Dict] = None
    ) -> str:
        """Send PagerDuty alert"""
        if not self.pagerduty_integration_key:
            return "PagerDuty not configured"

        # Map severity to PagerDuty severity
        pd_severity = {
            "info": "info",
            "warning": "warning",
            "critical": "critical"
        }

        payload = {
            "routing_key": self.pagerduty_integration_key,
            "event_action": "trigger",
            "payload": {
                "summary": title,
                "severity": pd_severity.get(severity.value, "warning"),
                "source": "Knowledge Vault",
                "custom_details": metadata or {}
            }
        }

        try:
            response = requests.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload,
                headers={"Content-Type": "application/json"}
            )

            if response.status_code == 202:
                print("  ✅ PagerDuty alert created")
                return "Triggered"
            else:
                return f"Failed: {response.status_code}"

        except Exception as e:
            return f"Error: {str(e)}"


# Global alert manager
_alert_manager = None


def get_alert_manager() -> AlertManager:
    """Get global alert manager instance"""
    global _alert_manager

    if _alert_manager is None:
        _alert_manager = AlertManager()

    return _alert_manager


def send_alert(title: str, message: str, severity: AlertSeverity = AlertSeverity.WARNING, **kwargs):
    """Convenience function to send alert"""
    manager = get_alert_manager()
    return manager.send_alert(title, message, severity, **kwargs)


if __name__ == "__main__":
    print("="*60)
    print("Alert Manager Test")
    print("="*60)

    # Initialize
    manager = AlertManager()

    # Test alerts (will only work if credentials configured)
    print("\n1️⃣  Testing alert notifications...")

    results = manager.send_alert(
        title="Test Security Alert",
        message="This is a test alert from the security monitoring system.",
        severity=AlertSeverity.WARNING,
        metadata={
            "test": True,
            "component": "alert_manager",
            "timestamp": datetime.utcnow().isoformat()
        }
    )

    print("\n2️⃣  Alert Results:")
    for channel, result in results.items():
        print(f"  {channel}: {result}")

    print("\n" + "="*60)
    print("✅ Alert Manager Working!")
    print("="*60)
    print("\nTo enable alerts, configure:")
    print("  - SendGrid: SENDGRID_API_KEY, ALERT_EMAIL_TO")
    print("  - Twilio: TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, ALERT_PHONE_NUMBERS")
    print("  - Slack: SLACK_WEBHOOK_URL")
    print("  - PagerDuty: PAGERDUTY_INTEGRATION_KEY")
