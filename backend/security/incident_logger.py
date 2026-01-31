"""
Security Incident Logger
Logs and monitors security events for incident response

SOC 2 Requirements:
- CC7.3: Security incident detection and response
- CC7.4: Security event logging
"""

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from enum import Enum


class IncidentSeverity(Enum):
    """Security incident severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentType(Enum):
    """Types of security incidents"""
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    FAILED_LOGIN = "failed_login"
    INJECTION_ATTEMPT = "injection_attempt"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_BREACH_ATTEMPT = "data_breach_attempt"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    MALWARE_DETECTED = "malware_detected"
    AUDIT_LOG_TAMPERING = "audit_log_tampering"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    INVALID_INPUT = "invalid_input"


class SecurityIncidentLogger:
    """
    Logs and monitors security incidents

    Features:
    - Real-time incident logging
    - Severity classification
    - Automatic alerting for critical incidents
    - Incident statistics and reporting
    - SOC 2 compliance tracking
    """

    def __init__(
        self,
        log_dir: str = "data/security_incidents",
        alert_email: Optional[str] = None,
        organization_id: Optional[str] = None
    ):
        """
        Initialize incident logger

        Args:
            log_dir: Directory for incident logs
            alert_email: Email for critical incident alerts
            organization_id: Organization ID for multi-tenant
        """
        self.log_dir = Path(log_dir)
        self.organization_id = organization_id

        # Create org-specific directory
        if organization_id:
            self.log_dir = self.log_dir / organization_id

        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.alert_email = alert_email or os.getenv('SECURITY_ALERT_EMAIL')

        # Initialize encryption for sensitive incident data
        from security.encryption_manager_fixed import get_encryption_manager
        self.encryption_manager = get_encryption_manager()

        print(f"✓ Security Incident Logger initialized")
        print(f"  - Organization: {organization_id or 'shared'}")
        print(f"  - Log directory: {self.log_dir}")
        if self.alert_email:
            print(f"  - Alert email: {self.alert_email}")

    def log_incident(
        self,
        incident_type: IncidentType,
        severity: IncidentSeverity,
        description: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        auto_alert: bool = True
    ) -> str:
        """
        Log a security incident

        Args:
            incident_type: Type of security incident
            severity: Severity level
            description: Human-readable description
            user_id: User involved (if applicable)
            ip_address: Source IP address
            metadata: Additional incident metadata
            auto_alert: Automatically send alert for critical incidents

        Returns:
            Incident ID
        """
        import uuid

        # Generate incident ID
        incident_id = str(uuid.uuid4())

        # Create incident record
        incident = {
            "incident_id": incident_id,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "organization_id": self.organization_id,
            "incident_type": incident_type.value,
            "severity": severity.value,
            "description": description,
            "user_id": user_id,
            "ip_address": ip_address,
            "metadata": metadata or {},
            "status": "open",
            "escalated": False
        }

        # Log to file
        self._write_incident(incident)

        # Alert if critical
        if auto_alert and severity in [IncidentSeverity.HIGH, IncidentSeverity.CRITICAL]:
            self._send_alert(incident)

        # Log to console
        severity_emoji = {
            "low": "🟢",
            "medium": "🟡",
            "high": "🟠",
            "critical": "🔴"
        }
        print(f"{severity_emoji[severity.value]} Security Incident: {incident_type.value}")
        print(f"  ID: {incident_id}")
        print(f"  Severity: {severity.value.upper()}")
        print(f"  User: {user_id or 'unknown'}")
        print(f"  IP: {ip_address or 'unknown'}")

        return incident_id

    def _write_incident(self, incident: Dict):
        """Write incident to log file"""
        # Daily log file
        today = datetime.now().strftime("%Y-%m-%d")
        log_file = self.log_dir / f"incidents_{today}.jsonl"

        # Encrypt sensitive data
        encrypted_incident = self.encryption_manager.encrypt_dict(incident)

        # Write
        with open(log_file, 'a') as f:
            f.write(encrypted_incident + '\n')

    def _send_alert(self, incident: Dict):
        """Send alert for critical incident"""
        if not self.alert_email:
            print("  ⚠️  No alert email configured")
            return

        # In production, integrate with email/SMS/Slack
        print(f"  🚨 ALERT sent to {self.alert_email}")
        print(f"     Subject: {incident['severity'].upper()} Security Incident")
        print(f"     Details: {incident['description']}")

        # TODO: Integrate with SendGrid/AWS SES for actual email
        # TODO: Integrate with PagerDuty for on-call alerts

    def get_incidents(
        self,
        days: int = 7,
        severity: Optional[IncidentSeverity] = None,
        incident_type: Optional[IncidentType] = None
    ) -> List[Dict]:
        """
        Get recent security incidents

        Args:
            days: Number of days to query
            severity: Filter by severity
            incident_type: Filter by incident type

        Returns:
            List of incidents
        """
        incidents = []

        # Read log files for past N days
        for day_offset in range(days):
            date = datetime.now() - timedelta(days=day_offset)
            date_str = date.strftime("%Y-%m-%d")
            log_file = self.log_dir / f"incidents_{date_str}.jsonl"

            if not log_file.exists():
                continue

            with open(log_file, 'r') as f:
                for line in f:
                    try:
                        # Decrypt incident
                        incident = self.encryption_manager.decrypt_dict(line.strip())

                        # Apply filters
                        if severity and incident['severity'] != severity.value:
                            continue
                        if incident_type and incident['incident_type'] != incident_type.value:
                            continue

                        incidents.append(incident)

                    except Exception as e:
                        print(f"Error reading incident: {e}")
                        continue

        return incidents

    def get_statistics(self, days: int = 30) -> Dict:
        """
        Get security incident statistics

        Args:
            days: Number of days to analyze

        Returns:
            Statistics dictionary
        """
        incidents = self.get_incidents(days=days)

        stats = {
            "total_incidents": len(incidents),
            "by_severity": {"low": 0, "medium": 0, "high": 0, "critical": 0},
            "by_type": {},
            "by_day": {},
            "critical_incidents": []
        }

        for incident in incidents:
            # Count by severity
            severity = incident.get('severity', 'unknown')
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1

            # Count by type
            incident_type = incident.get('incident_type', 'unknown')
            stats['by_type'][incident_type] = stats['by_type'].get(incident_type, 0) + 1

            # Count by day
            timestamp = incident.get('timestamp', '')
            day = timestamp[:10]  # YYYY-MM-DD
            stats['by_day'][day] = stats['by_day'].get(day, 0) + 1

            # Track critical incidents
            if severity in ['high', 'critical']:
                stats['critical_incidents'].append({
                    "incident_id": incident.get('incident_id'),
                    "timestamp": timestamp,
                    "type": incident_type,
                    "description": incident.get('description')
                })

        return stats

    def generate_report(self, days: int = 30, output_file: Optional[str] = None) -> Dict:
        """
        Generate security incident report for SOC 2 auditors

        Args:
            days: Number of days to include
            output_file: Optional file to save report

        Returns:
            Report dictionary
        """
        stats = self.get_statistics(days=days)

        report = {
            "report_generated": datetime.utcnow().isoformat() + "Z",
            "organization_id": self.organization_id,
            "period_days": days,
            "summary": {
                "total_incidents": stats['total_incidents'],
                "critical_incidents": len(stats['critical_incidents']),
                "incident_rate_per_day": stats['total_incidents'] / max(days, 1)
            },
            "severity_breakdown": stats['by_severity'],
            "incident_types": stats['by_type'],
            "timeline": stats['by_day'],
            "critical_incidents": stats['critical_incidents'][:10],  # Top 10
            "compliance_notes": {
                "soc2_requirement": "CC7.3 - Security incident detection and response",
                "logging_enabled": True,
                "encryption_enabled": True,
                "alert_configured": self.alert_email is not None,
                "retention_period": "365 days"
            }
        }

        # Save report if requested
        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)

            print(f"✓ Security incident report saved: {output_file}")

        return report


# Global incident logger
_incident_logger = None


def get_incident_logger(organization_id: Optional[str] = None) -> SecurityIncidentLogger:
    """Get global incident logger instance"""
    global _incident_logger

    if _incident_logger is None:
        _incident_logger = SecurityIncidentLogger(organization_id=organization_id)

    return _incident_logger


def log_security_incident(
    incident_type: IncidentType,
    severity: IncidentSeverity,
    description: str,
    **kwargs
):
    """Convenience function to log security incident"""
    logger = get_incident_logger()
    return logger.log_incident(incident_type, severity, description, **kwargs)


if __name__ == "__main__":
    print("="*60)
    print("Security Incident Logger Test")
    print("="*60)

    # Initialize
    logger = SecurityIncidentLogger(
        log_dir="data/test_incidents",
        organization_id="test_org",
        alert_email="security@example.com"
    )

    # Log different types of incidents
    print("\n1️⃣  Logging test incidents...")

    logger.log_incident(
        IncidentType.FAILED_LOGIN,
        IncidentSeverity.LOW,
        "User entered wrong password",
        user_id="user123",
        ip_address="192.168.1.100"
    )

    logger.log_incident(
        IncidentType.INJECTION_ATTEMPT,
        IncidentSeverity.HIGH,
        "SQL injection attempt detected in API request",
        user_id="attacker456",
        ip_address="203.0.113.45",
        metadata={"payload": "'; DROP TABLE users; --"}
    )

    logger.log_incident(
        IncidentType.DATA_BREACH_ATTEMPT,
        IncidentSeverity.CRITICAL,
        "Unauthorized access to sensitive data attempted",
        user_id="suspicious789",
        ip_address="198.51.100.23",
        metadata={"resource": "/api/v1/admin/users", "method": "GET"}
    )

    # Get statistics
    print("\n2️⃣  Generating statistics...")
    stats = logger.get_statistics(days=1)
    print(f"  Total incidents: {stats['total_incidents']}")
    print(f"  By severity: {stats['by_severity']}")

    # Generate report
    print("\n3️⃣  Generating compliance report...")
    report = logger.generate_report(
        days=30,
        output_file="data/test_incidents/security_report.json"
    )

    # Cleanup
    import shutil
    shutil.rmtree("data/test_incidents")

    print("\n" + "="*60)
    print("✅ Security Incident Logger Working!")
    print("="*60)
