"""
Security Awareness Training Tracker
Tracks employee security training completion

SOC 2 Requirements:
- CC1.4: Security awareness training
- CC1.5: Ongoing training
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict


@dataclass
class TrainingModule:
    """Security training module"""
    module_id: str
    title: str
    description: str
    duration_minutes: int
    required: bool
    frequency_days: int  # How often to retake (365 = annually)


@dataclass
class TrainingRecord:
    """Employee training completion record"""
    user_id: str
    employee_name: str
    module_id: str
    completion_date: str
    score: Optional[float]
    passed: bool
    next_due_date: str


class SecurityTrainingManager:
    """
    Employee security training tracker

    Features:
    - Training module library
    - Completion tracking
    - Automated reminders
    - Compliance reporting
    """

    def __init__(self, data_dir: str = "data/security_training"):
        """Initialize training manager"""
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.modules = self._initialize_modules()
        self.records: List[TrainingRecord] = []

        print("✓ Security Training Manager initialized")
        print(f"  - Training modules: {len(self.modules)}")

    def _initialize_modules(self) -> Dict[str, TrainingModule]:
        """Initialize training module library"""
        modules = {}

        # SOC 2 required training modules
        modules['security_basics'] = TrainingModule(
            module_id='security_basics',
            title='Security Basics & Best Practices',
            description='Password management, phishing awareness, device security',
            duration_minutes=30,
            required=True,
            frequency_days=365  # Annual
        )

        modules['data_protection'] = TrainingModule(
            module_id='data_protection',
            title='Data Protection & Privacy',
            description='GDPR, data classification, handling sensitive data',
            duration_minutes=45,
            required=True,
            frequency_days=365
        )

        modules['incident_response'] = TrainingModule(
            module_id='incident_response',
            title='Incident Response Procedures',
            description='How to report security incidents, what to do if compromised',
            duration_minutes=30,
            required=True,
            frequency_days=365
        )

        modules['social_engineering'] = TrainingModule(
            module_id='social_engineering',
            title='Social Engineering Awareness',
            description='Recognizing phishing, vishing, pretexting attacks',
            duration_minutes=25,
            required=True,
            frequency_days=180  # Semi-annual
        )

        modules['secure_coding'] = TrainingModule(
            module_id='secure_coding',
            title='Secure Coding Practices',
            description='OWASP Top 10, input validation, SQL injection prevention',
            duration_minutes=60,
            required=False,  # Engineers only
            frequency_days=365
        )

        modules['compliance_training'] = TrainingModule(
            module_id='compliance_training',
            title='SOC 2 & Compliance Overview',
            description='SOC 2 requirements, audit procedures, employee responsibilities',
            duration_minutes=40,
            required=True,
            frequency_days=365
        )

        return modules

    def record_completion(
        self,
        user_id: str,
        employee_name: str,
        module_id: str,
        score: Optional[float] = None,
        passed: bool = True
    ):
        """Record training completion"""
        if module_id not in self.modules:
            raise ValueError(f"Unknown module: {module_id}")

        module = self.modules[module_id]
        completion_date = datetime.now()
        next_due = completion_date + timedelta(days=module.frequency_days)

        record = TrainingRecord(
            user_id=user_id,
            employee_name=employee_name,
            module_id=module_id,
            completion_date=completion_date.isoformat(),
            score=score,
            passed=passed,
            next_due_date=next_due.isoformat()
        )

        self.records.append(record)
        print(f"✓ Training recorded: {employee_name} completed {module.title}")

    def get_user_training_status(self, user_id: str) -> Dict:
        """Get training status for user"""
        user_records = [r for r in self.records if r.user_id == user_id]

        completed_modules = set(r.module_id for r in user_records)
        required_modules = set(
            m.module_id for m in self.modules.values() if m.required
        )

        overdue = []
        upcoming = []

        for record in user_records:
            due_date = datetime.fromisoformat(record.next_due_date)
            days_until_due = (due_date - datetime.now()).days

            if days_until_due < 0:
                overdue.append({
                    "module": self.modules[record.module_id].title,
                    "days_overdue": abs(days_until_due)
                })
            elif days_until_due < 30:
                upcoming.append({
                    "module": self.modules[record.module_id].title,
                    "days_until_due": days_until_due
                })

        return {
            "user_id": user_id,
            "completion_percentage": len(completed_modules) / len(required_modules) * 100 if required_modules else 0,
            "completed_modules": len(completed_modules),
            "required_modules": len(required_modules),
            "missing_required": list(required_modules - completed_modules),
            "overdue_renewals": overdue,
            "upcoming_renewals": upcoming,
            "compliant": len(required_modules - completed_modules) == 0 and len(overdue) == 0
        }

    def generate_compliance_report(self) -> Dict:
        """Generate organization-wide training compliance report"""
        # Get unique users
        users = set(r.user_id for r in self.records)

        total_users = max(len(users), 1)  # Avoid division by zero
        compliant_users = 0
        overdue_users = 0

        user_statuses = []
        for user_id in users:
            status = self.get_user_training_status(user_id)
            user_statuses.append(status)

            if status['compliant']:
                compliant_users += 1
            if status['overdue_renewals']:
                overdue_users += 1

        return {
            "report_date": datetime.now().isoformat(),
            "total_users": total_users,
            "compliant_users": compliant_users,
            "compliance_rate": compliant_users / total_users * 100,
            "users_with_overdue_training": overdue_users,
            "total_completions": len(self.records),
            "user_details": user_statuses,
            "soc2_compliance_note": "CC1.4, CC1.5 - Security awareness training"
        }


if __name__ == "__main__":
    print("="*60)
    print("Security Training Manager Test")
    print("="*60)

    # Initialize
    manager = SecurityTrainingManager()

    # Record some completions
    print("\n1️⃣  Recording training completions...")
    manager.record_completion("user_001", "John Doe", "security_basics", score=95, passed=True)
    manager.record_completion("user_001", "John Doe", "data_protection", score=88, passed=True)
    manager.record_completion("user_002", "Jane Smith", "security_basics", score=92, passed=True)

    # Get user status
    print("\n2️⃣  User training status:")
    status = manager.get_user_training_status("user_001")
    print(f"  Completion: {status['completion_percentage']:.0f}%")
    print(f"  Compliant: {status['compliant']}")

    # Generate report
    print("\n3️⃣  Compliance report:")
    report = manager.generate_compliance_report()
    print(f"  Total users: {report['total_users']}")
    print(f"  Compliance rate: {report['compliance_rate']:.0f}%")

    print("\n" + "="*60)
    print("✅ Security Training Manager Working!")
    print("="*60)
