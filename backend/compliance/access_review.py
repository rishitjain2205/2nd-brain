"""
Access Review Automation
Periodic review of user access rights

SOC 2 Requirements:
- CC6.2: User access reviews
- CC6.3: Removal of access upon termination
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict


@dataclass
class AccessReviewRecord:
    """Access review record"""
    user_id: str
    email: str
    roles: List[str]
    permissions: List[str]
    last_login: Optional[str]
    account_age_days: int
    review_date: str
    reviewer: str
    status: str  # approved, revoked, needs_review
    notes: str


class AccessReviewManager:
    """
    Automated access review system

    Features:
    - Quarterly access reviews
    - Inactive account detection
    - Excessive permissions flagging
    - Automated review reports
    """

    def __init__(self, review_dir: str = "data/access_reviews"):
        """Initialize access review manager"""
        self.review_dir = Path(review_dir)
        self.review_dir.mkdir(parents=True, exist_ok=True)

        print("✓ Access Review Manager initialized")

    def generate_access_report(self) -> List[AccessReviewRecord]:
        """
        Generate access review report for all users

        Returns:
            List of access review records
        """
        # TODO: Integrate with Auth0 to get real user list
        # For now, return mock data

        records = []

        # Mock users for demonstration
        mock_users = [
            {
                "user_id": "user_001",
                "email": "admin@example.com",
                "roles": ["admin"],
                "permissions": ["read:*", "write:*", "delete:*"],
                "last_login": (datetime.now() - timedelta(days=2)).isoformat(),
                "created_at": (datetime.now() - timedelta(days=365)).isoformat()
            },
            {
                "user_id": "user_002",
                "email": "inactive@example.com",
                "roles": ["employee"],
                "permissions": ["read:data"],
                "last_login": (datetime.now() - timedelta(days=120)).isoformat(),
                "created_at": (datetime.now() - timedelta(days=500)).isoformat()
            }
        ]

        for user in mock_users:
            last_login = datetime.fromisoformat(user['last_login'])
            created_at = datetime.fromisoformat(user['created_at'])
            account_age = (datetime.now() - created_at).days
            days_inactive = (datetime.now() - last_login).days

            # Auto-flag for review
            if days_inactive > 90:
                status = "needs_review"
                notes = f"Inactive for {days_inactive} days"
            elif "admin" in user['roles'] or "delete:*" in user['permissions']:
                status = "needs_review"
                notes = "Elevated privileges - quarterly review"
            else:
                status = "approved"
                notes = "Regular access"

            record = AccessReviewRecord(
                user_id=user['user_id'],
                email=user['email'],
                roles=user['roles'],
                permissions=user['permissions'],
                last_login=user['last_login'],
                account_age_days=account_age,
                review_date=datetime.now().isoformat(),
                reviewer="automated_system",
                status=status,
                notes=notes
            )

            records.append(record)

        return records

    def flag_inactive_accounts(self, days: int = 90) -> List[Dict]:
        """
        Flag accounts inactive for X days

        Args:
            days: Number of days to consider inactive

        Returns:
            List of inactive accounts
        """
        records = self.generate_access_report()

        inactive = []
        for record in records:
            if record.last_login:
                last_login = datetime.fromisoformat(record.last_login)
                days_inactive = (datetime.now() - last_login).days

                if days_inactive >= days:
                    inactive.append({
                        "user_id": record.user_id,
                        "email": record.email,
                        "days_inactive": days_inactive,
                        "last_login": record.last_login,
                        "action": "disable_account"
                    })

        return inactive

    def flag_excessive_permissions(self) -> List[Dict]:
        """
        Flag users with excessive permissions

        Returns:
            List of users with excessive access
        """
        records = self.generate_access_report()

        excessive = []
        for record in records:
            # Flag admin roles
            if "admin" in record.roles:
                excessive.append({
                    "user_id": record.user_id,
                    "email": record.email,
                    "reason": "Admin role assigned",
                    "roles": record.roles,
                    "action": "review_necessity"
                })

            # Flag delete permissions
            if any("delete" in p for p in record.permissions):
                excessive.append({
                    "user_id": record.user_id,
                    "email": record.email,
                    "reason": "Delete permissions granted",
                    "permissions": record.permissions,
                    "action": "review_necessity"
                })

        return excessive

    def export_review_report(self, output_file: Optional[str] = None) -> Path:
        """
        Export quarterly access review report

        Args:
            output_file: Optional output file path

        Returns:
            Path to report file
        """
        records = self.generate_access_report()

        # Generate report
        report = {
            "report_type": "quarterly_access_review",
            "generated_date": datetime.now().isoformat(),
            "review_period": "Q4 2024",
            "total_users": len(records),
            "needs_review": len([r for r in records if r.status == "needs_review"]),
            "approved": len([r for r in records if r.status == "approved"]),
            "revoked": len([r for r in records if r.status == "revoked"]),
            "records": [asdict(r) for r in records],
            "flagged_inactive": self.flag_inactive_accounts(),
            "flagged_excessive": self.flag_excessive_permissions(),
            "compliance_notes": {
                "soc2_requirement": "CC6.2 - User access reviews",
                "review_frequency": "Quarterly",
                "next_review_date": (datetime.now() + timedelta(days=90)).strftime("%Y-%m-%d")
            }
        }

        # Save report
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.review_dir / f"access_review_{timestamp}.json"
        else:
            output_file = Path(output_file)

        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"✓ Access review report generated: {output_file}")
        print(f"  - Total users: {report['total_users']}")
        print(f"  - Needs review: {report['needs_review']}")
        print(f"  - Inactive accounts: {len(report['flagged_inactive'])}")
        print(f"  - Excessive permissions: {len(report['flagged_excessive'])}")

        return output_file


if __name__ == "__main__":
    print("="*60)
    print("Access Review Manager Test")
    print("="*60)

    # Initialize
    manager = AccessReviewManager()

    # Generate report
    print("\n1️⃣  Generating access review report...")
    report_path = manager.export_review_report()

    # Read and display
    with open(report_path, 'r') as f:
        report = json.load(f)

    print(f"\n2️⃣  Report Summary:")
    print(f"  Total users: {report['total_users']}")
    print(f"  Needs review: {report['needs_review']}")

    # Cleanup
    import shutil
    shutil.rmtree("data/access_reviews", ignore_errors=True)

    print("\n" + "="*60)
    print("✅ Access Review Manager Working!")
    print("="*60)
