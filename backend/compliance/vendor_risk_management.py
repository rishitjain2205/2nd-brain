"""
Vendor Risk Management System
Tracks and assesses third-party vendor security risks

SOC 2 Requirements:
- CC9.1: Vendor management
- CC9.2: Vendor risk assessment
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum


class VendorRiskLevel(Enum):
    """Vendor risk classification"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VendorStatus(Enum):
    """Vendor approval status"""
    APPROVED = "approved"
    UNDER_REVIEW = "under_review"
    REJECTED = "rejected"
    NEEDS_RENEWAL = "needs_renewal"


@dataclass
class Vendor:
    """Vendor information"""
    vendor_id: str
    name: str
    service_description: str
    data_access: List[str]  # What data does vendor access
    risk_level: str
    status: str
    soc2_certified: bool
    gdpr_compliant: bool
    hipaa_compliant: bool
    last_assessment_date: str
    next_review_date: str
    contact_email: str
    contract_start: str
    contract_end: str
    dpa_signed: bool  # Data Processing Agreement
    notes: str


class VendorRiskManager:
    """
    Vendor risk management and assessment

    Features:
    - Vendor inventory
    - Risk assessments
    - Compliance tracking
    - Automated review scheduling
    - Vendor questionnaires
    """

    def __init__(self, data_dir: str = "data/vendor_management"):
        """Initialize vendor risk manager"""
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.vendors_file = self.data_dir / "vendors.json"
        self.vendors = self._load_vendors()

        print("✓ Vendor Risk Manager initialized")
        print(f"  - Total vendors: {len(self.vendors)}")

    def _load_vendors(self) -> Dict[str, Vendor]:
        """Load vendors from file"""
        if not self.vendors_file.exists():
            # Initialize with current vendors
            return self._initialize_vendors()

        with open(self.vendors_file, 'r') as f:
            data = json.load(f)

        vendors = {}
        for vendor_id, vendor_data in data.items():
            vendors[vendor_id] = Vendor(**vendor_data)

        return vendors

    def _save_vendors(self):
        """Save vendors to file"""
        data = {
            vendor_id: asdict(vendor)
            for vendor_id, vendor in self.vendors.items()
        }

        with open(self.vendors_file, 'w') as f:
            json.dump(data, f, indent=2)

    def _initialize_vendors(self) -> Dict[str, Vendor]:
        """Initialize with current third-party vendors"""
        vendors = {}

        # Azure OpenAI
        vendors['azure_openai'] = Vendor(
            vendor_id='azure_openai',
            name='Microsoft Azure OpenAI',
            service_description='AI/ML API for document classification and analysis',
            data_access=['document_content', 'user_queries'],
            risk_level=VendorRiskLevel.HIGH.value,
            status=VendorStatus.APPROVED.value,
            soc2_certified=True,
            gdpr_compliant=True,
            hipaa_compliant=True,
            last_assessment_date=datetime.now().isoformat(),
            next_review_date=(datetime.now() + timedelta(days=90)).isoformat(),
            contact_email='azure-support@microsoft.com',
            contract_start='2024-01-01',
            contract_end='2025-12-31',
            dpa_signed=True,
            notes='Zero data retention policy. Enterprise tier. BAA available for HIPAA.'
        )

        # Auth0
        vendors['auth0'] = Vendor(
            vendor_id='auth0',
            name='Auth0 by Okta',
            service_description='Authentication and authorization service',
            data_access=['user_credentials', 'email', 'user_metadata'],
            risk_level=VendorRiskLevel.HIGH.value,
            status=VendorStatus.APPROVED.value,
            soc2_certified=True,
            gdpr_compliant=True,
            hipaa_compliant=False,
            last_assessment_date=datetime.now().isoformat(),
            next_review_date=(datetime.now() + timedelta(days=90)).isoformat(),
            contact_email='support@auth0.com',
            contract_start='2024-01-01',
            contract_end='2025-12-31',
            dpa_signed=True,
            notes='SOC 2 Type 2 certified. GDPR DPA in place.'
        )

        # AWS
        vendors['aws'] = Vendor(
            vendor_id='aws',
            name='Amazon Web Services',
            service_description='Cloud infrastructure and storage',
            data_access=['all_application_data', 'backups', 'logs'],
            risk_level=VendorRiskLevel.CRITICAL.value,
            status=VendorStatus.APPROVED.value,
            soc2_certified=True,
            gdpr_compliant=True,
            hipaa_compliant=True,
            last_assessment_date=datetime.now().isoformat(),
            next_review_date=(datetime.now() + timedelta(days=180)).isoformat(),
            contact_email='aws-compliance@amazon.com',
            contract_start='2024-01-01',
            contract_end='2025-12-31',
            dpa_signed=True,
            notes='SOC 2, ISO 27001, HIPAA BAA. Shared responsibility model.'
        )

        # ChromaDB (self-hosted)
        vendors['chromadb'] = Vendor(
            vendor_id='chromadb',
            name='ChromaDB (Self-Hosted)',
            service_description='Vector database for embeddings',
            data_access=['document_embeddings', 'metadata'],
            risk_level=VendorRiskLevel.LOW.value,
            status=VendorStatus.APPROVED.value,
            soc2_certified=False,
            gdpr_compliant=True,
            hipaa_compliant=False,
            last_assessment_date=datetime.now().isoformat(),
            next_review_date=(datetime.now() + timedelta(days=180)).isoformat(),
            contact_email='opensource@chroma.com',
            contract_start='2024-01-01',
            contract_end='N/A',
            dpa_signed=False,
            notes='Self-hosted open source. No data leaves our infrastructure.'
        )

        return vendors

    def add_vendor(self, vendor: Vendor):
        """Add or update vendor"""
        self.vendors[vendor.vendor_id] = vendor
        self._save_vendors()
        print(f"✓ Vendor added/updated: {vendor.name}")

    def assess_vendor_risk(self, vendor_id: str) -> Dict[str, Any]:
        """
        Perform risk assessment for vendor

        Returns:
            Risk assessment report
        """
        if vendor_id not in self.vendors:
            raise ValueError(f"Vendor not found: {vendor_id}")

        vendor = self.vendors[vendor_id]

        # Calculate risk score
        risk_score = 0

        # Data access risk
        if 'all_application_data' in vendor.data_access:
            risk_score += 40
        elif 'user_credentials' in vendor.data_access or 'document_content' in vendor.data_access:
            risk_score += 25
        else:
            risk_score += 10

        # Compliance status
        if vendor.soc2_certified:
            risk_score -= 15
        if vendor.gdpr_compliant:
            risk_score -= 10
        if vendor.dpa_signed:
            risk_score -= 10

        # Contract status
        if vendor.contract_end:
            end_date = datetime.fromisoformat(vendor.contract_end)
            days_to_expiry = (end_date - datetime.now()).days
            if days_to_expiry < 90:
                risk_score += 15

        # Assessment overdue
        last_assessment = datetime.fromisoformat(vendor.last_assessment_date)
        days_since_assessment = (datetime.now() - last_assessment).days
        if days_since_assessment > 180:
            risk_score += 20

        # Determine risk level
        if risk_score >= 60:
            calculated_risk = VendorRiskLevel.CRITICAL.value
        elif risk_score >= 40:
            calculated_risk = VendorRiskLevel.HIGH.value
        elif risk_score >= 20:
            calculated_risk = VendorRiskLevel.MEDIUM.value
        else:
            calculated_risk = VendorRiskLevel.LOW.value

        return {
            "vendor_id": vendor_id,
            "vendor_name": vendor.name,
            "risk_score": risk_score,
            "calculated_risk_level": calculated_risk,
            "current_risk_level": vendor.risk_level,
            "assessment_date": datetime.now().isoformat(),
            "findings": {
                "data_access": vendor.data_access,
                "soc2_certified": vendor.soc2_certified,
                "gdpr_compliant": vendor.gdpr_compliant,
                "dpa_signed": vendor.dpa_signed,
                "contract_expiry": vendor.contract_end,
                "days_since_last_assessment": days_since_assessment
            },
            "recommendations": self._get_recommendations(vendor, risk_score)
        }

    def _get_recommendations(self, vendor: Vendor, risk_score: int) -> List[str]:
        """Get risk mitigation recommendations"""
        recommendations = []

        if not vendor.soc2_certified:
            recommendations.append("Request SOC 2 Type 2 report")

        if not vendor.dpa_signed:
            recommendations.append("Execute Data Processing Agreement")

        if not vendor.gdpr_compliant:
            recommendations.append("Verify GDPR compliance mechanisms")

        if vendor.contract_end:
            end_date = datetime.fromisoformat(vendor.contract_end)
            days_to_expiry = (end_date - datetime.now()).days
            if days_to_expiry < 90:
                recommendations.append(f"Contract expires in {days_to_expiry} days - negotiate renewal")

        last_assessment = datetime.fromisoformat(vendor.last_assessment_date)
        days_since = (datetime.now() - last_assessment).days
        if days_since > 180:
            recommendations.append("Conduct updated vendor assessment")

        if risk_score >= 60:
            recommendations.append("Consider alternative vendors or additional controls")

        return recommendations

    def get_vendors_needing_review(self) -> List[Vendor]:
        """Get vendors requiring assessment review"""
        needing_review = []

        for vendor in self.vendors.values():
            next_review = datetime.fromisoformat(vendor.next_review_date)
            if datetime.now() >= next_review:
                needing_review.append(vendor)

        return needing_review

    def generate_vendor_report(self) -> Dict[str, Any]:
        """Generate comprehensive vendor risk report"""
        total_vendors = len(self.vendors)

        # Count by risk level
        risk_counts = {level.value: 0 for level in VendorRiskLevel}
        for vendor in self.vendors.values():
            risk_counts[vendor.risk_level] += 1

        # Count by status
        status_counts = {status.value: 0 for status in VendorStatus}
        for vendor in self.vendors.values():
            status_counts[vendor.status] += 1

        # Compliance stats
        compliance_stats = {
            "soc2_certified": sum(1 for v in self.vendors.values() if v.soc2_certified),
            "gdpr_compliant": sum(1 for v in self.vendors.values() if v.gdpr_compliant),
            "hipaa_compliant": sum(1 for v in self.vendors.values() if v.hipaa_compliant),
            "dpa_signed": sum(1 for v in self.vendors.values() if v.dpa_signed)
        }

        # Vendors needing attention
        needs_review = self.get_vendors_needing_review()

        return {
            "report_date": datetime.now().isoformat(),
            "total_vendors": total_vendors,
            "risk_distribution": risk_counts,
            "status_distribution": status_counts,
            "compliance_stats": compliance_stats,
            "vendors_needing_review": [v.name for v in needs_review],
            "high_risk_vendors": [
                v.name for v in self.vendors.values()
                if v.risk_level in [VendorRiskLevel.HIGH.value, VendorRiskLevel.CRITICAL.value]
            ],
            "vendor_details": [asdict(v) for v in self.vendors.values()],
            "soc2_compliance_note": "CC9.1, CC9.2 - Vendor risk management"
        }

    def export_report(self, output_file: Optional[str] = None) -> Path:
        """Export vendor risk report"""
        report = self.generate_vendor_report()

        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.data_dir / f"vendor_risk_report_{timestamp}.json"
        else:
            output_file = Path(output_file)

        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"✓ Vendor risk report exported: {output_file}")
        return output_file


if __name__ == "__main__":
    print("="*60)
    print("Vendor Risk Management Test")
    print("="*60)

    # Initialize
    manager = VendorRiskManager()

    # Assess all vendors
    print("\n1️⃣  Vendor Risk Assessments:")
    for vendor_id in manager.vendors:
        assessment = manager.assess_vendor_risk(vendor_id)
        print(f"\n  {assessment['vendor_name']}:")
        print(f"    Risk Score: {assessment['risk_score']}")
        print(f"    Risk Level: {assessment['calculated_risk_level'].upper()}")
        if assessment['recommendations']:
            print(f"    Recommendations:")
            for rec in assessment['recommendations']:
                print(f"      - {rec}")

    # Generate report
    print("\n2️⃣  Generating vendor report...")
    report_path = manager.export_report()

    # Cleanup
    import shutil
    shutil.rmtree("data/vendor_management", ignore_errors=True)

    print("\n" + "="*60)
    print("✅ Vendor Risk Management Working!")
    print("="*60)
