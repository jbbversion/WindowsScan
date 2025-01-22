import pytest
from winvulnscan.compliance_checker import ComplianceChecker

def test_compliance_checker():
    checker = ComplianceChecker()
    system_config = {
        "firewall_enabled": False,
        "encryption_enabled": False,
        "audit_logs_enabled": False,
        "access_controls_enabled": False,
        "data_encryption_enabled": False,
        "user_consent_obtained": False,
    }
    checker.check_pci_dss(system_config)
    checker.check_hipaa(system_config)
    checker.check_gdpr(system_config)
    violations = checker.get_violations()
    assert isinstance(violations, list)￼Enter
