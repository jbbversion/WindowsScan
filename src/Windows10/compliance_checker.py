class ComplianceChecker:
    def __init__(self):
        self.violations = []

    def check_pci_dss(self, system_config):
        if not system_config.get("firewall_enabled"):
            self.violations.append("PCI-DSS Violation: Firewall not enabled.")
        if not system_config.get("encryption_enabled"):
            self.violations.append("PCI-DSS Violation: Encryption not enabled.")

    def check_hipaa(self, system_config):
        if not system_config.get("audit_logs_enabled"):
            self.violations.append("HIPAA Violation: Audit logs not enabled.")
        if not system_config.get("access_controls_enabled"):
            self.violations.append("HIPAA Violation: Access controls not enabled.")

    def check_gdpr(self, system_config):
        if not system_config.get("data_encryption_enabled"):
            self.violations.append("GDPR Violation: Data encryption not enabled.")
        if not system_config.get("user_consent_obtained"):
            self.violations.append("GDPR Violation: User consent not obtained.")

    def get_violations(self):
        return self.violations
