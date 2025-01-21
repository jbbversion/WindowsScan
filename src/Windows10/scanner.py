from .local_scanner import LocalScanner
from .remote_scanner import RemoteScanner
from .network_scanner import NetworkScanner
from .exploit_detector import ExploitDetector
from .compliance_checker import ComplianceChecker
from .vulnerability_detector import VulnerabilityDetector

class Scanner:
    def __init__(self):
        self.local_scanner = LocalScanner()
        self.remote_scanner = RemoteScanner()
        self.network_scanner = NetworkScanner()
        self.exploit_detector = ExploitDetector()
        self.compliance_checker = ComplianceChecker()
        self.vulnerability_detector = VulnerabilityDetector()
        self.vulnerabilities = []

    def scan_local(self):
        self.vulnerabilities.extend(self.local_scanner.scan())
        return self.vulnerabilities

    def scan_remote(self, target):
        self.vulnerabilities.extend(self.remote_scanner.scan(target))
        return self.vulnerabilities

    def scan_network(self, network_range):
        self.vulnerabilities.extend(self.network_scanner.scan_network(network_range))
        return self.vulnerabilities

    def detect_exploits(self, target):
        self.vulnerabilities.extend(self.exploit_detector.detect_exploits(target))
        return self.vulnerabilities

    def check_compliance(self, system_config):
        self.compliance_checker.check_pci_dss(system_config)
        self.compliance_checker.check_hipaa(system_config)
        self.compliance_checker.check_gdpr(system_config)
        self.vulnerabilities.extend(self.compliance_checker.get_violations())
        return self.vulnerabilities

    def detect_vulnerabilities(self):
        self.vulnerabilities.extend(self.vulnerability_detector.detect_vulnerabilities())
        return self.vulnerabilities

    def get_vulnerabilities(self):
        return self.vulnerabilities￼Enter
