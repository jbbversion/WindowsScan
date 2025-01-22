from winvulnscan import Scanner, Reporter

scanner = Scanner()
scanner.scan_local()
scanner.scan_remote("google.com")
scanner.scan_network("192.168.1.0/24")
scanner.detect_exploits("http://google.com")
system_config = {
    "firewall_enabled": False,
    "encryption_enabled": False,
    "audit_logs_enabled": False,
    "access_controls_enabled": False,
    "data_encryption_enabled": False,
    "user_consent_obtained": False,
}
scanner.check_compliance(system_config)
reporter = Reporter()
reporter.generate_report(scanner.get_vulnerabilities(), "vulnscan_report.pdf")
