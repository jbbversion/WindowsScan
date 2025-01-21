from PyQt5.QtWidgets import QMainWindow, QTabWidget, QWidget, QVBoxLayout, QPushButton, QTextEdit, QFileDialog
from .scanner import Scanner
from .reporter import Reporter

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WinVulnScan")
        self.setGeometry(100, 100, 800, 600)

        # Create tabs
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # Local Scan Tab
        self.local_tab = QWidget()
        self.local_layout = QVBoxLayout()
        self.local_scan_button = QPushButton("Scan Local System")
        self.local_scan_button.clicked.connect(self.scan_local)
        self.local_output = QTextEdit()
        self.local_layout.addWidget(self.local_scan_button)
        self.local_layout.addWidget(self.local_output)
        self.local_tab.setLayout(self.local_layout)
        self.tabs.addTab(self.local_tab, "Local Scan")

        # Remote Scan Tab
        self.remote_tab = QWidget()
        self.remote_layout = QVBoxLayout()
        self.remote_scan_button = QPushButton("Scan Remote Server")
        self.remote_scan_button.clicked.connect(self.scan_remote)
        self.remote_output = QTextEdit()
        self.remote_layout.addWidget(self.remote_scan_button)
        self.remote_layout.addWidget(self.remote_output)
        self.remote_tab.setLayout(self.remote_layout)
        self.tabs.addTab(self.remote_tab, "Remote Scan")

        # Network Scan Tab
        self.network_tab = QWidget()
        self.network_layout = QVBoxLayout()
from PyQt5.QtWidgets import QMainWindow, QTabWidget, QWidget, QVBoxLayout, QPushButton, QTextEdit, QFileDialog
from .scanner import Scanner
from .reporter import Reporter

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WinVulnScan")
        self.setGeometry(100, 100, 800, 600)

        # Create tabs
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # Local Scan Tab
        self.local_tab = QWidget()
        self.local_layout = QVBoxLayout()
        self.local_scan_button = QPushButton("Scan Local System")
        self.local_scan_button.clicked.connect(self.scan_local)
        self.local_output = QTextEdit()
        self.local_layout.addWidget(self.local_scan_button)
        self.local_layout.addWidget(self.local_output)
        self.local_tab.setLayout(self.local_layout)
        self.tabs.addTab(self.local_tab, "Local Scan")

        # Remote Scan Tab
        self.remote_tab = QWidget()
        self.remote_layout = QVBoxLayout()
        self.remote_scan_button = QPushButton("Scan Remote Server")
        self.remote_scan_button.clicked.connect(self.scan_remote)
        self.remote_output = QTextEdit()
        self.remote_layout.addWidget(self.remote_scan_button)
        self.remote_layout.addWidget(self.remote_output)
        self.remote_tab.setLayout(self.remote_layout)
        self.tabs.addTab(self.remote_tab, "Remote Scan")

        # Network Scan Tab
        self.network_tab = QWidget()
        self.network_layout = QVBoxLayout()
        self.network_scan_button = QPushButton("Scan Network")
        self.network_scan_button.clicked.connect(self.scan_network)
        self.network_output = QTextEdit()
        self.network_layout.addWidget(self.network_scan_button)
        self.network_layout.addWidget(self.network_output)
        self.network_tab.setLayout(self.network_layout)
        self.tabs.addTab(self.network_tab, "Network Scan")

        # Exploit Detection Tab
        self.exploit_tab = QWidget()
        self.exploit_layout = QVBoxLayout()
        self.exploit_detect_button = QPushButton("Detect Exploits")
        self.exploit_detect_button.clicked.connect(self.detect_exploits)
        self.exploit_output = QTextEdit()
        self.exploit_layout.addWidget(self.exploit_detect_button)
        self.exploit_layout.addWidget(self.exploit_output)
        self.exploit_tab.setLayout(self.exploit_layout)
        self.tabs.addTab(self.exploit_tab, "Exploit Detection")

        # Compliance Check Tab
        self.compliance_tab = QWidget()
        self.compliance_layout = QVBoxLayout()
        self.compliance_check_button = QPushButton("Check Compliance")
        self.compliance_check_button.clicked.connect(self.check_compliance)
        self.compliance_output = QTextEdit()
        self.compliance_layout.addWidget(self.compliance_check_button)
        self.compliance_layout.addWidget(self.compliance_output)
        self.compliance_tab.setLayout(self.compliance_layout)
        self.tabs.addTab(self.compliance_tab, "Compliance Check")

        # Report Tab
        self.report_tab = QWidget()
        self.report_layout = QVBoxLayout()
        self.generate_report_button = QPushButton("Generate Report")
        self.generate_report_button.clicked.connect(self.generate_report)
        self.report_output = QTextEdit()
        self.report_layout.addWidget(self.generate_report_button)
        self.report_layout.addWidget(self.report_output)
        self.report_tab.setLayout(self.report_layout)
        self.tabs.addTab(self.report_tab, "Report")

        # Scanner instance
        self.scanner = Scanner()
        self.reporter = Reporter()

    def scan_local(self):
        vulnerabilities = self.scanner.scan_local()
        self.local_output.setText("\n".join(vulnerabilities))

    def scan_remote(self):
        vulnerabilities = self.scanner.scan_remote("example.com")
        self.remote_output.setText("\n".join(vulnerabilities))

    def scan_network(self):
        vulnerabilities = self.scanner.scan_network("192.168.1.0/24")
        self.network_output.setText("\n".join(vulnerabilities))

    def detect_exploits(self):
        vulnerabilities = self.scanner.detect_exploits("http://example.com")
        self.exploit_output.setText("\n".join(vulnerabilities))

    def check_compliance(self):
        system_config = {
            "firewall_enabled": False,
            "encryption_enabled": False,
            "audit_logs_enabled": False,
            "access_controls_enabled": False,
            "data_encryption_enabled": False,
            "user_consent_obtained": False,
        }
        vulnerabilities = self.scanner.check_compliance(system_config)
        self.compliance_output.setText("\n".join(vulnerabilities))

    def generate_report(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Report", "", "PDF Files (*.pdf);;CSV Files (*.csv);;HTML Files (*.html)")
        if file_path:
            vulnerabilities = self.scanner.get_vulnerabilities()
            self.reporter.generate_report(vulnerabilities, file_path)
            self.report_output.setText(f"Report saved to {file_path}")￼Enter        self.network_scan_button = QPushButton("Scan Network")
        self.network_scan_button.clicked.connect(self.scan_network)
        self.network_output = QTextEdit()
        self.network_layout.addWidget(self.network_scan_button)
        self.network_layout.addWidget(self.network_output)
        self.network_tab.setLayout(self.network_layout)
        self.tabs.addTab(self.network_tab, "Network Scan")

        # Exploit Detection Tab
        self.exploit_tab = QWidget()
        self.exploit_layout = QVBoxLayout()
        self.exploit_detect_button = QPushButton("Detect Exploits")
        self.exploit_detect_button.clicked.connect(self.detect_exploits)
        self.exploit_output = QTextEdit()
        self.exploit_layout.addWidget(self.exploit_detect_button)
        self.exploit_layout.addWidget(self.exploit_output)
        self.exploit_tab.setLayout(self.exploit_layout)
        self.tabs.addTab(self.exploit_tab, "Exploit Detection")

        # Compliance Check Tab
        self.compliance_tab = QWidget()
        self.compliance_layout = QVBoxLayout()
        self.compliance_check_button = QPushButton("Check Compliance")
        self.compliance_check_button.clicked.connect(self.check_compliance)
        self.compliance_output = QTextEdit()
        self.compliance_layout.addWidget(self.compliance_check_button)
  self.compliance_layout.addWidget(self.compliance_output)
        self.compliance_tab.setLayout(self.compliance_layout)
        self.tabs.addTab(self.compliance_tab, "Compliance Check")

        # Report Tab
        self.report_tab = QWidget()
        self.report_layout = QVBoxLayout()
        self.generate_report_button = QPushButton("Generate Report")
        self.generate_report_button.clicked.connect(self.generate_report)
        self.report_output = QTextEdit()
        self.report_layout.addWidget(self.generate_report_button)
        self.report_layout.addWidget(self.report_output)
        self.report_tab.setLayout(self.report_layout)
        self.tabs.addTab(self.report_tab, "Report")

        # Scanner instance
        self.scanner = Scanner()
        self.reporter = Reporter()

    def scan_local(self):
        vulnerabilities = self.scanner.scan_local()
        self.local_output.setText("\n".join(vulnerabilities))

    def scan_remote(self):
        vulnerabilities = self.scanner.scan_remote("google.com")
        self.remote_output.setText("\n".join(vulnerabilities))
