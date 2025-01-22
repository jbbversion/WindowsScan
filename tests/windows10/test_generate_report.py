import pytest
from winvulnscan.reporter import Reporter

def test_generate_report(tmp_path):
    vulnerabilities = ["Vulnerability 1", "Vulnerability 2"]
    file_path = tmp_path / "report.pdf"
    reporter = Reporter()
    reporter.generate_report(vulnerabilities, file_path)
    assert file_path.exists()
