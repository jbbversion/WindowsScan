import pytest
from WindowsScan.network_scanner import NetworkScanner

def test_network_scanner():
    scanner = NetworkScanner()
    open_ports = scanner.scan_network("192.168.1.0/24")
    assert isinstance(open_ports, dict)
