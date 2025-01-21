import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor

class NetworkScanner:
    def __init__(self):
        self.open_ports = {}

    def scan_network(self, network_range, ports=None):
        if ports is None:
            ports = [21, 22, 80, 443, 8080]  # Common ports
        network = ipaddress.ip_network(network_range)
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(self._scan_ip, str(ip), ports) for ip in network.hosts()]
            for future in futures:
                ip, open_ports = future.result()
                if open_ports:
                    self.open_ports[ip] = open_ports
        return self.open_ports

    def _scan_ip(self, ip, ports):
        open_ports = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        return ip, open_ports
