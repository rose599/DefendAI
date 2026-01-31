import random
import numpy as np
from datetime import datetime, timezone, timedelta
from typing import List, Dict
import ipaddress

class LogGenerator:
    """Generate synthetic network traffic logs"""
    
    ATTACK_TYPES = [
        'DoS',
        'Port Scan',
        'Brute Force',
        'Malware Beacon'
    ]
    
    PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS']
    
    def __init__(self):
        self.normal_ips = self._generate_ip_pool(100)
        self.attacker_ips = self._generate_ip_pool(20)
        
    def _generate_ip_pool(self, count: int) -> List[str]:
        """Generate a pool of random IPs"""
        ips = []
        for _ in range(count):
            ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            ips.append(ip)
        return ips
    
    def generate_normal_traffic(self, count: int = 1) -> List[Dict]:
        """Generate normal network traffic logs"""
        logs = []
        for _ in range(count):
            log = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'source_ip': random.choice(self.normal_ips),
                'destination_ip': random.choice(self.normal_ips),
                'protocol': random.choice(['TCP', 'UDP', 'HTTP', 'HTTPS']),
                'packet_size': random.randint(64, 1500),
                'port': random.choice([80, 443, 22, 3306, 5432, 8080]),
                'login_attempts': 0,
                'flow_duration': random.uniform(0.1, 10.0),
                'packets_per_second': random.uniform(1, 50),
                'label': 'normal',
                'attack_type': None
            }
            logs.append(log)
        return logs
    
    def generate_dos_attack(self, count: int = 1) -> List[Dict]:
        """Generate DoS attack logs"""
        logs = []
        attacker_ip = random.choice(self.attacker_ips)
        target_ip = random.choice(self.normal_ips)
        
        for _ in range(count):
            log = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'source_ip': attacker_ip,
                'destination_ip': target_ip,
                'protocol': 'TCP',
                'packet_size': random.randint(1, 64),
                'port': random.choice([80, 443]),
                'login_attempts': 0,
                'flow_duration': random.uniform(0.001, 0.1),
                'packets_per_second': random.uniform(1000, 10000),
                'label': 'malicious',
                'attack_type': 'DoS'
            }
            logs.append(log)
        return logs
    
    def generate_port_scan(self, count: int = 1) -> List[Dict]:
        """Generate port scanning logs"""
        logs = []
        attacker_ip = random.choice(self.attacker_ips)
        target_ip = random.choice(self.normal_ips)
        
        for i in range(count):
            log = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'source_ip': attacker_ip,
                'destination_ip': target_ip,
                'protocol': 'TCP',
                'packet_size': 64,
                'port': 1000 + i,
                'login_attempts': 0,
                'flow_duration': 0.01,
                'packets_per_second': random.uniform(100, 500),
                'label': 'malicious',
                'attack_type': 'Port Scan'
            }
            logs.append(log)
        return logs
    
    def generate_brute_force(self, count: int = 1) -> List[Dict]:
        """Generate brute force attack logs"""
        logs = []
        attacker_ip = random.choice(self.attacker_ips)
        target_ip = random.choice(self.normal_ips)
        
        for _ in range(count):
            log = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'source_ip': attacker_ip,
                'destination_ip': target_ip,
                'protocol': 'TCP',
                'packet_size': random.randint(200, 500),
                'port': 22,
                'login_attempts': random.randint(10, 100),
                'flow_duration': random.uniform(0.5, 2.0),
                'packets_per_second': random.uniform(10, 50),
                'label': 'malicious',
                'attack_type': 'Brute Force'
            }
            logs.append(log)
        return logs
    
    def generate_malware_beacon(self, count: int = 1) -> List[Dict]:
        """Generate malware beaconing traffic"""
        logs = []
        infected_ip = random.choice(self.normal_ips)
        c2_server = random.choice(self.attacker_ips)
        
        for _ in range(count):
            log = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'source_ip': infected_ip,
                'destination_ip': c2_server,
                'protocol': 'HTTPS',
                'packet_size': random.randint(100, 300),
                'port': 443,
                'login_attempts': 0,
                'flow_duration': random.uniform(0.1, 1.0),
                'packets_per_second': random.uniform(1, 10),
                'label': 'malicious',
                'attack_type': 'Malware Beacon'
            }
            logs.append(log)
        return logs
    
    def generate_mixed_traffic(self, total_logs: int = 100, attack_ratio: float = 0.3) -> List[Dict]:
        """Generate a mix of normal and attack traffic"""
        logs = []
        num_attacks = int(total_logs * attack_ratio)
        num_normal = total_logs - num_attacks
        
        logs.extend(self.generate_normal_traffic(num_normal))
        
        attacks_per_type = num_attacks // 4
        logs.extend(self.generate_dos_attack(attacks_per_type))
        logs.extend(self.generate_port_scan(attacks_per_type))
        logs.extend(self.generate_brute_force(attacks_per_type))
        logs.extend(self.generate_malware_beacon(num_attacks - 3 * attacks_per_type))
        
        random.shuffle(logs)
        return logs
