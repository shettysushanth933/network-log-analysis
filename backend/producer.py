import json
import random
import time
from datetime import datetime, timedelta
from kafka import KafkaProducer
import socket
import threading
from typing import Dict, List
import ipaddress

class NetworkLogGenerator:
    def __init__(self):
        self.protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'SSH', 'FTP', 'DNS', 'ICMP']
        self.log_levels = ['INFO', 'WARNING', 'ERROR', 'CRITICAL']
        self.actions = ['ALLOW', 'DENY', 'DROP', 'REJECT']
        self.attack_types = ['Brute Force', 'DDoS', 'Port Scan', 'SQL Injection', 'XSS', 'Malware']
        
        # Common internal IP ranges
        self.internal_ips = [
            '192.168.1.{}',
            '10.0.0.{}',
            '172.16.0.{}'
        ]
        
        # Common external IPs (simulate real world)
        self.external_ips = [
            '8.8.8.8', '1.1.1.1', '208.67.222.222', '185.228.168.9',
            '134.195.196.26', '23.253.146.63', '104.244.42.129'
        ]
        
        # Common ports
        self.common_ports = {
            'HTTP': 80, 'HTTPS': 443, 'SSH': 22, 'FTP': 21,
            'DNS': 53, 'SMTP': 25, 'POP3': 110, 'IMAP': 143,
            'TELNET': 23, 'SNMP': 161, 'LDAP': 389
        }
        
        # Suspicious ports
        self.suspicious_ports = [1337, 31337, 4444, 5555, 6666, 9999]

    def generate_ip(self, ip_type='random'):
        """Generate IP address"""
        if ip_type == 'internal':
            template = random.choice(self.internal_ips)
            return template.format(random.randint(1, 254))
        elif ip_type == 'external':
            return random.choice(self.external_ips)
        else:
            # Mix of internal and external
            if random.random() > 0.7:  # 30% external
                return random.choice(self.external_ips)
            else:
                template = random.choice(self.internal_ips)
                return template.format(random.randint(1, 254))

    def generate_port(self, suspicious=False):
        """Generate port number"""
        if suspicious:
            return random.choice(self.suspicious_ports)
        else:
            if random.random() > 0.6:  # 40% common ports
                return random.choice(list(self.common_ports.values()))
            else:
                return random.randint(1024, 65535)

    def generate_normal_log(self) -> Dict:
        """Generate normal network activity log"""
        src_ip = self.generate_ip('internal')
        dst_ip = self.generate_ip('external')
        protocol = random.choice(['TCP', 'UDP', 'HTTP', 'HTTPS'])
        dst_port = self.generate_port()
        
        return {
            'timestamp': datetime.now().isoformat(),
            'log_type': 'network_traffic',
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'source_port': random.randint(32768, 65535),
            'destination_port': dst_port,
            'protocol': protocol,
            'bytes_sent': random.randint(64, 10240),
            'bytes_received': random.randint(64, 8192),
            'duration': random.uniform(0.1, 30.0),
            'action': 'ALLOW',
            'log_level': 'INFO',
            'threat_level': 'LOW',
            'user_agent': random.choice([
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
                'curl/7.68.0',
                'python-requests/2.25.1'
            ]) if protocol in ['HTTP', 'HTTPS'] else None,
            'status_code': random.choice([200, 201, 204, 301, 302]) if protocol in ['HTTP', 'HTTPS'] else None
        }

    def generate_suspicious_log(self) -> Dict:
        """Generate suspicious/attack network activity log"""
        attack_type = random.choice(self.attack_types)
        src_ip = self.generate_ip('external')  # Attacks usually from external
        dst_ip = self.generate_ip('internal')
        
        if attack_type == 'Port Scan':
            return {
                'timestamp': datetime.now().isoformat(),
                'log_type': 'security_alert',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'source_port': random.randint(32768, 65535),
                'destination_port': self.generate_port(suspicious=True),
                'protocol': 'TCP',
                'bytes_sent': random.randint(40, 100),
                'bytes_received': 0,
                'duration': random.uniform(0.01, 0.1),
                'action': 'DENY',
                'log_level': 'WARNING',
                'threat_level': 'MEDIUM',
                'attack_type': attack_type,
                'attack_signature': f"Multiple connection attempts from {src_ip}",
                'severity_score': random.randint(5, 7)
            }
        
        elif attack_type == 'Brute Force':
            return {
                'timestamp': datetime.now().isoformat(),
                'log_type': 'security_alert',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'source_port': random.randint(32768, 65535),
                'destination_port': 22,  # SSH
                'protocol': 'SSH',
                'bytes_sent': random.randint(100, 500),
                'bytes_received': random.randint(50, 200),
                'duration': random.uniform(1.0, 5.0),
                'action': 'DENY',
                'log_level': 'ERROR',
                'threat_level': 'HIGH',
                'attack_type': attack_type,
                'failed_attempts': random.randint(5, 50),
                'target_service': 'SSH',
                'severity_score': random.randint(7, 9)
            }
        
        elif attack_type == 'DDoS':
            return {
                'timestamp': datetime.now().isoformat(),
                'log_type': 'security_alert',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'source_port': random.randint(1024, 65535),
                'destination_port': random.choice([80, 443]),
                'protocol': random.choice(['TCP', 'UDP']),
                'bytes_sent': random.randint(1000, 50000),
                'bytes_received': 0,
                'duration': random.uniform(0.1, 1.0),
                'action': 'DROP',
                'log_level': 'CRITICAL',
                'threat_level': 'CRITICAL',
                'attack_type': attack_type,
                'request_rate': random.randint(100, 1000),
                'severity_score': random.randint(8, 10)
            }
        
        else:  # Other attacks
            return {
                'timestamp': datetime.now().isoformat(),
                'log_type': 'security_alert',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'source_port': random.randint(32768, 65535),
                'destination_port': random.choice([80, 443]),
                'protocol': 'HTTP',
                'bytes_sent': random.randint(500, 5000),
                'bytes_received': random.randint(100, 1000),
                'duration': random.uniform(0.5, 10.0),
                'action': 'DENY',
                'log_level': 'ERROR',
                'threat_level': 'HIGH',
                'attack_type': attack_type,
                'payload_size': random.randint(1000, 10000),
                'severity_score': random.randint(6, 9)
            }

    def generate_firewall_log(self) -> Dict:
        """Generate firewall log entry"""
        return {
            'timestamp': datetime.now().isoformat(),
            'log_type': 'firewall',
            'source_ip': self.generate_ip(),
            'destination_ip': self.generate_ip(),
            'source_port': random.randint(1024, 65535),
            'destination_port': self.generate_port(),
            'protocol': random.choice(self.protocols),
            'action': random.choice(self.actions),
            'rule_id': f"FW_RULE_{random.randint(100, 999)}",
            'bytes_transferred': random.randint(64, 10240),
            'log_level': random.choice(['INFO', 'WARNING']),
            'interface': random.choice(['eth0', 'eth1', 'wlan0']),
            'threat_level': random.choice(['LOW', 'MEDIUM'])
        }

class NetworkLogProducer:
    def __init__(self, kafka_servers='localhost:9092', topic='network-logs'):
        self.producer = KafkaProducer(
            bootstrap_servers=kafka_servers,
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            key_serializer=lambda k: k.encode('utf-8') if k else None
        )
        self.topic = topic
        self.log_generator = NetworkLogGenerator()
        self.is_running = False
        self.stats = {
            'total_sent': 0,
            'normal_logs': 0,
            'suspicious_logs': 0,
            'firewall_logs': 0,
            'errors': 0
        }

    def send_log(self, log_data: Dict, log_category: str = 'normal'):
        """Send log to Kafka"""
        try:
            # Use source IP as key for partitioning
            key = log_data.get('source_ip', 'unknown')
            
            future = self.producer.send(
                self.topic,
                key=key,
                value=log_data
            )
            
            # Update stats
            self.stats['total_sent'] += 1
            if log_category == 'suspicious':
                self.stats['suspicious_logs'] += 1
            elif log_category == 'firewall':
                self.stats['firewall_logs'] += 1
            else:
                self.stats['normal_logs'] += 1
            
            print(f"✅ Sent {log_category} log: {log_data['source_ip']} -> {log_data['destination_ip']} "
                  f"({log_data.get('protocol', 'N/A')}) [{log_data.get('threat_level', 'N/A')}]")
            
            return future
            
        except Exception as e:
            self.stats['errors'] += 1
            print(f"❌ Error sending log: {e}")
            return None

    def generate_log_burst(self):
        """Generate a burst of logs (simulate real network traffic)"""
        burst_size = random.randint(5, 20)
        
        for _ in range(burst_size):
            # 70% normal, 20% suspicious, 10% firewall
            rand = random.random()
            
            if rand < 0.70:  # Normal traffic
                log = self.log_generator.generate_normal_log()
                self.send_log(log, 'normal')
            elif rand < 0.90:  # Suspicious activity
                log = self.log_generator.generate_suspicious_log()
                self.send_log(log, 'suspicious')
            else:  # Firewall logs
                log = self.log_generator.generate_firewall_log()
                self.send_log(log, 'firewall')
            
            # Small delay between logs in burst
            time.sleep(random.uniform(0.1, 0.5))

    def simulate_attack_scenario(self):
        """Simulate a coordinated attack scenario"""
        print("🚨 Simulating attack scenario...")
        
        attack_ip = self.log_generator.generate_ip('external')
        target_ip = self.log_generator.generate_ip('internal')
        
        # Generate multiple attack logs from same IP
        for i in range(random.randint(10, 25)):
            if i < 5:  # Start with port scan
                log = {
                    'timestamp': datetime.now().isoformat(),
                    'log_type': 'security_alert',
                    'source_ip': attack_ip,
                    'destination_ip': target_ip,
                    'source_port': random.randint(32768, 65535),
                    'destination_port': random.randint(1, 1024),
                    'protocol': 'TCP',
                    'bytes_sent': 64,
                    'bytes_received': 0,
                    'duration': 0.1,
                    'action': 'DENY',
                    'log_level': 'WARNING',
                    'threat_level': 'MEDIUM',
                    'attack_type': 'Port Scan',
                    'severity_score': 6
                }
            else:  # Follow up with brute force
                log = {
                    'timestamp': datetime.now().isoformat(),
                    'log_type': 'security_alert',
                    'source_ip': attack_ip,
                    'destination_ip': target_ip,
                    'source_port': random.randint(32768, 65535),
                    'destination_port': 22,
                    'protocol': 'SSH',
                    'bytes_sent': random.randint(100, 300),
                    'bytes_received': 50,
                    'duration': random.uniform(1.0, 3.0),
                    'action': 'DENY',
                    'log_level': 'ERROR',
                    'threat_level': 'HIGH',
                    'attack_type': 'Brute Force',
                    'failed_attempts': i - 4,
                    'severity_score': min(9, 6 + (i - 4))
                }
            
            self.send_log(log, 'suspicious')
            time.sleep(random.uniform(0.2, 1.0))

    def print_stats(self):
        """Print current statistics"""
        print(f"""
📊 Network Log Producer Statistics:
  Total Logs Sent: {self.stats['total_sent']}
  ├── Normal Traffic: {self.stats['normal_logs']} ({self.stats['normal_logs']/max(self.stats['total_sent'],1)*100:.1f}%)
  ├── Suspicious Activity: {self.stats['suspicious_logs']} ({self.stats['suspicious_logs']/max(self.stats['total_sent'],1)*100:.1f}%)
  ├── Firewall Logs: {self.stats['firewall_logs']} ({self.stats['firewall_logs']/max(self.stats['total_sent'],1)*100:.1f}%)
  └── Errors: {self.stats['errors']}
        """)

    def run_continuous(self, interval=5):
        """Run continuous log generation"""
        print("🚀 Starting continuous network log generation...")
        print(f"📡 Kafka Topic: {self.topic}")
        print("⏸️  Press Ctrl+C to stop")
        
        self.is_running = True
        
        try:
            while self.is_running:
                # 80% normal bursts, 15% attack scenarios, 5% quiet period
                rand = random.random()
                
                if rand < 0.80:
                    self.generate_log_burst()
                elif rand < 0.95:
                    self.simulate_attack_scenario()
                else:
                    print("😴 Quiet period...")
                    time.sleep(interval * 2)
                    continue
                
                # Print stats every 50 logs
                if self.stats['total_sent'] % 50 == 0 and self.stats['total_sent'] > 0:
                    self.print_stats()
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n🛑 Stopping log generation...")
            self.is_running = False
            self.print_stats()
            self.producer.close()

def main():
    # Configuration
    KAFKA_SERVERS = 'localhost:9092'
    TOPIC = 'network-logs'
    INTERVAL = 3  # seconds between log bursts
    
    print("🔥 Network Log Analysis - Log Producer")
    print("=" * 50)
    
    try:
        producer = NetworkLogProducer(
            kafka_servers=KAFKA_SERVERS,
            topic=TOPIC
        )
        
        producer.run_continuous(interval=INTERVAL)
        
    except Exception as e:
        print(f"❌ Failed to start producer: {e}")

if __name__ == "__main__":
    main()