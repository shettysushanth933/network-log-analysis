import json
import threading
import time
import ipaddress
from datetime import datetime
from typing import Dict, Any, Optional
from kafka import KafkaConsumer
from kafka.errors import NoBrokersAvailable, KafkaError
from neo4j_client import driver
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NetworkLogConsumer:
    def __init__(self, kafka_servers='localhost:9092', topic='network-logs', group_id='network-log-group'):
        self.kafka_servers = kafka_servers
        self.topic = topic
        self.group_id = group_id
        self.consumer = None
        self.driver = driver
        self.is_running = False
        self.max_retries = 5
        self.retry_delay = 5  # seconds
        
        # Statistics
        self.stats = {
            'total_processed': 0,
            'network_traffic': 0,
            'security_alerts': 0,
            'firewall_logs': 0,
            'errors': 0,
            'db_writes': 0,
            'processing_errors': 0,
            'connection_retries': 0
        }
        
        # Validate Neo4j connection first
        self._validate_neo4j_connection()
        
        # Initialize consumer with retries
        self._init_consumer_with_retry()
        
        # Create Neo4j constraints and indexes
        self._create_database_schema()

    def _validate_neo4j_connection(self):
        """Validate Neo4j connection"""
        if not self.driver:
            logger.error("❌ Neo4j driver is None - database operations will fail")
            logger.error("💡 Please check your neo4j_client.py configuration")
            return False
        
        try:
            with self.driver.session() as session:
                result = session.run("RETURN 1 as test")
                record = result.single()
                if record and record["test"] == 1:
                    logger.info("✅ Neo4j connection validated successfully")
                    return True
                else:
                    logger.error("❌ Neo4j connection test failed")
                    return False
        except Exception as e:
            logger.error(f"❌ Neo4j connection validation failed: {e}")
            return False

    def _check_kafka_connection(self) -> bool:
        """Check if Kafka is available"""
        try:
            from kafka import KafkaProducer
            producer = KafkaProducer(
                bootstrap_servers=self.kafka_servers,
                request_timeout_ms=5000,
                api_version=(0, 10, 1)
            )
            producer.close()
            return True
        except Exception:
            return False

    def _init_consumer_with_retry(self):
        """Initialize Kafka consumer with retry logic"""
        for attempt in range(self.max_retries):
            try:
                logger.info(f"🔄 Attempting to connect to Kafka (attempt {attempt + 1}/{self.max_retries})...")
                
                # Check if Kafka is available first
                if not self._check_kafka_connection():
                    raise NoBrokersAvailable("Kafka broker not available")
                
                self.consumer = KafkaConsumer(
                    self.topic,
                    bootstrap_servers=self.kafka_servers,
                    group_id=self.group_id,
                    value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                    key_deserializer=lambda k: k.decode('utf-8') if k else None,
                    auto_offset_reset='earliest',  # Changed from 'latest' to 'earliest'
                    enable_auto_commit=True,
                    consumer_timeout_ms=5000,  # Increased from 1000ms
                    request_timeout_ms=30000,
                    api_version=(0, 10, 1),
                    session_timeout_ms=10000,
                    heartbeat_interval_ms=3000
                )
                
                # Test the connection
                self.consumer.topics()
                
                logger.info(f"✅ Kafka consumer initialized for topic: {self.topic}")
                logger.info(f"🔌 Connected to Kafka server: {self.kafka_servers}")
                return
                
            except NoBrokersAvailable as e:
                self.stats['connection_retries'] += 1
                if attempt < self.max_retries - 1:
                    logger.warning(f"⚠️ Kafka not available, retrying in {self.retry_delay} seconds... ({e})")
                    time.sleep(self.retry_delay)
                else:
                    logger.error(f"❌ Failed to connect to Kafka after {self.max_retries} attempts")
                    self._suggest_kafka_setup()
                    raise
            except Exception as e:
                self.stats['connection_retries'] += 1
                if attempt < self.max_retries - 1:
                    logger.warning(f"⚠️ Connection error, retrying in {self.retry_delay} seconds... ({e})")
                    time.sleep(self.retry_delay)
                else:
                    logger.error(f"❌ Failed to initialize Kafka consumer: {e}")
                    raise

    def _suggest_kafka_setup(self):
        """Provide setup suggestions when Kafka is not available"""
        print(f"""
🚨 Kafka Connection Failed!

Please ensure Kafka is running on port 9092:

🍎 For macOS:
1️⃣ Start Zookeeper:
   brew services start zookeeper
   OR manually: zookeeper-server-start /usr/local/etc/kafka/zookeeper.properties

2️⃣ Start Kafka:
   brew services start kafka
   OR manually: kafka-server-start /usr/local/etc/kafka/server.properties

3️⃣ Create topic (if needed):
   kafka-topics --create --topic {self.topic} --bootstrap-server {self.kafka_servers} --partitions 1 --replication-factor 1

4️⃣ Check if Kafka is running:
   lsof -i :9092
   OR: netstat -an | grep 9092

🐧 For Linux/Ubuntu:
1️⃣ cd ~/kafka_2.13-2.8.1 (or your Kafka installation directory)
2️⃣ bin/zookeeper-server-start.sh config/zookeeper.properties &
3️⃣ bin/kafka-server-start.sh config/server.properties &

🪟 For Windows:
1️⃣ cd C:\\kafka_2.13-2.8.1
2️⃣ bin\\windows\\zookeeper-server-start.bat config\\zookeeper.properties
3️⃣ bin\\windows\\kafka-server-start.bat config\\server.properties

Current Kafka server: {self.kafka_servers}
Topic: {self.topic}
        """)

    def _create_topic_if_missing(self):
        """Create Kafka topic if it doesn't exist"""
        try:
            from kafka.admin import KafkaAdminClient, NewTopic
            
            admin_client = KafkaAdminClient(
                bootstrap_servers=self.kafka_servers,
                client_id='log_consumer_admin'
            )
            
            topic = NewTopic(
                name=self.topic,
                num_partitions=1,
                replication_factor=1
            )
            
            admin_client.create_topics([topic])
            logger.info(f"✅ Created topic: {self.topic}")
            
        except Exception as e:
            logger.error(f"❌ Could not create topic: {e}")

    def _create_database_schema(self):
        """Create Neo4j database schema"""
        if not self.driver:
            logger.error("❌ Neo4j driver not available - skipping schema creation")
            return
            
        try:
            with self.driver.session() as session:
                # Create constraints
                constraints = [
                    "CREATE CONSTRAINT ip_address_unique IF NOT EXISTS FOR (ip:IPAddress) REQUIRE ip.address IS UNIQUE",
                    "CREATE CONSTRAINT log_id_unique IF NOT EXISTS FOR (log:NetworkLog) REQUIRE log.log_id IS UNIQUE",
                    "CREATE CONSTRAINT alert_id_unique IF NOT EXISTS FOR (alert:SecurityAlert) REQUIRE alert.alert_id IS UNIQUE"
                ]
                
                for constraint in constraints:
                    try:
                        session.run(constraint)
                    except Exception as e:
                        # Constraint might already exist
                        pass
                
                # Create indexes for better performance
                indexes = [
                    "CREATE INDEX log_timestamp_idx IF NOT EXISTS FOR (log:NetworkLog) ON (log.timestamp)",
                    "CREATE INDEX alert_timestamp_idx IF NOT EXISTS FOR (alert:SecurityAlert) ON (alert.timestamp)",
                    "CREATE INDEX ip_address_idx IF NOT EXISTS FOR (ip:IPAddress) ON (ip.address)",
                    "CREATE INDEX threat_level_idx IF NOT EXISTS FOR (alert:SecurityAlert) ON (alert.threat_level)",
                    "CREATE INDEX attack_type_idx IF NOT EXISTS FOR (alert:SecurityAlert) ON (alert.attack_type)"
                ]
                
                for index in indexes:
                    try:
                        session.run(index)
                    except Exception as e:
                        # Index might already exist
                        pass
                
                logger.info("✅ Database schema created/verified")
                
        except Exception as e:
            logger.error(f"❌ Failed to create database schema: {e}")

    def _generate_log_id(self, log_data: Dict) -> str:
        """Generate unique log ID"""
        timestamp = log_data.get('timestamp', datetime.now().isoformat())
        source_ip = log_data.get('source_ip', 'unknown')
        dest_ip = log_data.get('destination_ip', 'unknown')
        return f"{timestamp}_{source_ip}_{dest_ip}_{hash(json.dumps(log_data, sort_keys=True)) % 1000000}"

    def _process_network_traffic_log(self, log_data: Dict) -> bool:
        """Process normal network traffic log"""
        if not self.driver:
            logger.error("❌ Neo4j driver not available - cannot process log")
            return False
            
        try:
            log_id = self._generate_log_id(log_data)
            
            query = """
            // Create or update source IP
            MERGE (src:IPAddress {address: $source_ip})
            ON CREATE SET 
                src.first_seen = $timestamp,
                src.is_internal = $src_is_internal,
                src.connection_count = 1
            ON MATCH SET 
                src.connection_count = src.connection_count + 1,
                src.last_seen = $timestamp
            
            // Create or update destination IP
            MERGE (dst:IPAddress {address: $destination_ip})
            ON CREATE SET 
                dst.first_seen = $timestamp,
                dst.is_internal = $dst_is_internal,
                dst.connection_count = 1
            ON MATCH SET 
                dst.connection_count = dst.connection_count + 1,
                dst.last_seen = $timestamp
            
            // Create network log
            CREATE (log:NetworkLog {
                log_id: $log_id,
                timestamp: $timestamp,
                log_type: $log_type,
                source_port: $source_port,
                destination_port: $destination_port,
                protocol: $protocol,
                bytes_sent: $bytes_sent,
                bytes_received: $bytes_received,
                duration: $duration,
                action: $action,
                log_level: $log_level,
                threat_level: $threat_level,
                user_agent: $user_agent,
                status_code: $status_code
            })
            
            // Create connections
            CREATE (src)-[:CONNECTED_TO {
                timestamp: $timestamp,
                protocol: $protocol,
                bytes_sent: $bytes_sent,
                bytes_received: $bytes_received,
                duration: $duration
            }]->(dst)
            
            CREATE (log)-[:FROM_IP]->(src)
            CREATE (log)-[:TO_IP]->(dst)
            """
            
            with self.driver.session() as session:
                session.run(query, {
                    'log_id': log_id,
                    'source_ip': log_data['source_ip'],
                    'destination_ip': log_data['destination_ip'],
                    'timestamp': log_data['timestamp'],
                    'log_type': log_data['log_type'],
                    'source_port': log_data['source_port'],
                    'destination_port': log_data['destination_port'],
                    'protocol': log_data['protocol'],
                    'bytes_sent': log_data['bytes_sent'],
                    'bytes_received': log_data['bytes_received'],
                    'duration': log_data['duration'],
                    'action': log_data['action'],
                    'log_level': log_data['log_level'],
                    'threat_level': log_data['threat_level'],
                    'user_agent': log_data.get('user_agent'),
                    'status_code': log_data.get('status_code'),
                    'src_is_internal': self._is_internal_ip(log_data['source_ip']),
                    'dst_is_internal': self._is_internal_ip(log_data['destination_ip'])
                })
            
            self.stats['network_traffic'] += 1
            self.stats['db_writes'] += 1
            return True
            
        except Exception as e:
            logger.error(f"❌ Error processing network traffic log: {e}")
            self.stats['processing_errors'] += 1
            return False

    def _process_security_alert(self, log_data: Dict) -> bool:
        """Process security alert log"""
        if not self.driver:
            logger.error("❌ Neo4j driver not available - cannot process log")
            return False
            
        try:
            alert_id = self._generate_log_id(log_data)
            
            query = """
            // Create or update source IP (attacker)
            MERGE (src:IPAddress {address: $source_ip})
            ON CREATE SET 
                src.first_seen = $timestamp,
                src.is_internal = $src_is_internal,
                src.threat_score = $severity_score,
                src.is_malicious = true,
                src.attack_count = 1
            ON MATCH SET 
                src.attack_count = COALESCE(src.attack_count, 0) + 1,
                src.threat_score = CASE WHEN $severity_score > COALESCE(src.threat_score, 0) 
                                   THEN $severity_score 
                                   ELSE src.threat_score END,
                src.last_attack = $timestamp,
                src.is_malicious = true
            
            // Create or update target IP
            MERGE (dst:IPAddress {address: $destination_ip})
            ON CREATE SET 
                dst.first_seen = $timestamp,
                dst.is_internal = $dst_is_internal,
                dst.times_targeted = 1
            ON MATCH SET 
                dst.times_targeted = COALESCE(dst.times_targeted, 0) + 1,
                dst.last_targeted = $timestamp
            
            // Create security alert
            CREATE (alert:SecurityAlert {
                alert_id: $alert_id,
                timestamp: $timestamp,
                log_type: $log_type,
                source_port: $source_port,
                destination_port: $destination_port,
                protocol: $protocol,
                bytes_sent: $bytes_sent,
                bytes_received: $bytes_received,
                duration: $duration,
                action: $action,
                log_level: $log_level,
                threat_level: $threat_level,
                attack_type: $attack_type,
                attack_signature: $attack_signature,
                severity_score: $severity_score,
                failed_attempts: $failed_attempts,
                target_service: $target_service,
                request_rate: $request_rate,
                payload_size: $payload_size
            })
            
            // Create attack relationship
            CREATE (src)-[:ATTACKED {
                timestamp: $timestamp,
                attack_type: $attack_type,
                severity_score: $severity_score,
                success: CASE WHEN $action = 'ALLOW' THEN true ELSE false END
            }]->(dst)
            
            CREATE (alert)-[:FROM_IP]->(src)
            CREATE (alert)-[:TO_IP]->(dst)
            """
            
            with self.driver.session() as session:
                session.run(query, {
                    'alert_id': alert_id,
                    'source_ip': log_data['source_ip'],
                    'destination_ip': log_data['destination_ip'],
                    'timestamp': log_data['timestamp'],
                    'log_type': log_data['log_type'],
                    'source_port': log_data['source_port'],
                    'destination_port': log_data['destination_port'],
                    'protocol': log_data['protocol'],
                    'bytes_sent': log_data['bytes_sent'],
                    'bytes_received': log_data['bytes_received'],
                    'duration': log_data['duration'],
                    'action': log_data['action'],
                    'log_level': log_data['log_level'],
                    'threat_level': log_data['threat_level'],
                    'attack_type': log_data['attack_type'],
                    'attack_signature': log_data.get('attack_signature'),
                    'severity_score': log_data['severity_score'],
                    'failed_attempts': log_data.get('failed_attempts'),
                    'target_service': log_data.get('target_service'),
                    'request_rate': log_data.get('request_rate'),
                    'payload_size': log_data.get('payload_size'),
                    'src_is_internal': self._is_internal_ip(log_data['source_ip']),
                    'dst_is_internal': self._is_internal_ip(log_data['destination_ip'])
                })
            
            self.stats['security_alerts'] += 1
            self.stats['db_writes'] += 1
            return True
            
        except Exception as e:
            logger.error(f"❌ Error processing security alert: {e}")
            self.stats['processing_errors'] += 1
            return False

    def _process_firewall_log(self, log_data: Dict) -> bool:
        """Process firewall log"""
        if not self.driver:
            logger.error("❌ Neo4j driver not available - cannot process log")
            return False
            
        try:
            log_id = self._generate_log_id(log_data)
            
            query = """
            // Create or update source IP
            MERGE (src:IPAddress {address: $source_ip})
            ON CREATE SET 
                src.first_seen = $timestamp,
                src.is_internal = $src_is_internal
                
            // Create or update destination IP  
            MERGE (dst:IPAddress {address: $destination_ip})
            ON CREATE SET 
                dst.first_seen = $timestamp,
                dst.is_internal = $dst_is_internal
            
            // Create firewall log
            CREATE (fw:FirewallLog {
                log_id: $log_id,
                timestamp: $timestamp,
                log_type: $log_type,
                source_port: $source_port,
                destination_port: $destination_port,
                protocol: $protocol,
                action: $action,
                rule_id: $rule_id,
                bytes_transferred: $bytes_transferred,
                log_level: $log_level,
                interface: $interface,
                threat_level: $threat_level
            })
            
            // Create firewall action relationship
            CREATE (src)-[:FIREWALL_ACTION {
                timestamp: $timestamp,
                action: $action,
                rule_id: $rule_id,
                interface: $interface
            }]->(dst)
            
            CREATE (fw)-[:FROM_IP]->(src)
            CREATE (fw)-[:TO_IP]->(dst)
            """
            
            with self.driver.session() as session:
                session.run(query, {
                    'log_id': log_id,
                    'source_ip': log_data['source_ip'],
                    'destination_ip': log_data['destination_ip'],
                    'timestamp': log_data['timestamp'],
                    'log_type': log_data['log_type'],
                    'source_port': log_data['source_port'],
                    'destination_port': log_data['destination_port'],
                    'protocol': log_data['protocol'],
                    'action': log_data['action'],
                    'rule_id': log_data['rule_id'],
                    'bytes_transferred': log_data['bytes_transferred'],
                    'log_level': log_data['log_level'],
                    'interface': log_data['interface'],
                    'threat_level': log_data['threat_level'],
                    'src_is_internal': self._is_internal_ip(log_data['source_ip']),
                    'dst_is_internal': self._is_internal_ip(log_data['destination_ip'])
                })
            
            self.stats['firewall_logs'] += 1
            self.stats['db_writes'] += 1
            return True
            
        except Exception as e:
            logger.error(f"❌ Error processing firewall log: {e}")
            self.stats['processing_errors'] += 1
            return False

    def _is_internal_ip(self, ip_address: str) -> bool:
        """Check if IP address is internal"""
        try:
            ip = ipaddress.ip_address(ip_address)
            
            # Check for private IP ranges
            private_ranges = [
                ipaddress.ip_network('192.168.0.0/16'),
                ipaddress.ip_network('10.0.0.0/8'),
                ipaddress.ip_network('172.16.0.0/12'),
                ipaddress.ip_network('127.0.0.0/8')  # localhost
            ]
            
            return any(ip in network for network in private_ranges)
        except:
            return False

    def process_log(self, log_data: Dict) -> bool:
        """Process a single log entry based on type"""
        try:
            log_type = log_data.get('log_type', 'unknown')
            
            if log_type == 'network_traffic':
                return self._process_network_traffic_log(log_data)
            elif log_type == 'security_alert':
                return self._process_security_alert(log_data)
            elif log_type == 'firewall':
                return self._process_firewall_log(log_data)
            else:
                logger.warning(f"⚠️ Unknown log type: {log_type}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error processing log: {e}")
            self.stats['processing_errors'] += 1
            return False

    def print_stats(self):
        """Print processing statistics"""
        print(f"""
📊 Network Log Consumer Statistics:
  Total Processed: {self.stats['total_processed']}
  ├── Network Traffic: {self.stats['network_traffic']}
  ├── Security Alerts: {self.stats['security_alerts']}
  ├── Firewall Logs: {self.stats['firewall_logs']}
  ├── Database Writes: {self.stats['db_writes']}
  ├── Processing Errors: {self.stats['processing_errors']}
  ├── Connection Retries: {self.stats['connection_retries']}
  └── Kafka Errors: {self.stats['errors']}
        """)

    def start_consuming(self):
        """Start consuming messages from Kafka"""
        logger.info("🚀 Starting network log consumer...")
        logger.info(f"📡 Kafka Topic: {self.topic}")
        logger.info(f"🔗 Kafka Servers: {self.kafka_servers}")
        logger.info("⏸️  Press Ctrl+C to stop")
        
        self.is_running = True
        
        try:
            # Check if consumer is initialized
            if not self.consumer:
                logger.error("❌ Consumer not initialized")
                return
            
            # Subscribe to topic and check if it exists
            try:
                topics = self.consumer.topics()
                if self.topic not in topics:
                    logger.warning(f"⚠️ Topic '{self.topic}' not found. Available topics: {list(topics)}")
                    self._create_topic_if_missing()
                else:
                    logger.info(f"✅ Topic '{self.topic}' found successfully")
            except Exception as e:
                logger.warning(f"⚠️ Could not check topics: {e}")
            
            message_count = 0
            last_message_time = time.time()
            
            logger.info("🔍 Waiting for messages...")
            
            for message in self.consumer:
                if not self.is_running:
                    break
                
                try:
                    log_data = message.value
                    key = message.key
                    message_count += 1
                    last_message_time = time.time()
                    
                    # Process the log
                    success = self.process_log(log_data)
                    
                    if success:
                        self.stats['total_processed'] += 1
                        
                        # Print log summary
                        threat_level = log_data.get('threat_level', 'UNKNOWN')
                        log_type = log_data.get('log_type', 'unknown')
                        src_ip = log_data.get('source_ip', 'unknown')
                        dst_ip = log_data.get('destination_ip', 'unknown')
                        
                        threat_emoji = {
                            'LOW': '🟢',
                            'MEDIUM': '🟡', 
                            'HIGH': '🟠',
                            'CRITICAL': '🔴'
                        }.get(threat_level, '⚪')
                        
                        print(f"{threat_emoji} Processed {log_type}: {src_ip} -> {dst_ip} [{threat_level}]")
                    
                    # Print stats every 10 messages (reduced from 25 for better feedback)
                    if self.stats['total_processed'] % 10 == 0 and self.stats['total_processed'] > 0:
                        self.print_stats()
                        
                except json.JSONDecodeError as e:
                    logger.error(f"❌ Invalid JSON in message: {e}")
                    self.stats['errors'] += 1
                except Exception as e:
                    logger.error(f"❌ Error processing message: {e}")
                    self.stats['errors'] += 1
            
            # If we reach here without processing any messages
            if message_count == 0:
                logger.info("ℹ️ No messages received. Check if producer is sending data to the topic.")
                logger.info("💡 Try running the producer in another terminal: python producer.py")
                
        except KeyboardInterrupt:
            logger.info("\n🛑 Stopping consumer...")
            self.is_running = False
        except KafkaError as e:
            logger.error(f"❌ Kafka error: {e}")
            logger.error("💡 Make sure Kafka is running on localhost:9092")
        except Exception as e:
            logger.error(f"❌ Unexpected error: {e}")
            
        finally:
            self.print_stats()
            if self.consumer:
                try:
                    self.consumer.close()
                    logger.info("🔌 Kafka consumer connection closed")
                except:
                    pass
            logger.info("✅ Consumer stopped")

def start_consumer_thread():
    """Start consumer in a separate thread"""
    def consumer_worker():
        try:
            consumer = NetworkLogConsumer()
            consumer.start_consuming()
        except Exception as e:
            logger.error(f"❌ Consumer thread error: {e}")
    
    thread = threading.Thread(target=consumer_worker, daemon=True)
    thread.start()
    logger.info("✅ Consumer thread started")
    return thread

def main():
    """Main function for standalone execution"""
    print("🔥 Network Log Analysis - Kafka Consumer")
    print("=" * 50)
    print("🔌 Connecting to Kafka on localhost:9092")
    print("📋 Topic: network-logs")
    print("🗄️  Database: Neo4j on localhost:7687")
    print("=" * 50)
    
    try:
        consumer = NetworkLogConsumer()
        consumer.start_consuming()
    except Exception as e:
        logger.error(f"❌ Failed to start consumer: {e}")
        print("\n💡 Troubleshooting tips:")
        print("1. Make sure Kafka is running: lsof -i :9092")
        print("2. Make sure Neo4j is running: lsof -i :7687")
        print("3. Check if producer is running in another terminal")
        print("4. Verify topic exists: kafka-topics --list --bootstrap-server localhost:9092")

if __name__ == "__main__":
    main()