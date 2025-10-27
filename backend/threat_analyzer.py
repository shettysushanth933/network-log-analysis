import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional
from langchain_core.prompts import PromptTemplate
from groq_client import get_groq_llm
from neo4j_client import driver
import json
from collections import defaultdict, Counter
import ipaddress

class ThreatIntelligenceAnalyzer:
    def __init__(self):
        self.llm = get_groq_llm()
        self.driver = driver
        
        # AI Analysis Prompts
        self.attack_pattern_prompt = PromptTemplate(
            input_variables=["coordinated_attacks", "attack_timeline", "ip_clusters", "statistics"],
            template="""
You are an expert cybersecurity threat analyst. Analyze the following coordinated attack patterns:

COORDINATED ATTACKS DETECTED:
{coordinated_attacks}

ATTACK TIMELINE:
{attack_timeline}

IP ATTACK CLUSTERS:
{ip_clusters}

STATISTICS:
{statistics}

Provide detailed analysis:
1. **Attack Campaign Assessment**: Are these coordinated attacks part of a larger campaign?
2. **Threat Actor Profiling**: What type of threat actor might be behind these attacks?
3. **Attack Sophistication**: Rate the sophistication level (1-10) and explain
4. **Target Selection**: What appears to be the attacker's target selection criteria?
5. **Mitigation Recommendations**: Specific steps to counter these attack patterns
6. **Indicators of Compromise (IoCs)**: Key indicators to monitor
7. **Risk Level**: Rate overall risk (LOW/MEDIUM/HIGH/CRITICAL) with reasoning

Be specific and provide actionable security insights.
"""
        )
        
        self.apt_analysis_prompt = PromptTemplate(
            input_variables=["long_term_patterns", "persistence_indicators", "stealth_metrics", "attribution_clues"],
            template="""
Analyze potential Advanced Persistent Threat (APT) activity:

LONG-TERM ATTACK PATTERNS:
{long_term_patterns}

PERSISTENCE INDICATORS:
{persistence_indicators}

STEALTH METRICS:
{stealth_metrics}

ATTRIBUTION CLUES:
{attribution_clues}

Provide APT assessment:
1. **APT Likelihood**: Probability this is APT activity (0-100%) with reasoning
2. **Campaign Duration**: Estimated length and phases of the campaign
3. **Persistence Mechanisms**: How attackers maintain access
4. **Stealth Techniques**: Methods used to avoid detection
5. **Attribution Analysis**: Possible threat group characteristics
6. **Impact Assessment**: Potential data/system compromise
7. **Countermeasures**: Specific APT mitigation strategies
8. **Hunting Recommendations**: What to look for to find more APT activity

Focus on long-term strategic threats and advanced evasion techniques.
"""
        )

        self.malware_behavior_prompt = PromptTemplate(
            input_variables=["cc_patterns", "malware_indicators", "communication_analysis", "behavioral_signatures"],
            template="""
Analyze potential malware Command & Control (C&C) behavior:

C&C COMMUNICATION PATTERNS:
{cc_patterns}

MALWARE INDICATORS:
{malware_indicators}

COMMUNICATION ANALYSIS:
{communication_analysis}

BEHAVIORAL SIGNATURES:
{behavioral_signatures}

Provide malware analysis:
1. **Malware Classification**: Likely malware type (botnet, RAT, ransomware, etc.)
2. **C&C Infrastructure**: Analysis of command and control setup
3. **Communication Protocols**: How malware communicates with C&C servers
4. **Infection Spread**: How the malware might be spreading
5. **Payload Analysis**: Likely malware capabilities and objectives
6. **Evasion Techniques**: Methods used to avoid detection
7. **Disruption Strategy**: How to disrupt the malware operation
8. **Network Signatures**: Patterns to detect similar infections

Focus on behavioral analysis and network-based malware detection.
"""
        )

    def _convert_numpy_types(self, obj):
        """Convert numpy types to Python native types"""
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, dict):
            return {key: self._convert_numpy_types(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._convert_numpy_types(item) for item in obj]
        return obj

    def analyze_attack_patterns(self, time_window_hours: int = 24) -> Dict[str, Any]:
        """Analyze coordinated attack patterns"""
        try:
            # Get recent attack data
            coordinated_attacks = self._detect_coordinated_attacks(time_window_hours)
            attack_timeline = self._build_attack_timeline(time_window_hours)
            ip_clusters = self._analyze_ip_attack_clusters(time_window_hours)
            statistics = self._get_attack_statistics(time_window_hours)
            
            # Generate AI analysis
            ai_analysis = self._generate_attack_pattern_analysis(
                coordinated_attacks, attack_timeline, ip_clusters, statistics
            )
            
            result = {
                "analysis_type": "attack_pattern_recognition",
                "time_window_hours": time_window_hours,
                "coordinated_attacks": coordinated_attacks,
                "attack_timeline": attack_timeline,
                "ip_clusters": ip_clusters,
                "statistics": statistics,
                "ai_analysis": ai_analysis,
                "risk_score": self._calculate_attack_risk_score(coordinated_attacks, ip_clusters),
                "timestamp": datetime.now().isoformat()
            }
            
            return self._convert_numpy_types(result)
            
        except Exception as e:
            return {"error": f"Attack pattern analysis failed: {str(e)}"}

    def analyze_apt_activity(self, days_back: int = 30) -> Dict[str, Any]:
        """Analyze potential APT (Advanced Persistent Threat) activity"""
        try:
            # Long-term pattern analysis
            long_term_patterns = self._detect_long_term_patterns(days_back)
            persistence_indicators = self._find_persistence_indicators(days_back)
            stealth_metrics = self._calculate_stealth_metrics(days_back)
            attribution_clues = self._gather_attribution_clues(days_back)
            
            # Generate AI analysis
            ai_analysis = self._generate_apt_analysis(
                long_term_patterns, persistence_indicators, stealth_metrics, attribution_clues
            )
            
            result = {
                "analysis_type": "apt_detection",
                "analysis_period_days": days_back,
                "long_term_patterns": long_term_patterns,
                "persistence_indicators": persistence_indicators,
                "stealth_metrics": stealth_metrics,
                "attribution_clues": attribution_clues,
                "ai_analysis": ai_analysis,
                "apt_probability": self._calculate_apt_probability(long_term_patterns, persistence_indicators),
                "timestamp": datetime.now().isoformat()
            }
            
            return self._convert_numpy_types(result)
            
        except Exception as e:
            return {"error": f"APT analysis failed: {str(e)}"}

    def analyze_malware_behavior(self, hours_back: int = 12) -> Dict[str, Any]:
        """Analyze malware C&C behavior patterns"""
        try:
            # Malware behavior analysis
            cc_patterns = self._detect_cc_patterns(hours_back)
            malware_indicators = self._identify_malware_indicators(hours_back)
            communication_analysis = self._analyze_malware_communication(hours_back)
            behavioral_signatures = self._extract_behavioral_signatures(hours_back)
            
            # Generate AI analysis
            ai_analysis = self._generate_malware_analysis(
                cc_patterns, malware_indicators, communication_analysis, behavioral_signatures
            )
            
            result = {
                "analysis_type": "malware_behavior_analysis",
                "analysis_window_hours": hours_back,
                "cc_patterns": cc_patterns,
                "malware_indicators": malware_indicators,
                "communication_analysis": communication_analysis,
                "behavioral_signatures": behavioral_signatures,
                "ai_analysis": ai_analysis,
                "malware_confidence": self._calculate_malware_confidence(cc_patterns, malware_indicators),
                "timestamp": datetime.now().isoformat()
            }
            
            return self._convert_numpy_types(result)
            
        except Exception as e:
            return {"error": f"Malware analysis failed: {str(e)}"}

    def detect_zero_day_indicators(self, hours_back: int = 6) -> Dict[str, Any]:
        """Detect potential zero-day attack indicators"""
        try:
            # Zero-day detection
            unusual_patterns = self._find_unusual_attack_patterns(hours_back)
            novel_techniques = self._identify_novel_techniques(hours_back)
            signature_gaps = self._detect_signature_gaps(hours_back)
            anomaly_score = self._calculate_anomaly_score(hours_back)
            
            result = {
                "analysis_type": "zero_day_detection",
                "analysis_window_hours": hours_back,
                "unusual_patterns": unusual_patterns,
                "novel_techniques": novel_techniques,
                "signature_gaps": signature_gaps,
                "anomaly_score": anomaly_score,
                "zero_day_likelihood": self._calculate_zero_day_likelihood(unusual_patterns, anomaly_score),
                "recommendations": self._generate_zero_day_recommendations(unusual_patterns),
                "timestamp": datetime.now().isoformat()
            }
            
            return self._convert_numpy_types(result)
            
        except Exception as e:
            return {"error": f"Zero-day detection failed: {str(e)}"}

    def _detect_coordinated_attacks(self, hours_back: int) -> Dict[str, Any]:
        """Detect coordinated attacks across multiple IPs"""
        query = """
        MATCH (alert:SecurityAlert)-[:FROM_IP]->(src:IPAddress)
        WHERE alert.timestamp >= datetime() - duration({hours: $hours_back})
        WITH src.address as source_ip, 
             alert.attack_type as attack_type,
             count(alert) as attack_count,
             collect(alert.destination_ip)[0..5] as targets,
             avg(alert.severity_score) as avg_severity
        WHERE attack_count >= 3
        RETURN source_ip, attack_type, attack_count, targets, avg_severity
        ORDER BY attack_count DESC
        LIMIT 20
        """
        
        with self.driver.session() as session:
            result = session.run(query, {"hours_back": hours_back})
            
            coordinated = []
            for record in result:
                coordinated.append({
                    "source_ip": record["source_ip"],
                    "attack_type": record["attack_type"],
                    "attack_count": int(record["attack_count"]),
                    "targets": record["targets"],
                    "avg_severity": float(record["avg_severity"])
                })
            
            return {
                "total_coordinated_sources": len(coordinated),
                "attacks": coordinated,
                "top_attack_types": Counter([a["attack_type"] for a in coordinated]).most_common(5)
            }

    def _build_attack_timeline(self, hours_back: int) -> Dict[str, Any]:
        """Build timeline of attacks"""
        query = """
        MATCH (alert:SecurityAlert)
        WHERE alert.timestamp >= datetime() - duration({hours: $hours_back})
        RETURN alert.timestamp as timestamp,
               alert.attack_type as attack_type,
               alert.threat_level as threat_level,
               alert.source_ip as source_ip,
               alert.severity_score as severity
        ORDER BY alert.timestamp ASC
        """
        
        with self.driver.session() as session:
            result = session.run(query, {"hours_back": hours_back})
            
            timeline = []
            hourly_counts = defaultdict(int)
            
            for record in result:
                timestamp = record["timestamp"]
                # Parse Neo4j datetime to get hour
                hour = timestamp.hour if hasattr(timestamp, 'hour') else 0
                hourly_counts[hour] += 1
                
                timeline.append({
                    "timestamp": str(timestamp),
                    "attack_type": record["attack_type"],
                    "threat_level": record["threat_level"],
                    "source_ip": record["source_ip"],
                    "severity": float(record["severity"])
                })
            
            return {
                "total_events": len(timeline),
                "events": timeline[-50:],  # Last 50 events
                "hourly_distribution": dict(hourly_counts),
                "peak_hour": max(hourly_counts.keys(), key=hourly_counts.get) if hourly_counts else 0
            }

    def _analyze_ip_attack_clusters(self, hours_back: int) -> Dict[str, Any]:
        """Analyze IP address attack clusters"""
        query = """
        MATCH (src:IPAddress)-[attack:ATTACKED]->(dst:IPAddress)
        WHERE attack.timestamp >= datetime() - duration({hours: $hours_back})
        RETURN src.address as attacker_ip,
               count(attack) as total_attacks,
               collect(DISTINCT dst.address)[0..10] as targets,
               collect(DISTINCT attack.attack_type)[0..5] as attack_types,
               avg(attack.severity_score) as avg_severity,
               src.is_internal as is_internal
        ORDER BY total_attacks DESC
        LIMIT 15
        """
        
        with self.driver.session() as session:
            result = session.run(query, {"hours_back": hours_back})
            
            clusters = []
            for record in result:
                clusters.append({
                    "attacker_ip": record["attacker_ip"],
                    "total_attacks": int(record["total_attacks"]),
                    "unique_targets": len(record["targets"]),
                    "targets": record["targets"],
                    "attack_types": record["attack_types"],
                    "avg_severity": float(record["avg_severity"]),
                    "is_internal": record["is_internal"],
                    "cluster_score": int(record["total_attacks"]) * len(record["targets"])
                })
            
            return {
                "total_clusters": len(clusters),
                "clusters": clusters,
                "external_attackers": len([c for c in clusters if not c["is_internal"]]),
                "internal_attackers": len([c for c in clusters if c["is_internal"]])
            }

    def _get_attack_statistics(self, hours_back: int) -> Dict[str, Any]:
        """Get attack statistics"""
        query = """
        MATCH (alert:SecurityAlert)
        WHERE alert.timestamp >= datetime() - duration({hours: $hours_back})
        RETURN count(alert) as total_alerts,
               count(DISTINCT alert.source_ip) as unique_attackers,
               count(DISTINCT alert.destination_ip) as unique_targets,
               avg(alert.severity_score) as avg_severity,
               collect(DISTINCT alert.attack_type) as attack_types,
               collect(DISTINCT alert.threat_level) as threat_levels
        """
        
        with self.driver.session() as session:
            result = session.run(query, {"hours_back": hours_back})
            record = result.single()
            
            return {
                "total_alerts": int(record["total_alerts"]),
                "unique_attackers": int(record["unique_attackers"]),
                "unique_targets": int(record["unique_targets"]),
                "avg_severity": float(record["avg_severity"]),
                "attack_types": record["attack_types"],
                "threat_levels": record["threat_levels"],
                "attacks_per_hour": float(record["total_alerts"]) / hours_back
            }

    def _detect_long_term_patterns(self, days_back: int) -> Dict[str, Any]:
        """Detect long-term attack patterns for APT analysis"""
        query = """
        MATCH (alert:SecurityAlert)-[:FROM_IP]->(src:IPAddress)
        WHERE alert.timestamp >= datetime() - duration({days: $days_back})
        WITH src.address as attacker_ip,
             date(alert.timestamp) as attack_date,
             count(alert) as daily_attacks
        WITH attacker_ip,
             count(DISTINCT attack_date) as active_days,
             avg(daily_attacks) as avg_daily_attacks,
             max(daily_attacks) as max_daily_attacks,
             collect(attack_date)[0..10] as attack_dates
        WHERE active_days >= 3
        RETURN attacker_ip, active_days, avg_daily_attacks, 
               max_daily_attacks, attack_dates
        ORDER BY active_days DESC, avg_daily_attacks ASC
        LIMIT 10
        """
        
        with self.driver.session() as session:
            result = session.run(query, {"days_back": days_back})
            
            patterns = []
            for record in result:
                patterns.append({
                    "attacker_ip": record["attacker_ip"],
                    "active_days": int(record["active_days"]),
                    "avg_daily_attacks": float(record["avg_daily_attacks"]),
                    "max_daily_attacks": int(record["max_daily_attacks"]),
                    "persistence_score": int(record["active_days"]) / days_back * 100,
                    "stealth_score": 100 - float(record["avg_daily_attacks"]) * 10  # Lower activity = higher stealth
                })
            
            return {
                "persistent_attackers": len(patterns),
                "patterns": patterns,
                "avg_persistence_days": np.mean([p["active_days"] for p in patterns]) if patterns else 0
            }

    def _find_persistence_indicators(self, days_back: int) -> Dict[str, Any]:
        """Find indicators of persistent access"""
        # Look for regular, low-volume connections that might indicate persistent access
        query = """
        MATCH (log:NetworkLog)-[:FROM_IP]->(src:IPAddress)
        WHERE log.timestamp >= datetime() - duration({days: $days_back})
          AND src.is_internal = false
        WITH src.address as external_ip,
             date(log.timestamp) as connection_date,
             count(log) as daily_connections,
             avg(log.bytes_sent + log.bytes_received) as avg_bytes
        WITH external_ip,
             count(DISTINCT connection_date) as connection_days,
             avg(daily_connections) as avg_daily_connections,
             avg(avg_bytes) as avg_data_transfer
        WHERE connection_days >= 5 AND avg_daily_connections < 50  # Regular but low volume
        RETURN external_ip, connection_days, avg_daily_connections, avg_data_transfer
        ORDER BY connection_days DESC
        LIMIT 15
        """
        
        with self.driver.session() as session:
            result = session.run(query, {"days_back": days_back})
            
            indicators = []
            for record in result:
                indicators.append({
                    "ip_address": record["external_ip"],
                    "connection_days": int(record["connection_days"]),
                    "avg_daily_connections": float(record["avg_daily_connections"]),
                    "avg_data_transfer": float(record["avg_data_transfer"]),
                    "persistence_indicator_score": (int(record["connection_days"]) / days_back) * 100
                })
            
            return {
                "total_persistence_indicators": len(indicators),
                "indicators": indicators,
                "high_persistence_ips": [i for i in indicators if i["persistence_indicator_score"] > 30]
            }

    def _calculate_stealth_metrics(self, days_back: int) -> Dict[str, Any]:
        """Calculate stealth metrics for potential APT activity"""
        # Analyze traffic that might be designed to blend in
        query = """
        MATCH (alert:SecurityAlert)
        WHERE alert.timestamp >= datetime() - duration({days: $days_back})
        WITH alert.source_ip as attacker_ip,
             count(alert) as total_alerts,
             avg(alert.severity_score) as avg_severity,
             stdDev(alert.severity_score) as severity_stddev
        RETURN attacker_ip, total_alerts, avg_severity, severity_stddev
        ORDER BY avg_severity ASC, total_alerts DESC
        LIMIT 20
        """
        
        with self.driver.session() as session:
            result = session.run(query, {"days_back": days_back})
            
            stealth_ips = []
            for record in result:
                stealth_score = 100 - (float(record["avg_severity"]) * 10)  # Lower severity = higher stealth
                stealth_ips.append({
                    "ip_address": record["attacker_ip"],
                    "total_alerts": int(record["total_alerts"]),
                    "avg_severity": float(record["avg_severity"]),
                    "stealth_score": max(0, stealth_score)
                })
            
            return {
                "potential_stealth_attackers": len([s for s in stealth_ips if s["stealth_score"] > 70]),
                "stealth_metrics": stealth_ips,
                "avg_stealth_score": np.mean([s["stealth_score"] for s in stealth_ips]) if stealth_ips else 0
            }

    def _gather_attribution_clues(self, days_back: int) -> Dict[str, Any]:
        """Gather clues for threat actor attribution"""
        query = """
        MATCH (alert:SecurityAlert)
        WHERE alert.timestamp >= datetime() - duration({days: $days_back})
        RETURN alert.attack_type as attack_type,
               alert.source_ip as source_ip,
               alert.destination_port as target_port,
               alert.target_service as target_service,
               count(*) as frequency
        ORDER BY frequency DESC
        """
        
        with self.driver.session() as session:
            result = session.run(query, {"days_back": days_back})
            
            ttps = []  # Tactics, Techniques, and Procedures
            target_analysis = defaultdict(int)
            
            for record in result:
                ttps.append({
                    "attack_type": record["attack_type"],
                    "frequency": int(record["frequency"]),
                    "target_port": record["target_port"],
                    "target_service": record["target_service"]
                })
                
                if record["target_service"]:
                    target_analysis[record["target_service"]] += int(record["frequency"])
            
            return {
                "tactics_techniques_procedures": ttps[:10],
                "target_preferences": dict(target_analysis),
                "attack_sophistication": self._assess_attack_sophistication(ttps),
                "likely_objectives": self._infer_attack_objectives(target_analysis)
            }

    def _detect_cc_patterns(self, hours_back: int) -> Dict[str, Any]:
        """Detect Command & Control communication patterns"""
        # Look for regular, automated-looking traffic patterns
        query = """
        MATCH (log:NetworkLog)-[:FROM_IP]->(src:IPAddress), 
              (log)-[:TO_IP]->(dst:IPAddress)
        WHERE log.timestamp >= datetime() - duration({hours: $hours_back})
          AND src.is_internal = true AND dst.is_internal = false
        WITH dst.address as external_ip,
             count(log) as connection_count,
             avg(log.bytes_sent) as avg_bytes_sent,
             avg(log.bytes_received) as avg_bytes_received,
             stdDev(log.duration) as duration_stddev,
             collect(DISTINCT log.destination_port) as ports_used
        WHERE connection_count > 10 AND duration_stddev < 1.0  # Regular intervals
        RETURN external_ip, connection_count, avg_bytes_sent, 
               avg_bytes_received, duration_stddev, ports_used
        ORDER BY connection_count DESC
        LIMIT 10
        """
        
        with self.driver.session() as session:
            result = session.run(query, {"hours_back": hours_back})
            
            cc_candidates = []
            for record in result:
                cc_score = int(record["connection_count"]) / (float(record["duration_stddev"]) + 0.1)
                cc_candidates.append({
                    "external_ip": record["external_ip"],
                    "connection_count": int(record["connection_count"]),
                    "avg_bytes_sent": float(record["avg_bytes_sent"]),
                    "avg_bytes_received": float(record["avg_bytes_received"]),
                    "regularity_score": 100 - (float(record["duration_stddev"]) * 50),
                    "cc_likelihood_score": min(100, cc_score),
                    "ports_used": record["ports_used"]
                })
            
            return {
                "potential_cc_servers": len([c for c in cc_candidates if c["cc_likelihood_score"] > 50]),
                "cc_patterns": cc_candidates,
                "high_confidence_cc": [c for c in cc_candidates if c["cc_likelihood_score"] > 75]
            }

    def _identify_malware_indicators(self, hours_back: int) -> Dict[str, Any]:
        """Identify malware behavioral indicators"""
        # Look for typical malware network behaviors
        indicators = {
            "beaconing": self._detect_beaconing_behavior(hours_back),
            "data_exfiltration": self._detect_data_exfiltration(hours_back),
            "lateral_movement": self._detect_lateral_movement(hours_back),
            "suspicious_dns": self._detect_suspicious_dns(hours_back)
        }
        
        return indicators

    def _detect_beaconing_behavior(self, hours_back: int) -> List[Dict]:
        """Detect beaconing behavior typical of malware"""
        query = """
        MATCH (log:NetworkLog)-[:FROM_IP]->(src:IPAddress), 
              (log)-[:TO_IP]->(dst:IPAddress)
        WHERE log.timestamp >= datetime() - duration({hours: $hours_back})
          AND src.is_internal = true AND dst.is_internal = false
        WITH src.address as internal_ip, dst.address as external_ip,
             count(log) as beacon_count,
             avg(log.bytes_sent) as avg_out_bytes,
             stdDev(log.bytes_sent) as out_bytes_stddev
        WHERE beacon_count > 20 AND out_bytes_stddev < 100  # Consistent small packets
        RETURN internal_ip, external_ip, beacon_count, avg_out_bytes, out_bytes_stddev
        LIMIT 10
        """
        
        with self.driver.session() as session:
            result = session.run(query, {"hours_back": hours_back})
            
            beacons = []
            for record in result:
                beacons.append({
                    "internal_ip": record["internal_ip"],
                    "external_ip": record["external_ip"],
                    "beacon_count": int(record["beacon_count"]),
                    "avg_out_bytes": float(record["avg_out_bytes"]),
                    "consistency_score": 100 - float(record["out_bytes_stddev"])
                })
            
            return beacons

    def _calculate_attack_risk_score(self, coordinated_attacks: Dict, ip_clusters: Dict) -> float:
        """Calculate overall attack risk score"""
        base_score = 0
        
        # Factor in coordinated attacks
        if coordinated_attacks["total_coordinated_sources"] > 5:
            base_score += 30
        elif coordinated_attacks["total_coordinated_sources"] > 0:
            base_score += 15
        
        # Factor in IP clusters
        high_impact_clusters = len([c for c in ip_clusters["clusters"] if c["cluster_score"] > 50])
        base_score += min(40, high_impact_clusters * 8)
        
        # Factor in external vs internal attackers
        if ip_clusters["external_attackers"] > ip_clusters["internal_attackers"]:
            base_score += 20
        
        return min(100, base_score)

    def _calculate_apt_probability(self, long_term_patterns: Dict, persistence_indicators: Dict) -> float:
        """Calculate APT probability score"""
        probability = 0
        
        # Long-term persistence
        if long_term_patterns["persistent_attackers"] > 0:
            avg_persistence = long_term_patterns["avg_persistence_days"]
            probability += min(40, avg_persistence * 2)
        
        # Persistence indicators
        high_persistence = len(persistence_indicators["high_persistence_ips"])
        probability += min(30, high_persistence * 10)
        
        # Stealth behavior
        stealth_attackers = len([p for p in long_term_patterns["patterns"] if p["stealth_score"] > 70])
        probability += min(30, stealth_attackers * 15)
        
        return min(100, probability)

    def _calculate_malware_confidence(self, cc_patterns: Dict, malware_indicators: Dict) -> float:
        """Calculate malware presence confidence"""
        confidence = 0
        
        # C&C patterns
        high_confidence_cc = len(cc_patterns["high_confidence_cc"])
        confidence += min(40, high_confidence_cc * 20)
        
        # Beaconing behavior
        beaconing_hosts = len(malware_indicators["beaconing"])
        confidence += min(30, beaconing_hosts * 15)
        
        # Multiple indicators
        indicator_types = sum([
            len(malware_indicators["beaconing"]) > 0,
            len(malware_indicators["data_exfiltration"]) > 0,
            len(malware_indicators["lateral_movement"]) > 0,
            len(malware_indicators["suspicious_dns"]) > 0
        ])
        confidence += indicator_types * 7.5
        
        return min(100, confidence)

    # Additional helper methods would be implemented here...
    # (Continuing with the remaining detection methods)

    def _generate_attack_pattern_analysis(self, coordinated_attacks, attack_timeline, ip_clusters, statistics) -> str:
        """Generate AI analysis of attack patterns"""
        try:
            coordinated_summary = f"""
            Coordinated Attack Sources: {coordinated_attacks['total_coordinated_sources']}
            Top Attack Types: {', '.join([f"{name} ({count})" for name, count in coordinated_attacks['top_attack_types']])}
            Most Active Cluster: {ip_clusters['clusters'][0]['attacker_ip'] if ip_clusters['clusters'] else 'None'} 
                                 ({ip_clusters['clusters'][0]['total_attacks']} attacks) if ip_clusters['clusters'] else ''
            """
            
            timeline_summary = f"""
            Total Attack Events: {attack_timeline['total_events']}
            Peak Attack Hour: {attack_timeline['peak_hour']}:00
            Recent Event Types: {', '.join(set([e['attack_type'] for e in attack_timeline['events'][-10:]]))}
            """
            
            cluster_summary = f"""
            Attack Clusters: {ip_clusters['total_clusters']}
            External Attackers: {ip_clusters['external_attackers']}
            Internal Compromised: {ip_clusters['internal_attackers']}
            Top Cluster Score: {max([c['cluster_score'] for c in ip_clusters['clusters']], default=0)}
            """
            
            stats_summary = f"""
            Attack Statistics:
            - Total Alerts: {statistics['total_alerts']}
            - Unique Attackers: {statistics['unique_attackers']} 
            - Unique Targets: {statistics['unique_targets']}
            - Average Severity: {statistics['avg_severity']:.1f}/10
            - Attacks per Hour: {statistics['attacks_per_hour']:.1f}
            """
            
            # Modern LangChain syntax
            chain = self.attack_pattern_prompt | self.llm
            
            response = chain.invoke({
                "coordinated_attacks": coordinated_summary,
                "attack_timeline": timeline_summary,
                "ip_clusters": cluster_summary,
                "statistics": stats_summary
            })
            
            return response.content if hasattr(response, 'content') else str(response)
            
        except Exception as e:
            return f"Error generating attack pattern analysis: {str(e)}"

    def _generate_apt_analysis(self, long_term_patterns, persistence_indicators, stealth_metrics, attribution_clues) -> str:
        """Generate AI analysis of APT activity"""
        try:
            # Implementation similar to above but for APT analysis
            # Using the apt_analysis_prompt
            pass
        except Exception as e:
            return f"Error generating APT analysis: {str(e)}"

    def _generate_malware_analysis(self, cc_patterns, malware_indicators, communication_analysis, behavioral_signatures) -> str:
        """Generate AI analysis of malware behavior"""
        try:
            # Implementation similar to above but for malware analysis
            # Using the malware_behavior_prompt
            pass
        except Exception as e:
            return f"Error generating malware analysis: {str(e)}"

# Global instance
threat_analyzer = None

def get_threat_analyzer():
    """Get or create threat analyzer instance"""
    global threat_analyzer
    if threat_analyzer is None:
        threat_analyzer = ThreatIntelligenceAnalyzer()
    return threat_analyzer