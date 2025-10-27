from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
from datetime import datetime
from threat_analyzer import get_threat_analyzer

router = APIRouter(prefix="/threat-intelligence", tags=["Threat Intelligence"])

class ThreatAnalysisResponse(BaseModel):
    status: str
    analysis_type: str
    data: Dict[str, Any]
    timestamp: str

class ThreatHealthResponse(BaseModel):
    status: str
    message: str
    services: Dict[str, str]
    timestamp: str

@router.get("/attack-patterns", response_model=ThreatAnalysisResponse)
async def analyze_attack_patterns(
    time_window: int = Query(24, description="Time window in hours", ge=1, le=168)
):
    """
    Analyze coordinated attack patterns and multi-IP campaigns
    
    - **time_window**: Analysis window in hours (1-168 hours)
    - Returns AI-powered analysis of attack coordination and patterns
    """
    try:
        analyzer = get_threat_analyzer()
        result = analyzer.analyze_attack_patterns(time_window_hours=time_window)
        
        if "error" in result:
            raise HTTPException(status_code=500, detail=result["error"])
        
        return ThreatAnalysisResponse(
            status="success",
            analysis_type="attack_pattern_recognition",
            data=result,
            timestamp=result["timestamp"]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Attack pattern analysis failed: {str(e)}")

@router.get("/apt-detection", response_model=ThreatAnalysisResponse)
async def detect_apt_activity(
    days_back: int = Query(30, description="Analysis period in days", ge=7, le=365)
):
    """
    Detect Advanced Persistent Threat (APT) activity
    
    - **days_back**: Analysis period in days (7-365 days)
    - Returns APT likelihood assessment and long-term attack analysis
    """
    try:
        analyzer = get_threat_analyzer()
        result = analyzer.analyze_apt_activity(days_back=days_back)
        
        if "error" in result:
            raise HTTPException(status_code=500, detail=result["error"])
        
        return ThreatAnalysisResponse(
            status="success", 
            analysis_type="apt_detection",
            data=result,
            timestamp=result["timestamp"]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"APT detection failed: {str(e)}")

@router.get("/malware-behavior", response_model=ThreatAnalysisResponse)
async def analyze_malware_behavior(
    hours_back: int = Query(12, description="Analysis window in hours", ge=1, le=72)
):
    """
    Analyze malware Command & Control (C&C) behavior patterns
    
    - **hours_back**: Analysis window in hours (1-72 hours)
    - Returns C&C communication analysis and malware behavioral indicators
    """
    try:
        analyzer = get_threat_analyzer()
        result = analyzer.analyze_malware_behavior(hours_back=hours_back)
        
        if "error" in result:
            raise HTTPException(status_code=500, detail=result["error"])
        
        return ThreatAnalysisResponse(
            status="success",
            analysis_type="malware_behavior_analysis", 
            data=result,
            timestamp=result["timestamp"]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Malware behavior analysis failed: {str(e)}")

@router.get("/zero-day-indicators", response_model=ThreatAnalysisResponse)
async def detect_zero_day_indicators(
    hours_back: int = Query(6, description="Analysis window in hours", ge=1, le=48)
):
    """
    Detect potential zero-day attack indicators and novel techniques
    
    - **hours_back**: Analysis window in hours (1-48 hours)
    - Returns zero-day likelihood assessment and unusual pattern detection
    """
    try:
        analyzer = get_threat_analyzer()
        result = analyzer.detect_zero_day_indicators(hours_back=hours_back)
        
        if "error" in result:
            raise HTTPException(status_code=500, detail=result["error"])
        
        return ThreatAnalysisResponse(
            status="success",
            analysis_type="zero_day_detection",
            data=result, 
            timestamp=result["timestamp"]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Zero-day detection failed: {str(e)}")

@router.get("/ip-reputation/{ip_address}")
async def get_ip_reputation(ip_address: str):
    """
    Get comprehensive IP address reputation and threat intelligence
    
    - **ip_address**: IP address to analyze
    - Returns threat score, attack history, and behavioral analysis
    """
    try:
        analyzer = get_threat_analyzer()
        
        # Import here to avoid circular imports
        from neo4j_client import driver
        
        if not driver:
            raise HTTPException(status_code=500, detail="Database connection not available")
        
        query = """
        MATCH (ip:IPAddress {address: $ip_address})
        OPTIONAL MATCH (ip)<-[:FROM_IP]-(alert:SecurityAlert)
        OPTIONAL MATCH (ip)<-[:FROM_IP]-(log:NetworkLog)
        RETURN ip,
               count(DISTINCT alert) as total_alerts,
               count(DISTINCT log) as total_connections,
               collect(DISTINCT alert.attack_type)[0..5] as attack_types,
               avg(alert.severity_score) as avg_severity,
               max(alert.timestamp) as last_attack,
               ip.threat_score as threat_score,
               ip.is_malicious as is_malicious,
               ip.attack_count as attack_count
        """
        
        with driver.session() as session:
            result = session.run(query, {"ip_address": ip_address})
            record = result.single()
            
            if not record or not record["ip"]:
                raise HTTPException(status_code=404, detail=f"IP address {ip_address} not found in threat database")
            
            ip_data = record["ip"]
            
            reputation_data = {
                "ip_address": ip_address,
                "threat_score": record["threat_score"] or 0,
                "is_malicious": record["is_malicious"] or False,
                "is_internal": ip_data.get("is_internal", False),
                "total_alerts": record["total_alerts"] or 0,
                "total_connections": record["total_connections"] or 0,
                "attack_types": record["attack_types"] or [],
                "avg_severity": float(record["avg_severity"] or 0),
                "attack_count": record["attack_count"] or 0,
                "last_attack": str(record["last_attack"]) if record["last_attack"] else None,
                "first_seen": str(ip_data.get("first_seen", "Unknown")),
                "last_seen": str(ip_data.get("last_seen", "Unknown")),
                "reputation_level": "HIGH_THREAT" if record["threat_score"] and record["threat_score"] > 7 
                                 else "MEDIUM_THREAT" if record["threat_score"] and record["threat_score"] > 4
                                 else "LOW_THREAT" if record["threat_score"] and record["threat_score"] > 0
                                 else "UNKNOWN"
            }
            
            return {
                "status": "success",
                "data": reputation_data,
                "timestamp": datetime.now().isoformat()
            }
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"IP reputation lookup failed: {str(e)}")

@router.get("/threat-summary")
async def get_threat_summary(
    hours_back: int = Query(24, description="Summary period in hours", ge=1, le=168)
):
    """
    Get comprehensive threat intelligence summary
    
    - **hours_back**: Summary period in hours (1-168 hours)
    - Returns overview of all threat activities and key metrics
    """
    try:
        from neo4j_client import driver
        
        if not driver:
            raise HTTPException(status_code=500, detail="Database connection not available")
        
        # Get threat summary statistics
        query = """
        MATCH (alert:SecurityAlert)
        WHERE alert.timestamp >= datetime() - duration({hours: $hours_back})
        WITH count(alert) as total_alerts,
             count(DISTINCT alert.source_ip) as unique_attackers,
             count(DISTINCT alert.destination_ip) as unique_targets,
             avg(alert.severity_score) as avg_severity,
             collect(alert.attack_type) as all_attacks,
             collect(alert.threat_level) as all_threat_levels
        
        UNWIND all_attacks as attack_type
        WITH total_alerts, unique_attackers, unique_targets, avg_severity, all_threat_levels,
             attack_type, count(attack_type) as attack_count
        
        WITH total_alerts, unique_attackers, unique_targets, avg_severity, all_threat_levels,
             collect({attack_type: attack_type, count: attack_count}) as attack_distribution
        
        UNWIND all_threat_levels as threat_level  
        WITH total_alerts, unique_attackers, unique_targets, avg_severity, attack_distribution,
             threat_level, count(threat_level) as threat_count
             
        RETURN total_alerts, unique_attackers, unique_targets, avg_severity,
               attack_distribution[0..5] as top_attacks,
               collect({threat_level: threat_level, count: threat_count}) as threat_distribution
        """
        
        with driver.session() as session:
            result = session.run(query, {"hours_back": hours_back})
            record = result.single()
            
            if not record:
                summary_data = {
                    "total_alerts": 0,
                    "unique_attackers": 0, 
                    "unique_targets": 0,
                    "avg_severity": 0.0,
                    "top_attacks": [],
                    "threat_distribution": []
                }
            else:
                summary_data = {
                    "total_alerts": record["total_alerts"] or 0,
                    "unique_attackers": record["unique_attackers"] or 0,
                    "unique_targets": record["unique_targets"] or 0, 
                    "avg_severity": float(record["avg_severity"] or 0),
                    "top_attacks": record["top_attacks"] or [],
                    "threat_distribution": record["threat_distribution"] or []
                }
        
        # Get top malicious IPs
        malicious_ips_query = """
        MATCH (ip:IPAddress)
        WHERE ip.is_malicious = true
        RETURN ip.address as ip_address,
               ip.threat_score as threat_score,
               ip.attack_count as attack_count
        ORDER BY ip.threat_score DESC, ip.attack_count DESC
        LIMIT 10
        """
        
        with driver.session() as session:
            result = session.run(malicious_ips_query)
            top_malicious_ips = [
                {
                    "ip_address": record["ip_address"],
                    "threat_score": record["threat_score"] or 0,
                    "attack_count": record["attack_count"] or 0
                }
                for record in result
            ]
        
        return {
            "status": "success",
            "data": {
                "summary_period_hours": hours_back,
                "threat_statistics": summary_data,
                "top_malicious_ips": top_malicious_ips,
                "threat_level": "CRITICAL" if summary_data["avg_severity"] > 8
                              else "HIGH" if summary_data["avg_severity"] > 6  
                              else "MEDIUM" if summary_data["avg_severity"] > 3
                              else "LOW"
            },
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Threat summary failed: {str(e)}")

@router.get("/network-stats")
async def get_network_statistics(
    hours_back: int = Query(24, description="Statistics period in hours", ge=1, le=168)  
):
    """
    Get network traffic and security statistics
    
    - **hours_back**: Statistics period in hours (1-168 hours)
    - Returns network traffic patterns and security event statistics
    """
    try:
        from neo4j_client import driver
        
        if not driver:
            raise HTTPException(status_code=500, detail="Database connection not available")
        
        # Network traffic statistics
        traffic_query = """
        MATCH (log:NetworkLog)
        WHERE log.timestamp >= datetime() - duration({hours: $hours_back})
        RETURN count(log) as total_connections,
               sum(log.bytes_sent + log.bytes_received) as total_bytes,
               avg(log.bytes_sent + log.bytes_received) as avg_bytes_per_connection,
               count(DISTINCT log.source_ip) as unique_sources,
               count(DISTINCT log.destination_ip) as unique_destinations,
               collect(DISTINCT log.protocol)[0..10] as protocols_used
        """
        
        # Security event statistics  
        security_query = """
        MATCH (alert:SecurityAlert)
        WHERE alert.timestamp >= datetime() - duration({hours: $hours_back})
        RETURN count(alert) as total_security_events,
               avg(alert.severity_score) as avg_severity,
               collect(DISTINCT alert.action)[0..5] as security_actions,
               count(DISTINCT alert.source_ip) as attacking_ips,
               count(DISTINCT alert.destination_ip) as targeted_ips
        """
        
        # Firewall statistics
        firewall_query = """
        MATCH (fw:FirewallLog)
        WHERE fw.timestamp >= datetime() - duration({hours: $hours_back})
        RETURN count(fw) as total_firewall_events,
               collect(DISTINCT fw.action)[0..5] as firewall_actions,
               sum(CASE WHEN fw.action = 'ALLOW' THEN 1 ELSE 0 END) as allowed_connections,
               sum(CASE WHEN fw.action IN ['DENY', 'DROP', 'REJECT'] THEN 1 ELSE 0 END) as blocked_connections
        """
        
        with driver.session() as session:
            # Execute all queries
            traffic_result = session.run(traffic_query, {"hours_back": hours_back}).single()
            security_result = session.run(security_query, {"hours_back": hours_back}).single()
            firewall_result = session.run(firewall_query, {"hours_back": hours_back}).single()
            
            statistics = {
                "analysis_period_hours": hours_back,
                "network_traffic": {
                    "total_connections": traffic_result["total_connections"] or 0,
                    "total_bytes_transferred": traffic_result["total_bytes"] or 0,
                    "avg_bytes_per_connection": float(traffic_result["avg_bytes_per_connection"] or 0),
                    "unique_source_ips": traffic_result["unique_sources"] or 0,
                    "unique_destination_ips": traffic_result["unique_destinations"] or 0,
                    "protocols_observed": traffic_result["protocols_used"] or []
                },
                "security_events": {
                    "total_security_alerts": security_result["total_security_events"] or 0,
                    "avg_severity_score": float(security_result["avg_severity"] or 0),
                    "security_actions": security_result["security_actions"] or [],
                    "attacking_ip_count": security_result["attacking_ips"] or 0,
                    "targeted_ip_count": security_result["targeted_ips"] or 0
                },
                "firewall_activity": {
                    "total_firewall_events": firewall_result["total_firewall_events"] or 0,
                    "firewall_actions": firewall_result["firewall_actions"] or [],
                    "allowed_connections": firewall_result["allowed_connections"] or 0,
                    "blocked_connections": firewall_result["blocked_connections"] or 0,
                    "block_rate": float(firewall_result["blocked_connections"] or 0) / max(firewall_result["total_firewall_events"] or 1, 1) * 100
                }
            }
        
        return {
            "status": "success",
            "data": statistics,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Network statistics failed: {str(e)}")

@router.get("/health", response_model=ThreatHealthResponse)
async def threat_intelligence_health():
    """
    Check threat intelligence service health and dependencies
    
    - Returns health status of threat analysis components
    """
    try:
        # Test threat analyzer
        analyzer = get_threat_analyzer()
        
        # Test Neo4j connection
        from neo4j_client import driver
        neo4j_status = "disconnected"
        if driver:
            with driver.session() as session:
                result = session.run("RETURN 1 as test")
                if result.single():
                    neo4j_status = "connected"
        
        # Test Groq AI connection
        groq_status = "unknown"
        try:
            from groq_client import get_groq_llm
            llm = get_groq_llm()
            groq_status = "connected" if llm else "disconnected"
        except Exception:
            groq_status = "error"
        
        services = {
            "threat_analyzer": "operational",
            "neo4j_database": neo4j_status,
            "groq_ai": groq_status,
            "attack_detection": "active",
            "apt_analysis": "active", 
            "malware_detection": "active"
        }
        
        overall_status = "healthy" if all(
            status in ["operational", "connected", "active"] 
            for status in services.values()
        ) else "degraded"
        
        return ThreatHealthResponse(
            status=overall_status,
            message="Threat Intelligence service status",
            services=services,
            timestamp=datetime.now().isoformat()
        )
        
    except Exception as e:
        return ThreatHealthResponse(
            status="error",
            message=f"Health check failed: {str(e)}",
            services={"error": str(e)},
            timestamp=datetime.now().isoformat()
        )

# Additional utility endpoints
@router.get("/attack-timeline")
async def get_attack_timeline(
    hours_back: int = Query(12, description="Timeline period in hours", ge=1, le=72),
    limit: int = Query(100, description="Maximum events to return", ge=10, le=1000)
):
    """
    Get chronological attack timeline with detailed events
    
    - **hours_back**: Timeline period in hours (1-72 hours)
    - **limit**: Maximum number of events to return (10-1000)
    - Returns chronological list of security events
    """
    try:
        from neo4j_client import driver
        
        if not driver:
            raise HTTPException(status_code=500, detail="Database connection not available")
        
        query = """
        MATCH (alert:SecurityAlert)
        WHERE alert.timestamp >= datetime() - duration({hours: $hours_back})
        RETURN alert.timestamp as timestamp,
               alert.attack_type as attack_type,
               alert.source_ip as source_ip,
               alert.destination_ip as destination_ip,
               alert.threat_level as threat_level,
               alert.severity_score as severity_score,
               alert.action as action
        ORDER BY alert.timestamp DESC
        LIMIT $limit
        """
        
        with driver.session() as session:
            result = session.run(query, {"hours_back": hours_back, "limit": limit})
            
            timeline_events = []
            for record in result:
                timeline_events.append({
                    "timestamp": str(record["timestamp"]),
                    "attack_type": record["attack_type"],
                    "source_ip": record["source_ip"], 
                    "destination_ip": record["destination_ip"],
                    "threat_level": record["threat_level"],
                    "severity_score": record["severity_score"],
                    "action": record["action"]
                })
        
        return {
            "status": "success",
            "data": {
                "timeline_period_hours": hours_back,
                "total_events": len(timeline_events),
                "events": timeline_events
            },
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Attack timeline failed: {str(e)}")