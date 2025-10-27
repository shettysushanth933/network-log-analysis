from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from datetime import datetime
import uvicorn
import threading
import time
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import route modules
from threat_routes import router as threat_router

# Import clients and services
from neo4j_client import driver, neo4j_client
from kafka_consumer import start_consumer_thread

app = FastAPI(
    title="🔥 Network Log Analysis - AI-Powered Threat Intelligence",
    description="""
    **Advanced Network Security Analysis Platform**
    
    A comprehensive AI-powered network log analysis system that provides:
    
    ## 🔍 **Threat Intelligence Features**
    - **Attack Pattern Recognition**: Identifies coordinated multi-IP attacks
    - **APT Detection**: Advanced Persistent Threat analysis 
    - **Malware Behavior Analysis**: C&C communication detection
    - **Zero-day Indicators**: Novel attack technique identification
    - **IP Reputation Intelligence**: Comprehensive threat scoring
    
    ## 🤖 **AI-Powered Analytics**
    - **Groq AI Integration**: High-performance threat analysis
    - **Real-time Pattern Recognition**: Automated threat correlation
    - **Behavioral Analysis**: Advanced malware detection
    - **Predictive Intelligence**: Proactive threat identification
    
    ## 🛡️ **Security Capabilities**
    - **Real-time Log Processing**: Apache Kafka streaming
    - **Graph Database**: Neo4j for complex relationship analysis
    - **Network Behavior Analytics**: Baseline establishment and anomaly detection
    - **Automated Response**: Intelligent mitigation recommendations
    
    Built with FastAPI, Neo4j, Apache Kafka, and Groq AI.
    """,
    version="2.0.0",
    contact={
        "name": "Network Security Team",
        "url": "https://github.com/yourusername/network-log-analysis",
        "email": "security@yourcompany.com"
    },
    license_info={
        "name": "MIT License",
        "url": "https://opensource.org/licenses/MIT"
    }
)

# CORS middleware for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables for service management
consumer_thread = None
services_status = {
    "kafka_consumer": False,
    "neo4j_database": False,
    "groq_ai": False,
    "threat_analyzer": False
}

# Include routers
app.include_router(threat_router)

@app.on_event("startup")
async def startup_event():
    """Initialize services on application startup"""
    global consumer_thread, services_status
    
    print("🚀 Starting Network Log Analysis API...")
    print("=" * 60)
    
    # Check Neo4j connection
    if driver:
        services_status["neo4j_database"] = True
        print("✅ Neo4j database: Connected")
    else:
        print("❌ Neo4j database: Disconnected")
    
    # Check Groq AI
    try:
        from groq_client import get_groq_llm
        llm = get_groq_llm()
        if llm:
            services_status["groq_ai"] = True
            print("✅ Groq AI: Connected")
        else:
            print("❌ Groq AI: Not available")
    except Exception as e:
        print(f"❌ Groq AI: Error - {e}")
    
    # Check Threat Analyzer
    try:
        from threat_analyzer import get_threat_analyzer
        analyzer = get_threat_analyzer()
        services_status["threat_analyzer"] = True
        print("✅ Threat Analyzer: Initialized")
    except Exception as e:
        print(f"❌ Threat Analyzer: Error - {e}")
    
    # Start Kafka Consumer
    try:
        print("🔄 Starting Kafka consumer...")
        consumer_thread = start_consumer_thread()
        services_status["kafka_consumer"] = True
        print("✅ Kafka Consumer: Started")
    except Exception as e:
        print(f"❌ Kafka Consumer: Failed - {e}")
    
    print("=" * 60)
    print("🎯 Network Log Analysis API Ready!")
    print(f"📡 API Base URL: {os.getenv('API_BASE_URL', 'http://localhost:8000')}")
    print(f"📚 API Documentation: {os.getenv('API_BASE_URL', 'http://localhost:8000')}/docs")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on application shutdown"""
    print("\n🛑 Shutting down Network Log Analysis API...")
    
    # Close Neo4j connection
    if neo4j_client:
        neo4j_client.close()
    
    print("✅ Cleanup completed")

@app.get("/")
async def root():
    """API root endpoint with service information"""
    return {
        "message": "🔥 Network Log Analysis - AI-Powered Threat Intelligence API",
        "version": "2.0.0",
        "status": "operational",
        "services": {
            "threat_intelligence": "🔍 Advanced threat detection and analysis",
            "attack_patterns": "🎯 Coordinated attack recognition",
            "apt_detection": "🕵️ Advanced Persistent Threat analysis", 
            "malware_analysis": "🦠 Command & Control behavior detection",
            "zero_day_detection": "⚡ Novel attack technique identification",
            "ip_reputation": "🛡️ Comprehensive threat intelligence"
        },
        "endpoints": {
            "threat_intelligence": "/threat-intelligence/*",
            "api_docs": "/docs",
            "health_check": "/health",
            "system_status": "/status"
        },
        "powered_by": ["FastAPI", "Neo4j", "Apache Kafka", "Groq AI"],
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
async def health_check():
    """Comprehensive health check endpoint"""
    health_status = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0",
        "services": {}
    }
    
    overall_health = True
    
    # Check Neo4j
    try:
        if driver:
            with driver.session() as session:
                result = session.run("RETURN 1 as health_check")
                if result.single():
                    health_status["services"]["neo4j"] = {
                        "status": "healthy",
                        "message": "Database connection active"
                    }
                else:
                    raise Exception("Query failed")
        else:
            raise Exception("Driver not available")
    except Exception as e:
        health_status["services"]["neo4j"] = {
            "status": "unhealthy", 
            "message": f"Database error: {str(e)}"
        }
        overall_health = False
    
    # Check Groq AI
    try:
        from groq_client import get_groq_llm
        llm = get_groq_llm()
        if llm:
            health_status["services"]["groq_ai"] = {
                "status": "healthy",
                "message": "AI service operational"
            }
        else:
            raise Exception("LLM not available")
    except Exception as e:
        health_status["services"]["groq_ai"] = {
            "status": "unhealthy",
            "message": f"AI service error: {str(e)}"
        }
        overall_health = False
    
    # Check Threat Analyzer
    try:
        from threat_analyzer import get_threat_analyzer
        analyzer = get_threat_analyzer()
        health_status["services"]["threat_analyzer"] = {
            "status": "healthy",
            "message": "Threat analysis ready"
        }
    except Exception as e:
        health_status["services"]["threat_analyzer"] = {
            "status": "unhealthy",
            "message": f"Threat analyzer error: {str(e)}"
        }
        overall_health = False
    
    # Check Kafka Consumer
    health_status["services"]["kafka_consumer"] = {
        "status": "healthy" if services_status["kafka_consumer"] else "unhealthy",
        "message": "Log processing active" if services_status["kafka_consumer"] else "Consumer not running"
    }
    
    if not services_status["kafka_consumer"]:
        overall_health = False
    
    # Overall status
    health_status["status"] = "healthy" if overall_health else "degraded"
    
    return health_status

@app.get("/status")
async def system_status():
    """Detailed system status and statistics"""
    try:
        status_data = {
            "system": {
                "status": "operational",
                "uptime": "Available via system metrics",
                "version": "2.0.0",
                "environment": os.getenv("ENVIRONMENT", "development")
            },
            "services": services_status.copy(),
            "database": {
                "type": "Neo4j Graph Database",
                "uri": os.getenv("NEO4J_URI", "bolt://localhost:7687"),
                "status": "connected" if driver else "disconnected"
            },
            "messaging": {
                "type": "Apache Kafka",
                "brokers": os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
                "topic": "network-logs",
                "consumer_status": "running" if services_status["kafka_consumer"] else "stopped"
            },
            "ai_engine": {
                "provider": "Groq AI",
                "model": "Available via Groq API",
                "status": "connected" if services_status["groq_ai"] else "disconnected"
            },
            "timestamp": datetime.now().isoformat()
        }
        
        # Get database statistics if available
        if driver:
            try:
                with driver.session() as session:
                    # Count nodes
                    node_counts = {}
                    for node_type in ["IPAddress", "SecurityAlert", "NetworkLog", "FirewallLog"]:
                        result = session.run(f"MATCH (n:{node_type}) RETURN count(n) as count")
                        record = result.single()
                        node_counts[node_type.lower()] = record["count"] if record else 0
                    
                    status_data["database"]["statistics"] = {
                        "ip_addresses": node_counts.get("ipaddress", 0),
                        "security_alerts": node_counts.get("securityalert", 0), 
                        "network_logs": node_counts.get("networklog", 0),
                        "firewall_logs": node_counts.get("firewalllog", 0)
                    }
                    
            except Exception as e:
                status_data["database"]["statistics"] = f"Error retrieving stats: {str(e)}"
        
        return status_data
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Status check failed: {str(e)}")

@app.get("/metrics")
async def get_metrics():
    """Get system metrics and performance data"""
    try:
        metrics = {
            "system_metrics": {
                "api_version": "2.0.0",
                "python_version": f"{os.sys.version_info.major}.{os.sys.version_info.minor}",
                "platform": os.name
            },
            "service_health": {
                "total_services": 4,
                "healthy_services": sum(services_status.values()),
                "service_availability": (sum(services_status.values()) / 4) * 100
            },
            "timestamp": datetime.now().isoformat()
        }
        
        # Add database metrics if available
        if driver:
            try:
                with driver.session() as session:
                    # Recent activity metrics
                    recent_alerts = session.run("""
                        MATCH (alert:SecurityAlert)
                        WHERE alert.timestamp >= datetime() - duration({hours: 1})
                        RETURN count(alert) as recent_alerts
                    """).single()
                    
                    metrics["activity_metrics"] = {
                        "alerts_last_hour": recent_alerts["recent_alerts"] if recent_alerts else 0,
                        "database_responsive": True
                    }
            except Exception as e:
                metrics["activity_metrics"] = {
                    "database_error": str(e),
                    "database_responsive": False
                }
        
        return metrics
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Metrics collection failed: {str(e)}")

# Network Log Analysis specific endpoints
@app.get("/network-overview")
async def network_overview():
    """Get high-level network security overview"""
    try:
        if not driver:
            raise HTTPException(status_code=503, detail="Database not available")
        
        with driver.session() as session:
            # Get recent threat summary
            threat_summary = session.run("""
                MATCH (alert:SecurityAlert)
                WHERE alert.timestamp >= datetime() - duration({hours: 24})
                RETURN count(alert) as total_threats,
                       count(DISTINCT alert.source_ip) as unique_attackers,
                       avg(alert.severity_score) as avg_severity,
                       collect(DISTINCT alert.threat_level) as threat_levels
            """).single()
            
            # Get network activity summary  
            network_summary = session.run("""
                MATCH (log:NetworkLog)
                WHERE log.timestamp >= datetime() - duration({hours: 24})
                RETURN count(log) as total_connections,
                       sum(log.bytes_sent + log.bytes_received) as total_bytes,
                       count(DISTINCT log.source_ip) as unique_sources
            """).single()
            
            overview = {
                "security_overview": {
                    "threat_alerts_24h": threat_summary["total_threats"] or 0,
                    "unique_attackers_24h": threat_summary["unique_attackers"] or 0,
                    "avg_threat_severity": float(threat_summary["avg_severity"] or 0),
                    "threat_levels_observed": threat_summary["threat_levels"] or [],
                    "security_status": "HIGH_RISK" if (threat_summary["avg_severity"] or 0) > 7
                                    else "MEDIUM_RISK" if (threat_summary["avg_severity"] or 0) > 4
                                    else "LOW_RISK"
                },
                "network_overview": {
                    "total_connections_24h": network_summary["total_connections"] or 0,
                    "total_bytes_transferred": network_summary["total_bytes"] or 0,
                    "unique_sources_24h": network_summary["unique_sources"] or 0,
                    "network_activity": "HIGH" if (network_summary["total_connections"] or 0) > 10000
                                      else "MEDIUM" if (network_summary["total_connections"] or 0) > 1000
                                      else "LOW"
                },
                "recommendations": [
                    "Monitor high-severity threats closely",
                    "Review IP reputation for repeat attackers", 
                    "Check firewall rules for optimization",
                    "Analyze attack patterns for coordination"
                ],
                "timestamp": datetime.now().isoformat()
            }
            
        return overview
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Network overview failed: {str(e)}")

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler"""
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": str(exc),
            "timestamp": datetime.now().isoformat(),
            "path": str(request.url)
        }
    )

if __name__ == "__main__":
    # Configuration
    HOST = os.getenv("API_HOST", "0.0.0.0")
    PORT = int(os.getenv("API_PORT", "8000"))
    DEBUG = os.getenv("DEBUG", "true").lower() == "true"
    
    print("🔥 Network Log Analysis - AI-Powered Threat Intelligence")
    print("=" * 70)
    print(f"🚀 Starting server on {HOST}:{PORT}")
    print(f"📚 API Documentation: http://{HOST}:{PORT}/docs")
    print(f"🔍 Threat Intelligence: http://{HOST}:{PORT}/threat-intelligence/")
    print("=" * 70)
    
    uvicorn.run(
        "main:app",
        host=HOST,
        port=PORT,
        reload=DEBUG,
        log_level="info"
    )