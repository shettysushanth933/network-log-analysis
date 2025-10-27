import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import requests
import json
from datetime import datetime, timedelta
import time
from typing import Dict, Any, List
import numpy as np

# Configuration
API_BASE_URL = "http://localhost:8000"
REFRESH_INTERVAL = 30  # seconds

# Page configuration
st.set_page_config(
    page_title="🔥 Network Log Analysis - AI Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for styling
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        text-align: center;
        margin-bottom: 2rem;
        background: linear-gradient(90deg, #FF6B6B, #4ECDC4, #45B7D1);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
    }
    
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        margin: 0.5rem 0;
    }
    
    .threat-high {
        background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
    }
    
    .threat-medium {
        background: linear-gradient(135deg, #feca57 0%, #ff9ff3 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
    }
    
    .threat-low {
        background: linear-gradient(135deg, #48dbfb 0%, #0abde3 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
    }
    
    .alert-box {
        padding: 1rem;
        border-radius: 10px;
        margin: 1rem 0;
        border-left: 5px solid;
    }
    
    .alert-critical {
        background-color: #ffe6e6;
        border-color: #ff4757;
        color: #2c2c54;
    }
    
    .alert-high {
        background-color: #fff3e0;
        border-color: #ffa726;
        color: #2c2c54;
    }
    
    .alert-medium {
        background-color: #fff8e1;
        border-color: #ffcc02;
        color: #2c2c54;
    }
    
    .stButton > button {
        width: 100%;
        border-radius: 20px;
        border: none;
        padding: 0.5rem;
        font-weight: bold;
        transition: all 0.3s;
    }
</style>
""", unsafe_allow_html=True)

class NetworkLogAnalyzer:
    def __init__(self):
        self.api_base = API_BASE_URL
    
    def make_request(self, endpoint: str, params: Dict = None) -> Dict[str, Any]:
        """Make API request with error handling"""
        try:
            url = f"{self.api_base}{endpoint}"
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            st.error(f"API request failed: {str(e)}")
            return {"error": str(e)}
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get API health status"""
        return self.make_request("/health")
    
    def get_threat_summary(self, hours_back: int = 24) -> Dict[str, Any]:
        """Get threat intelligence summary"""
        return self.make_request("/threat-intelligence/threat-summary", {"hours_back": hours_back})
    
    def get_attack_patterns(self, time_window: int = 24) -> Dict[str, Any]:
        """Get attack pattern analysis"""
        return self.make_request("/threat-intelligence/attack-patterns", {"time_window": time_window})
    
    def get_apt_detection(self, days_back: int = 30) -> Dict[str, Any]:
        """Get APT detection analysis"""
        return self.make_request("/threat-intelligence/apt-detection", {"days_back": days_back})
    
    def get_malware_behavior(self, hours_back: int = 12) -> Dict[str, Any]:
        """Get malware behavior analysis"""
        return self.make_request("/threat-intelligence/malware-behavior", {"hours_back": hours_back})
    
    def get_zero_day_indicators(self, hours_back: int = 6) -> Dict[str, Any]:
        """Get zero-day indicators"""
        return self.make_request("/threat-intelligence/zero-day-indicators", {"hours_back": hours_back})
    
    def get_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """Get IP reputation"""
        return self.make_request(f"/threat-intelligence/ip-reputation/{ip_address}")
    
    def get_network_stats(self, hours_back: int = 24) -> Dict[str, Any]:
        """Get network statistics"""
        return self.make_request("/threat-intelligence/network-stats", {"hours_back": hours_back})
    
    def get_attack_timeline(self, hours_back: int = 12, limit: int = 100) -> Dict[str, Any]:
        """Get attack timeline"""
        return self.make_request("/threat-intelligence/attack-timeline", {
            "hours_back": hours_back,
            "limit": limit
        })

# Initialize analyzer
@st.cache_resource
def get_analyzer():
    return NetworkLogAnalyzer()

analyzer = get_analyzer()

# Sidebar
st.sidebar.title("🛡️ Network Security")
st.sidebar.markdown("---")

# Navigation
page = st.sidebar.selectbox(
    "📊 Select Analysis",
    [
        "🏠 Dashboard Overview",
        "🔍 Threat Intelligence", 
        "⚡ Real-time Monitoring",
        "🤖 AI Attack Analysis",
        "📊 Network Statistics",
        "🎯 IP Reputation Lookup",
        "🔬 Advanced Analytics"
    ]
)

# Auto-refresh toggle
auto_refresh = st.sidebar.checkbox("🔄 Auto Refresh (30s)", value=False)
if auto_refresh:
    time.sleep(REFRESH_INTERVAL)
    st.experimental_rerun()

# Manual refresh button
if st.sidebar.button("🔄 Refresh Now"):
    st.cache_data.clear()
    st.experimental_rerun()

st.sidebar.markdown("---")
st.sidebar.markdown("### 🔧 Settings")
time_window = st.sidebar.slider("⏰ Analysis Window (hours)", 1, 168, 24)

# Main content
st.markdown('<h1 class="main-header">🔥 Network Log Analysis Dashboard</h1>', unsafe_allow_html=True)

# Health check
with st.spinner("Checking system health..."):
    health_data = analyzer.get_health_status()

if "error" not in health_data:
    if health_data.get("status") == "healthy":
        st.success("🟢 All systems operational")
    else:
        st.warning("🟡 Some services degraded")
        for service, status in health_data.get("services", {}).items():
            if status.get("status") != "healthy":
                st.error(f"❌ {service}: {status.get('message', 'Unknown error')}")
else:
    st.error("🔴 API connection failed")

# Page content based on selection
if page == "🏠 Dashboard Overview":
    st.markdown("## 📊 Security Overview Dashboard")
    
    # Get threat summary
    with st.spinner("Loading threat intelligence..."):
        threat_data = analyzer.get_threat_summary(time_window)
    
    if "error" not in threat_data and "data" in threat_data:
        data = threat_data["data"]
        stats = data.get("threat_statistics", {})
        
        # Key metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown(f"""
            <div class="metric-card">
                <h3>🚨 Total Alerts</h3>
                <h2>{stats.get('total_alerts', 0):,}</h2>
                <p>Last {time_window} hours</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown(f"""
            <div class="metric-card">
                <h3>👤 Unique Attackers</h3>
                <h2>{stats.get('unique_attackers', 0):,}</h2>
                <p>Distinct threat sources</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown(f"""
            <div class="metric-card">
                <h3>🎯 Targets Hit</h3>
                <h2>{stats.get('unique_targets', 0):,}</h2>
                <p>Systems under attack</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col4:
            avg_severity = stats.get('avg_severity', 0)
            severity_color = "threat-high" if avg_severity > 7 else "threat-medium" if avg_severity > 4 else "threat-low"
            st.markdown(f"""
            <div class="{severity_color}">
                <h3>⚡ Avg Severity</h3>
                <h2>{avg_severity:.1f}/10</h2>
                <p>Threat intensity</p>
            </div>
            """, unsafe_allow_html=True)
        
        # Threat level distribution
        if stats.get('threat_distribution'):
            st.markdown("### 📊 Threat Level Distribution")
            threat_df = pd.DataFrame(stats['threat_distribution'])
            
            fig = px.pie(
                threat_df, 
                values='count', 
                names='threat_level',
                title="Threats by Severity Level",
                color_discrete_map={
                    'CRITICAL': '#ff4757',
                    'HIGH': '#ffa726', 
                    'MEDIUM': '#ffcc02',
                    'LOW': '#2ed573'
                }
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Top attack types
        if stats.get('top_attacks'):
            st.markdown("### 🎯 Top Attack Types")
            attacks_df = pd.DataFrame(stats['top_attacks'])
            
            fig = px.bar(
                attacks_df,
                x='count',
                y='attack_type',
                orientation='h',
                title="Most Frequent Attack Types",
                color='count',
                color_continuous_scale='Reds'
            )
            fig.update_layout(yaxis={'categoryorder': 'total ascending'})
            st.plotly_chart(fig, use_container_width=True)
        
        # Top malicious IPs
        malicious_ips = data.get('top_malicious_ips', [])
        if malicious_ips:
            st.markdown("### 🚫 Top Malicious IP Addresses")
            
            ips_df = pd.DataFrame(malicious_ips)
            
            # Display as interactive table
            st.dataframe(
                ips_df,
                column_config={
                    "ip_address": "IP Address",
                    "threat_score": st.column_config.ProgressColumn(
                        "Threat Score",
                        help="Threat score (0-10)",
                        min_value=0,
                        max_value=10,
                    ),
                    "attack_count": "Attack Count"
                },
                hide_index=True,
                use_container_width=True
            )

elif page == "🔍 Threat Intelligence":
    st.markdown("## 🔍 AI-Powered Threat Intelligence")
    
    # Analysis type selection
    analysis_type = st.selectbox(
        "Select Analysis Type",
        [
            "🎯 Attack Pattern Recognition",
            "🕵️ APT Detection", 
            "🦠 Malware Behavior Analysis",
            "⚡ Zero-Day Indicators"
        ]
    )
    
    if analysis_type == "🎯 Attack Pattern Recognition":
        st.markdown("### 🎯 Coordinated Attack Pattern Analysis")
        
        if st.button("🔄 Analyze Attack Patterns"):
            with st.spinner("Analyzing attack patterns..."):
                attack_data = analyzer.get_attack_patterns(time_window)
            
            if "error" not in attack_data and "data" in attack_data:
                data = attack_data["data"]
                
                # Risk score display
                risk_score = data.get("risk_score", 0)
                if risk_score > 70:
                    st.markdown(f"""
                    <div class="alert-critical">
                        <h3>🚨 CRITICAL RISK DETECTED</h3>
                        <p><strong>Risk Score: {risk_score}/100</strong></p>
                        <p>Multiple coordinated attacks detected. Immediate action required.</p>
                    </div>
                    """, unsafe_allow_html=True)
                elif risk_score > 40:
                    st.markdown(f"""
                    <div class="alert-high">
                        <h3>⚠️ HIGH RISK</h3>
                        <p><strong>Risk Score: {risk_score}/100</strong></p>
                        <p>Significant attack activity detected.</p>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                    <div class="alert-medium">
                        <h3>ℹ️ MODERATE RISK</h3>
                        <p><strong>Risk Score: {risk_score}/100</strong></p>
                        <p>Normal security posture.</p>
                    </div>
                    """, unsafe_allow_html=True)
                
                # Coordinated attacks
                coordinated = data.get("coordinated_attacks", {})
                if coordinated.get("attacks"):
                    st.markdown("#### 🎯 Coordinated Attack Sources")
                    attacks_df = pd.DataFrame(coordinated["attacks"])
                    
                    fig = px.scatter(
                        attacks_df,
                        x="attack_count",
                        y="avg_severity", 
                        size="attack_count",
                        color="attack_type",
                        hover_data=["source_ip", "targets"],
                        title="Attack Coordination Analysis"
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                # AI Analysis
                ai_analysis = data.get("ai_analysis")
                if ai_analysis:
                    st.markdown("### 🤖 AI Threat Analysis")
                    st.markdown(f"```\n{ai_analysis}\n```")

    elif analysis_type == "🕵️ APT Detection":
        st.markdown("### 🕵️ Advanced Persistent Threat Detection")
        
        days_back = st.slider("Analysis Period (days)", 7, 90, 30)
        
        if st.button("🔍 Detect APT Activity"):
            with st.spinner("Analyzing for APT indicators..."):
                apt_data = analyzer.get_apt_detection(days_back)
            
            if "error" not in apt_data and "data" in apt_data:
                data = apt_data["data"]
                
                # APT probability
                apt_prob = data.get("apt_probability", 0)
                
                col1, col2 = st.columns(2)
                with col1:
                    fig = go.Figure(go.Indicator(
                        mode="gauge+number+delta",
                        value=apt_prob,
                        domain={'x': [0, 1], 'y': [0, 1]},
                        title={'text': "APT Probability %"},
                        gauge={
                            'axis': {'range': [None, 100]},
                            'bar': {'color': "darkblue"},
                            'steps': [
                                {'range': [0, 25], 'color': "lightgray"},
                                {'range': [25, 50], 'color': "yellow"},
                                {'range': [50, 75], 'color': "orange"},
                                {'range': [75, 100], 'color': "red"}
                            ],
                            'threshold': {
                                'line': {'color': "red", 'width': 4},
                                'thickness': 0.75,
                                'value': 75
                            }
                        }
                    ))
                    st.plotly_chart(fig, use_container_width=True)
                
                with col2:
                    # Long-term patterns
                    patterns = data.get("long_term_patterns", {})
                    if patterns.get("patterns"):
                        st.markdown("#### 📊 Persistent Attackers")
                        patterns_df = pd.DataFrame(patterns["patterns"])
                        
                        fig = px.scatter(
                            patterns_df,
                            x="active_days",
                            y="stealth_score",
                            size="persistence_score",
                            color="avg_daily_attacks",
                            hover_data=["attacker_ip"],
                            title="APT Behavior Analysis"
                        )
                        st.plotly_chart(fig, use_container_width=True)
                
                # AI Analysis
                ai_analysis = data.get("ai_analysis")
                if ai_analysis:
                    st.markdown("### 🤖 APT Intelligence Analysis")
                    st.markdown(f"```\n{ai_analysis}\n```")

    elif analysis_type == "🦠 Malware Behavior Analysis":
        st.markdown("### 🦠 Malware C&C Behavior Analysis")
        
        if st.button("🔍 Analyze Malware Behavior"):
            with st.spinner("Analyzing malware indicators..."):
                malware_data = analyzer.get_malware_behavior(12)
            
            if "error" not in malware_data and "data" in malware_data:
                data = malware_data["data"]
                
                # Malware confidence
                confidence = data.get("malware_confidence", 0)
                
                st.metric(
                    "🦠 Malware Detection Confidence",
                    f"{confidence:.1f}%",
                    delta=f"{'High' if confidence > 70 else 'Medium' if confidence > 40 else 'Low'} confidence"
                )
                
                # C&C patterns
                cc_patterns = data.get("cc_patterns", {})
                if cc_patterns.get("cc_patterns"):
                    st.markdown("#### 📡 Potential C&C Servers")
                    cc_df = pd.DataFrame(cc_patterns["cc_patterns"])
                    
                    fig = px.bar(
                        cc_df,
                        x="external_ip",
                        y="cc_likelihood_score",
                        color="regularity_score",
                        title="Command & Control Analysis",
                        hover_data=["connection_count", "ports_used"]
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                # Beaconing behavior
                indicators = data.get("malware_indicators", {})
                beaconing = indicators.get("beaconing", [])
                if beaconing:
                    st.markdown("#### 📶 Beaconing Behavior")
                    beacon_df = pd.DataFrame(beaconing)
                    
                    fig = px.scatter(
                        beacon_df,
                        x="beacon_count",
                        y="consistency_score",
                        size="avg_out_bytes",
                        color="external_ip",
                        title="Malware Beaconing Analysis"
                    )
                    st.plotly_chart(fig, use_container_width=True)

    elif analysis_type == "⚡ Zero-Day Indicators":
        st.markdown("### ⚡ Zero-Day Attack Indicators")
        
        if st.button("🔍 Detect Zero-Day Indicators"):
            with st.spinner("Scanning for zero-day indicators..."):
                zeroday_data = analyzer.get_zero_day_indicators(6)
            
            if "error" not in zeroday_data and "data" in zeroday_data:
                data = zeroday_data["data"]
                
                # Zero-day likelihood
                likelihood = data.get("zero_day_likelihood", 0)
                
                if likelihood > 70:
                    st.error(f"🚨 HIGH ZERO-DAY PROBABILITY: {likelihood:.1f}%")
                elif likelihood > 40:
                    st.warning(f"⚠️ MEDIUM ZERO-DAY PROBABILITY: {likelihood:.1f}%")
                else:
                    st.info(f"ℹ️ LOW ZERO-DAY PROBABILITY: {likelihood:.1f}%")
                
                # Unusual patterns
                unusual = data.get("unusual_patterns", [])
                if unusual:
                    st.markdown("#### 🔍 Unusual Attack Patterns")
                    unusual_df = pd.DataFrame(unusual)
                    st.dataframe(unusual_df, use_container_width=True)
                
                # Recommendations
                recommendations = data.get("recommendations", [])
                if recommendations:
                    st.markdown("#### 💡 Security Recommendations")
                    for rec in recommendations:
                        st.markdown(f"• {rec}")

elif page == "⚡ Real-time Monitoring":
    st.markdown("## ⚡ Real-time Security Monitoring")
    
    # Attack timeline
    with st.spinner("Loading attack timeline..."):
        timeline_data = analyzer.get_attack_timeline(12, 50)
    
    if "error" not in timeline_data and "data" in timeline_data:
        data = timeline_data["data"]
        events = data.get("events", [])
        
        if events:
            st.markdown(f"### 📊 Recent Security Events ({len(events)} events)")
            
            # Convert to DataFrame
            events_df = pd.DataFrame(events)
            events_df['timestamp'] = pd.to_datetime(events_df['timestamp'])
            
            # Timeline chart
            fig = px.scatter(
                events_df,
                x="timestamp",
                y="threat_level",
                color="attack_type",
                size="severity_score",
                hover_data=["source_ip", "destination_ip", "action"],
                title="Security Events Timeline"
            )
            st.plotly_chart(fig, use_container_width=True)
            
            # Events table
            st.markdown("#### 📝 Event Details")
            display_df = events_df[['timestamp', 'attack_type', 'source_ip', 'destination_ip', 'threat_level', 'severity_score']].copy()
            display_df['timestamp'] = display_df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
            
            st.dataframe(
                display_df,
                column_config={
                    "severity_score": st.column_config.ProgressColumn(
                        "Severity",
                        min_value=0,
                        max_value=10,
                    )
                },
                hide_index=True,
                use_container_width=True
            )

elif page == "📊 Network Statistics":
    st.markdown("## 📊 Network Traffic Statistics")
    
    with st.spinner("Loading network statistics..."):
        stats_data = analyzer.get_network_stats(time_window)
    
    if "error" not in stats_data and "data" in stats_data:
        data = stats_data["data"]
        
        # Network traffic metrics
        traffic = data.get("network_traffic", {})
        security = data.get("security_events", {})
        firewall = data.get("firewall_activity", {})
        
        # Traffic overview
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric(
                "🌐 Total Connections",
                f"{traffic.get('total_connections', 0):,}",
                delta=f"{traffic.get('unique_source_ips', 0)} unique sources"
            )
        
        with col2:
            total_bytes = traffic.get('total_bytes_transferred', 0)
            st.metric(
                "📊 Data Transferred", 
                f"{total_bytes / (1024**3):.2f} GB" if total_bytes > 0 else "0 GB",
                delta=f"{traffic.get('avg_bytes_per_connection', 0):.0f} bytes/conn avg"
            )
        
        with col3:
            block_rate = firewall.get('block_rate', 0)
            st.metric(
                "🛡️ Firewall Block Rate",
                f"{block_rate:.1f}%",
                delta=f"{firewall.get('blocked_connections', 0)} blocked"
            )
        
        # Protocol distribution
        protocols = traffic.get('protocols_observed', [])
        if protocols:
            st.markdown("#### 📡 Protocol Distribution")
            protocol_counts = pd.Series(protocols).value_counts()
            
            fig = px.pie(
                values=protocol_counts.values,
                names=protocol_counts.index,
                title="Network Protocols Usage"
            )
            st.plotly_chart(fig, use_container_width=True)

elif page == "🎯 IP Reputation Lookup":
    st.markdown("## 🎯 IP Address Reputation Lookup")
    
    # IP input
    ip_address = st.text_input("Enter IP Address", placeholder="e.g., 192.168.1.100")
    
    if st.button("🔍 Lookup IP Reputation") and ip_address:
        with st.spinner(f"Analyzing IP {ip_address}..."):
            ip_data = analyzer.get_ip_reputation(ip_address)
        
        if "error" not in ip_data and "data" in ip_data:
            data = ip_data["data"]
            
            # Reputation overview
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                threat_score = data.get("threat_score", 0)
                st.metric("🚨 Threat Score", f"{threat_score}/10")
            
            with col2:
                is_malicious = data.get("is_malicious", False)
                st.metric("🔴 Malicious", "YES" if is_malicious else "NO")
            
            with col3:
                attack_count = data.get("attack_count", 0)
                st.metric("⚔️ Attack Count", attack_count)
            
            with col4:
                reputation = data.get("reputation_level", "UNKNOWN")
                st.metric("📊 Reputation", reputation)
            
            # Detailed information
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("#### 📋 IP Details")
                st.write(f"**IP Address:** {data.get('ip_address')}")
                st.write(f"**Internal IP:** {'Yes' if data.get('is_internal') else 'No'}")
                st.write(f"**First Seen:** {data.get('first_seen', 'Unknown')}")
                st.write(f"**Last Seen:** {data.get('last_seen', 'Unknown')}")
                st.write(f"**Last Attack:** {data.get('last_attack', 'Never')}")
            
            with col2:
                st.markdown("#### 📊 Activity Statistics")
                st.write(f"**Total Alerts:** {data.get('total_alerts', 0)}")
                st.write(f"**Total Connections:** {data.get('total_connections', 0)}")
                st.write(f"**Average Severity:** {data.get('avg_severity', 0):.1f}/10")
                
                # Attack types
                attack_types = data.get('attack_types', [])
                if attack_types:
                    st.write(f"**Attack Types:** {', '.join(attack_types)}")

elif page == "🔬 Advanced Analytics":
    st.markdown("## 🔬 Advanced Security Analytics")
    
    # Multi-analysis dashboard
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🔄 Run Complete Analysis"):
            with st.spinner("Running comprehensive analysis..."):
                # Get all analysis types
                attack_patterns = analyzer.get_attack_patterns(24)
                apt_detection = analyzer.get_apt_detection(30)
                malware_analysis = analyzer.get_malware_behavior(12)
                zero_day = analyzer.get_zero_day_indicators(6)
                
                st.success("✅ Analysis completed!")
                
                # Summary metrics
                st.markdown("### 📊 Analysis Summary")
                
                metrics_data = []
                if "data" in attack_patterns:
                    metrics_data.append({
                        "Analysis": "Attack Patterns",
                        "Risk Score": attack_patterns["data"].get("risk_score", 0),
                        "Status": "🔴 Critical" if attack_patterns["data"].get("risk_score", 0) > 70 else "🟡 Medium"
                    })
                
                if "data" in apt_detection:
                    metrics_data.append({
                        "Analysis": "APT Detection", 
                        "Risk Score": apt_detection["data"].get("apt_probability", 0),
                        "Status": "🔴 Critical" if apt_detection["data"].get("apt_probability", 0) > 70 else "🟡 Medium"
                    })
                
                if "data" in malware_analysis:
                    metrics_data.append({
                        "Analysis": "Malware Behavior",
                        "Risk Score": malware_analysis["data"].get("malware_confidence", 0),
                        "Status": "🔴 Critical" if malware_analysis["data"].get("malware_confidence", 0) > 70 else "🟡 Medium"
                    })
                
                if "data" in zero_day:
                    metrics_data.append({
                        "Analysis": "Zero-Day Indicators",
                        "Risk Score": zero_day["data"].get("zero_day_likelihood", 0),
                        "Status": "🔴 Critical" if zero_day["data"].get("zero_day_likelihood", 0) > 70 else "🟡 Medium"
                    })
                
                if metrics_data:
                    metrics_df = pd.DataFrame(metrics_data)
                    
                    fig = px.bar(
                        metrics_df,
                        x="Analysis",
                        y="Risk Score", 
                        color="Risk Score",
                        title="Comprehensive Security Analysis Results",
                        color_continuous_scale="Reds"
                    )
                    st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("### 🎯 Quick Actions")
        
        if st.button("📊 Generate Security Report"):
            st.info("📄 Security report generation feature coming soon!")
        
        if st.button("🚨 Emergency Response"):
            st.warning("🚨 Emergency response protocols activated!")
        
        if st.button("🔧 System Optimization"):
            st.info("⚙️ System optimization recommendations loading...")

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #666; padding: 20px;'>
    <p>🔥 <strong>Network Log Analysis Dashboard</strong> | Powered by AI Threat Intelligence</p>
    <p>FastAPI • Neo4j • Apache Kafka • Groq AI • Streamlit</p>
    <p>⚡ Real-time Security Analytics & Threat Detection</p>
</div>
""", unsafe_allow_html=True)