import streamlit as st
import pandas as pd
import requests
import json
from datetime import datetime

# --- CONFIGURATION ---
st.set_page_config(page_title="Threat Intel Aggregator", page_icon="🛡️", layout="wide")

# --- UTILITY FUNCTIONS ---
def get_secret(key_name):
    """Safely get API key or return None"""
    if "api_keys" in st.secrets and key_name in st.secrets["api_keys"]:
        return st.secrets["api_keys"][key_name]
    return None

# --- API FUNCTIONS ---
@st.cache_data(ttl=3600)
def fetch_abuseipdb_blacklist(limit=20):
    api_key = get_secret("abuseipdb")
    if not api_key: return "MISSING_KEY"
    
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"limit": limit}
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return pd.DataFrame(response.json().get("data", []))
    except Exception as e:
        return str(e)

def check_virustotal(ip):
    api_key = get_secret("virustotal")
    if not api_key: return "MISSING_KEY"
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return "NOT_FOUND"
        else:
            return f"Error: {response.status_code}"
    except Exception as e:
        return str(e)

def check_alienvault(ip):
    api_key = get_secret("alienvault")
    headers = {"X-OTX-API-KEY": api_key} if api_key else {}
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        return None
    except:
        return None

# --- SIDEBAR ---
st.sidebar.title("🛡️ Intel Ops")
page = st.sidebar.radio("Navigation", ["Dashboard", "IOC Scanner", "Live Feeds"])
st.sidebar.markdown("---")

# --- PAGE: DASHBOARD ---
if page == "Dashboard":
    st.title("Threat Intelligence Command Center")
    st.markdown("### 📊 System Status")
    col1, col2, col3 = st.columns(3)
    col1.metric("Active Feeds", "3", "Connected")
    col2.metric("Scan Engine", "VirusTotal v3", "Online")
    col3.metric("Last Update", datetime.now().strftime("%H:%M"), "Live")
    st.info("👈 Select **'IOC Scanner'** to start an investigation.")

# --- PAGE: IOC SCANNER (THE BIG UPDATE) ---
elif page == "IOC Scanner":
    st.title("🔍 Deep IOC Analysis")
    target_ip = st.text_input("Enter IP Address to Analyze", "8.8.8.8")
    
    if st.button("Run Intelligence Analysis"):
        st.write("---")
        
        # 1. VIRUSTOTAL ANALYSIS
        vt_data = check_virustotal(target_ip)
        
        if vt_data == "MISSING_KEY":
            st.warning("⚠️ VirusTotal API Key missing.")
        elif isinstance(vt_data, dict):
            # Parse the JSON Data
            attrs = vt_data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            total_scans = sum(stats.values())
            
            # A. THE VERDICT BANNER
            if malicious_count > 0:
                st.error(f"🚨 **DANGER DETECTED** | This IP was flagged by {malicious_count} security vendors.")
            else:
                st.success("✅ **CLEAN** | No security vendors flagged this IP as malicious.")

            # B. VISUAL ANALYSIS (Columns)
            col1, col2 = st.columns([1, 2])
            
            with col1:
                st.subheader("Risk Score")
                # Calculate percentage
                risk_score = (malicious_count / total_scans) * 100 if total_scans > 0 else 0
                st.metric("Malicious Flags", f"{malicious_count}/{total_scans}")
                st.progress(min(risk_score / 100, 1.0))
                
                if risk_score > 0:
                    st.caption("🔴 High Risk")
                else:
                    st.caption("🟢 Low Risk")

            with col2:
                st.subheader("Vendor Consensus")
                # Create a simple dataframe for the bar chart
                chart_data = pd.DataFrame({
                    "Category": ["Malicious", "Suspicious", "Harmless", "Undetected"],
                    "Count": [
                        stats.get("malicious", 0),
                        stats.get("suspicious", 0),
                        stats.get("harmless", 0),
                        stats.get("undetected", 0)
                    ]
                })
                st.bar_chart(chart_data.set_index("Category"))

            # C. NETWORK CONTEXT (Whois)
            st.subheader("🌍 Network Context")
            c1, c2, c3 = st.columns(3)
            c1.info(f"**Owner:** {attrs.get('as_owner', 'Unknown')}")
            c2.info(f"**Country:** {attrs.get('country', 'Unknown')}")
            c3.info(f"**Network:** {attrs.get('network', 'Unknown')}")
            
        else:
            st.error(f"Error analyzing IP: {vt_data}")

        # 2. ALIENVAULT CONTEXT (If available)
        otx_data = check_alienvault(target_ip)
        if otx_data:
            with st.expander("See AlienVault OTX Details"):
                st.write(f"**Pulse Count:** {otx_data.get('pulse_info', {}).get('count', 0)}")
                st.write(f"**Reputation:** {otx_data.get('reputation', 0)}")

# --- PAGE: LIVE FEEDS ---
elif page == "Live Feeds":
    st.title("🚨 Global Threat Feed")
    df = fetch_abuseipdb_blacklist()
    if isinstance(df, pd.DataFrame) and not df.empty:
        st.dataframe(df, use_container_width=True)
    elif df == "MISSING_KEY":
        st.warning("Add AbuseIPDB key to see live feeds.")