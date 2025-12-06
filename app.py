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
    # AlienVault OTX is often free without auth for some endpoints, 
    # but using a key is better for limits.
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
st.sidebar.caption("API Status:")
for service in ["virustotal", "abuseipdb", "alienvault"]:
    if get_secret(service):
        st.sidebar.success(f"✅ {service}")
    else:
        st.sidebar.warning(f"⚠️ {service} (Key Missing)")

# --- PAGE: DASHBOARD ---
if page == "Dashboard":
    st.title("Threat Intelligence Command Center")
    st.write("Welcome to the unified threat aggregation platform.")
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Active Feeds", "3")
    col2.metric("System Status", "Online")
    col3.metric("Last Update", datetime.now().strftime("%H:%M:%S"))

    st.info("👈 Select **'IOC Scanner'** to investigate an IP address.")

# --- PAGE: IOC SCANNER ---
elif page == "IOC Scanner":
    st.title("🔍 Multi-Source IOC Scanner")
    target_ip = st.text_input("Enter IP Address", "8.8.8.8")
    
    if st.button("Deep Scan"):
        # 1. VirusTotal
        with st.expander("VirusTotal Analysis", expanded=True):
            vt_result = check_virustotal(target_ip)
            if vt_result == "MISSING_KEY":
                st.warning("Please add VirusTotal key to secrets.toml")
            elif isinstance(vt_result, dict):
                stats = vt_result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                if stats.get("malicious", 0) > 0:
                    st.error(f"⚠️ MALICIOUS: {stats.get('malicious')} vendors flagged this.")
                else:
                    st.success("✅ Clean (0 Detections)")
                st.json(stats)
            else:
                st.error(vt_result)

        # 2. AlienVault OTX
        with st.expander("AlienVault OTX Context"):
            otx_result = check_alienvault(target_ip)
            if otx_result:
                st.write(f"**ASN:** {otx_result.get('asn', 'N/A')}")
                st.write(f"**Country:** {otx_result.get('country_name', 'N/A')}")
                st.write(f"**Reputation:** {otx_result.get('reputation', 'Unknown')}")
            else:
                st.info("No OTX data found or connection failed.")

# --- PAGE: LIVE FEEDS ---
elif page == "Live Feeds":
    st.title("🚨 Global Threat Feed (AbuseIPDB)")
    
    df = fetch_abuseipdb_blacklist()
    
    if isinstance(df, str) and df == "MISSING_KEY":
        st.warning("⚠️ Access Restricted: Please add 'abuseipdb' key to secrets.")
        st.markdown("[Get a free key here](https://www.abuseipdb.com/)")
    elif isinstance(df, pd.DataFrame) and not df.empty:
        st.dataframe(df[['ipAddress', 'abuseConfidenceScore', 'countryCode']], use_container_width=True)
    else:
        st.error("Unable to fetch feed.")