import streamlit as st
import pandas as pd
import requests
import feedparser
from bs4 import BeautifulSoup
from datetime import datetime

# --- CONFIGURATION ---
st.set_page_config(page_title="Threat Intel Platform", page_icon="🛡️", layout="wide")

# --- UTILITY FUNCTIONS ---
def get_secret(key_name):
    if "api_keys" in st.secrets and key_name in st.secrets["api_keys"]:
        return st.secrets["api_keys"][key_name]
    return None

def clean_html(raw_html):
    try:
        soup = BeautifulSoup(raw_html, "html.parser")
        return soup.get_text()
    except:
        return raw_html

def map_mitre_tactics(tags):
    mitre_map = {
        "Phishing": "Initial Access",
        "C2": "Command and Control",
        "Botnet": "Command and Control",
        "Scanner": "Reconnaissance",
        "Exploit": "Execution",
        "Ransomware": "Impact",
        "Backdoor": "Persistence",
        "Brute Force": "Credential Access",
        "ddos": "Impact",
        "Trojan": "Persistence"
    }
    detected = set()
    for tag in tags:
        for keyword, tactic in mitre_map.items():
            if keyword.lower() in tag.lower():
                detected.add(tactic)
    return list(detected)

# --- API FUNCTIONS (With Debug Prints) ---
@st.cache_data(ttl=3600)
def fetch_cisa_feed():
    try:
        url = "https://www.cisa.gov/uscert/ncas/alerts.xml"
        feed = feedparser.parse(url)
        if not feed.entries:
            return "EMPTY_FEED"
        return feed.entries[:10]
    except Exception as e:
        return f"ERROR: {str(e)}"

def check_virustotal(ip):
    api_key = get_secret("virustotal")
    if not api_key: return "MISSING_KEY"
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        return response.json() if response.status_code == 200 else None
    except: return None

def check_alienvault(ip):
    api_key = get_secret("alienvault")
    if not api_key: return "MISSING_KEY"
    
    headers = {"X-OTX-API-KEY": api_key}
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    try:
        response = requests.get(url, headers=headers)
        return response.json() if response.status_code == 200 else None
    except: return None

def check_abuseipdb(ip):
    api_key = get_secret("abuseipdb")
    if not api_key: return "MISSING_KEY"
    
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        response = requests.get(url, headers=headers, params=params)
        return response.json() if response.status_code == 200 else None
    except: return None

# --- UI LAYOUT ---
st.sidebar.title("🛡️ Intel Ops")
page = st.sidebar.radio("Modules", ["Dashboard", "IOC Scanner", "Strategic Intel (CISA)"])
st.sidebar.markdown("---")

# --- PAGE: DASHBOARD ---
if page == "Dashboard":
    st.title("Threat Intelligence Platform")
    col1, col2, col3 = st.columns(3)
    col1.metric("Framework", "MITRE ATT&CK", "Integrated")
    col2.metric("Scan Engine", "Multi-Vector", "Online")
    col3.metric("System Time", datetime.now().strftime("%H:%M"), "UTC")
    st.info("👈 Select **'IOC Scanner'** to investigate an IP.")

# --- PAGE: IOC SCANNER ---
elif page == "IOC Scanner":
    st.title("🔍 Deep IOC Analysis")
    target_ip = st.text_input("Enter IP Address", "185.220.101.43")
    
    if st.button("Run Intelligence Analysis"):
        st.write("---")
        
        tab1, tab2, tab3 = st.tabs(["VirusTotal", "AlienVault & MITRE", "AbuseIPDB"])
        
        # TAB 1: VIRUSTOTAL
        with tab1:
            vt_data = check_virustotal(target_ip)
            if vt_data == "MISSING_KEY":
                st.warning("⚠️ VirusTotal API Key is missing in secrets.")
            elif vt_data:
                stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                if stats.get("malicious", 0) > 0:
                    st.error(f"🚨 Malicious: {stats.get('malicious')} vendors")
                else:
                    st.success("✅ Clean")
                st.json(stats)

        # TAB 2: ALIENVAULT & MITRE
        with tab2:
            otx_data = check_alienvault(target_ip)
            
            # DEBUG MESSAGES
            if otx_data == "MISSING_KEY":
                st.error("❌ AlienVault API Key is missing. MITRE Matrix cannot be generated.")
                st.markdown("[Get a free key here](https://otx.alienvault.com/)")
            elif otx_data is None:
                st.warning("⚠️ Connection to AlienVault failed (Check IP or Key).")
            else:
                # If we have data, show the matrix
                pulses = otx_data.get("pulse_info", {}).get("pulses", [])
                all_tags = []
                for p in pulses:
                    all_tags.extend(p.get("tags", []))
                
                tactics = map_mitre_tactics(list(set(all_tags)))
                
                st.subheader("🟥 MITRE ATT&CK Matrix")
                if tactics:
                    for t in tactics:
                        st.warning(f"🛡️ {t}")
                else:
                    st.info("No MITRE Tactics mapped for this IP.")
                
                st.write(f"Associated Campaigns: {len(pulses)}")

        # TAB 3: ABUSEIPDB
        with tab3:
            abuse_data = check_abuseipdb(target_ip)
            if abuse_data == "MISSING_KEY":
                st.warning("⚠️ AbuseIPDB API Key is missing in secrets.")
            elif abuse_data:
                data = abuse_data.get("data", {})
                st.metric("Confidence Score", f"{data.get('abuseConfidenceScore')}%")
                st.write(f"ISP: {data.get('isp')}")

# --- PAGE: STRATEGIC INTEL ---
elif page == "Strategic Intel (CISA)":
    st.title("📢 Strategic Intelligence Feed")
    feed_data = fetch_cisa_feed()
    
    if feed_data == "EMPTY_FEED":
        st.warning("Feed fetched but contains no entries.")
    elif isinstance(feed_data, str) and "ERROR" in feed_data:
        st.error(f"Failed to load feed. Debug info: {feed_data}")
        st.info("Did you add 'feedparser' to requirements.txt?")
    elif feed_data:
        for entry in feed_data:
            with st.expander(f"🚨 {entry.title}"):
                st.write(clean_html(entry.summary))
                st.markdown(f"[Read Advisory]({entry.link})")