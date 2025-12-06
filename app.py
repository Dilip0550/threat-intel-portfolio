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
    """Removes HTML tags from RSS feeds for clean text display"""
    soup = BeautifulSoup(raw_html, "html.parser")
    return soup.get_text()

def map_mitre_tactics(tags):
    """Maps OTX tags to MITRE ATT&CK Tactics"""
    mitre_map = {
        "Phishing": "Initial Access",
        "C2": "Command and Control",
        "Botnet": "Command and Control",
        "Scanner": "Reconnaissance",
        "Exploit": "Execution",
        "Ransomware": "Impact",
        "Backdoor": "Persistence",
        "Brute Force": "Credential Access",
        "ddos": "Impact"
    }
    detected_tactics = set()
    for tag in tags:
        for keyword, tactic in mitre_map.items():
            if keyword.lower() in tag.lower():
                detected_tactics.add(tactic)
    return list(detected_tactics)

# --- API FUNCTIONS ---
@st.cache_data(ttl=3600)
def fetch_cisa_feed():
    url = "https://www.cisa.gov/uscert/ncas/alerts.xml"
    feed = feedparser.parse(url)
    return feed.entries[:10]

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
    # Note: OTX often works without a key for public pulses, but key is recommended
    headers = {"X-OTX-API-KEY": api_key} if api_key else {}
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    try:
        response = requests.get(url, headers=headers)
        return response.json() if response.status_code == 200 else None
    except: return None

# --- UI LAYOUT ---
st.sidebar.title("🛡️ Intel Ops")
page = st.sidebar.radio("Modules", ["Dashboard", "IOC Scanner", "Strategic Intel (CISA)"])
st.sidebar.markdown("---")
if get_secret("alienvault"):
    st.sidebar.success("✅ AlienVault Key Loaded")
else:
    st.sidebar.warning("⚠️ AlienVault Key Missing")

# --- PAGE: DASHBOARD ---
if page == "Dashboard":
    st.title("Threat Intelligence Platform")
    col1, col2, col3 = st.columns(3)
    col1.metric("Threat Framework", "MITRE ATT&CK", "Integrated")
    col2.metric("Strategic Feeds", "CISA / US-CERT", "Live")
    col3.metric("System Time", datetime.now().strftime("%H:%M"), "UTC")
    
    st.info("👈 Select **'Strategic Intel'** to see the corrected CISA feed.")

# --- PAGE: IOC SCANNER ---
elif page == "IOC Scanner":
    st.title("🔍 Tactical Analysis & MITRE Mapping")
    target_ip = st.text_input("Enter IP Address", "185.220.101.43") 
    
    if st.button("Run Comprehensive Scan"):
        st.write("---")
        
        # 1. VIRUSTOTAL
        vt_data = check_virustotal(target_ip)
        malicious_score = 0
        if vt_data and vt_data != "MISSING_KEY":
            stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_score = stats.get("malicious", 0)
            if malicious_score > 0:
                st.error(f"🚨 **MALICIOUS** | Flagged by {malicious_score} vendors")
            else:
                st.success("✅ **CLEAN** | No immediate threats detected")
        
        # 2. ALIENVAULT & MITRE FRAMEWORK
        otx_data = check_alienvault(target_ip)
        
        st.subheader("🟥 MITRE ATT&CK Framework Analysis")
        
        if otx_data:
            # Extract Tags
            pulse_info = otx_data.get("pulse_info", {})
            pulses = pulse_info.get("pulses", [])
            all_tags = []
            for p in pulses:
                all_tags.extend(p.get("tags", []))
            
            unique_tags = list(set(all_tags))
            mitre_tactics = map_mitre_tactics(unique_tags)
            
            # VISUAL MATRIX (Columns)
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**Identified TTPs (Tactics, Techniques, Procedures):**")
                if mitre_tactics:
                    for tactic in mitre_tactics:
                        st.warning(f"🛡️ **{tactic}**")
                else:
                    st.info("No specific MITRE tactics matched to this indicator.")
                    
            with c2:
                st.markdown("**Intelligence Context:**")
                if pulses:
                    st.write(f"Associated with {len(pulses)} known threat campaigns.")
                    st.json([p['name'] for p in pulses[:5]])
                else:
                    st.write("No direct campaign association found.")
        else:
             st.warning("Could not connect to AlienVault OTX (Check API Key).")

# --- PAGE: STRATEGIC INTEL (CISA FEED) ---
elif page == "Strategic Intel (CISA)":
    st.title("📢 Strategic Intelligence Feed")
    st.markdown("Real-time alerts from **CISA (Cybersecurity & Infrastructure Security Agency)**.")
    
    feed = fetch_cisa_feed()
    
    if feed:
        for entry in feed:
            with st.expander(f"🚨 {entry.title}"):
                # CLEAN THE HTML HERE
                clean_summary = clean_html(entry.summary)
                st.write(clean_summary)
                st.markdown(f"[Read Official Advisory]({entry.link})")
    else:
        st.error("Could not fetch CISA feed.")