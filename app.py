import streamlit as st
import pandas as pd
import requests
import feedparser
from datetime import datetime

# --- CONFIGURATION ---
st.set_page_config(page_title="Threat Intel Platform", page_icon="🛡️", layout="wide")

# --- UTILITY FUNCTIONS ---
def get_secret(key_name):
    if "api_keys" in st.secrets and key_name in st.secrets["api_keys"]:
        return st.secrets["api_keys"][key_name]
    return None

def map_mitre_tactics(tags):
    """Maps keywords in OTX tags to MITRE ATT&CK Tactics"""
    mitre_map = {
        "Phishing": "Initial Access",
        "C2": "Command and Control",
        "Botnet": "Command and Control",
        "Scanner": "Reconnaissance",
        "Exploit": "Execution",
        "Ransomware": "Impact",
        "Backdoor": "Persistence",
        "Brute Force": "Credential Access"
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
    """Fetches strategic intel from US-CERT/CISA RSS"""
    url = "https://www.cisa.gov/uscert/ncas/alerts.xml"
    feed = feedparser.parse(url)
    return feed.entries[:10]  # Return top 10 alerts

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
st.sidebar.info("MITRE ATT&CK Framework Integrated")

# --- PAGE: DASHBOARD ---
if page == "Dashboard":
    st.title("Threat Intelligence Platform")
    col1, col2, col3 = st.columns(3)
    col1.metric("Threat Framework", "MITRE ATT&CK", "Active")
    col2.metric("Strategic Feeds", "CISA / US-CERT", "Live")
    col3.metric("Dark Web Context", "OTX Pulses", "Connected")
    
    st.markdown("### 🌐 Recent Global Campaigns")
    # Quick preview of CISA alerts
    feed = fetch_cisa_feed()
    if feed:
        for entry in feed[:3]:
            st.warning(f"**{entry.title}**")

# --- PAGE: IOC SCANNER (With MITRE & Dark Web Context) ---
elif page == "IOC Scanner":
    st.title("🔍 Tactical Analysis & MITRE Mapping")
    target_ip = st.text_input("Enter IP Address", "185.220.101.43") # Default is a known Tor exit node
    
    if st.button("Run Comprehensive Scan"):
        st.write("---")
        
        # 1. VIRUSTOTAL (Verdict)
        vt_data = check_virustotal(target_ip)
        if vt_data and vt_data != "MISSING_KEY":
            stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            
            if malicious > 0:
                st.error(f"🚨 **MALICIOUS** | Flagged by {malicious} vendors")
            else:
                st.success("✅ **CLEAN** | No immediate threats detected")
        
        # 2. ALIENVAULT & MITRE MAPPING
        otx_data = check_alienvault(target_ip)
        if otx_data:
            # Extract Tags (simulating Dark Web/Campaign context)
            pulse_info = otx_data.get("pulse_info", {})
            pulses = pulse_info.get("pulses", [])
            
            all_tags = []
            for p in pulses:
                all_tags.extend(p.get("tags", []))
            
            unique_tags = list(set(all_tags))
            
            # MAPPING LOGIC
            mitre_tactics = map_mitre_tactics(unique_tags)
            
            # DISPLAY COLUMNS
            c1, c2 = st.columns(2)
            
            with c1:
                st.subheader("🕵️ Campaign Context")
                if pulses:
                    st.write(f"Associated with **{len(pulses)} known campaigns** (Dark Web/APT).")
                    for p in pulses[:3]:
                        st.markdown(f"- 🔗 [{p['name']}](https://otx.alienvault.com/pulse/{p['id']})")
                else:
                    st.info("No specific campaign history found in OTX.")

            with c2:
                st.subheader("🟥 MITRE ATT&CK Mapping")
                if mitre_tactics:
                    for tactic in mitre_tactics:
                        st.markdown(f"**Tactic:** `{tactic}`")
                elif malicious > 0:
                    st.markdown("**Inferred Tactic:** `Initial Access` (High Probability)")
                else:
                    st.markdown("No sufficient data to map TTPs.")
            
            # Show Tags as "Dark Web/Intel Keywords"
            if unique_tags:
                st.write("**Intelligence Tags:**")
                st.code(", ".join(unique_tags[:10]))

# --- PAGE: STRATEGIC INTEL (CISA FEED) ---
elif page == "Strategic Intel (CISA)":
    st.title("📢 Strategic Intelligence Feed")
    st.markdown("Real-time alerts from **CISA (Cybersecurity & Infrastructure Security Agency)**.")
    
    feed = fetch_cisa_feed()
    
    if feed:
        for entry in feed:
            with st.expander(f"🚨 {entry.title} ({entry.published[:16]})"):
                st.markdown(entry.summary)
                st.markdown(f"[Read Full CISA Advisory]({entry.link})")
    else:
        st.error("Could not fetch CISA feed.")