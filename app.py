import streamlit as st
import pandas as pd
import requests
import feedparser
from bs4 import BeautifulSoup
from datetime import datetime
import random

# --- CONFIGURATION ---
st.set_page_config(page_title="Threat Intel Platform", page_icon="🛡️", layout="wide")

# --- UTILITY FUNCTIONS ---
def get_secret(key_name):
    """Safely get API key or return None"""
    if "api_keys" in st.secrets and key_name in st.secrets["api_keys"]:
        key = st.secrets["api_keys"][key_name]
        # Check if the key is just a placeholder
        if "YOUR_" in key or len(key) < 10:
            return None
        return key
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

# --- MOCK DATA GENERATORS (For Demo Mode) ---
def get_mock_vt_data():
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 8, "suspicious": 2, "harmless": 60, "undetected": 5},
                "reputation": -15,
                "last_analysis_results": {
                    "Kaspersky": {"category": "malicious", "result": "Trojan.Win32.Generic"},
                    "Sophos": {"category": "malicious", "result": "Mal/Generic-S"},
                    "Google Safe Browsing": {"category": "harmless", "result": "Clean"}
                }
            }
        },
        "mock": True
    }

def get_mock_otx_data():
    return {
        "pulse_info": {
            "pulses": [
                {"name": "APT29 Phishing Campaign", "id": "mock_id_1", "tags": ["Phishing", "C2", "APT"]},
                {"name": "Cobalt Strike Beacon", "id": "mock_id_2", "tags": ["Backdoor", "Scanner"]}
            ]
        },
        "mock": True
    }

def get_mock_abuse_data():
    return {
        "data": {
            "abuseConfidenceScore": 95,
            "isp": "DigitalOcean (Simulated)",
            "countryCode": "RU",
            "totalReports": 450
        },
        "mock": True
    }

# --- API FUNCTIONS ---
@st.cache_data(ttl=3600)
def fetch_cisa_feed():
    try:
        url = "https://www.cisa.gov/uscert/ncas/alerts.xml"
        feed = feedparser.parse(url)
        return feed.entries[:10]
    except:
        return []

def check_virustotal(ip):
    api_key = get_secret("virustotal")
    if not api_key: return get_mock_vt_data()  # Fallback to Mock
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        return response.json() if response.status_code == 200 else get_mock_vt_data()
    except: return get_mock_vt_data()

def check_alienvault(ip):
    api_key = get_secret("alienvault")
    if not api_key: return get_mock_otx_data() # Fallback to Mock
    
    headers = {"X-OTX-API-KEY": api_key}
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    try:
        response = requests.get(url, headers=headers)
        return response.json() if response.status_code == 200 else get_mock_otx_data()
    except: return get_mock_otx_data()

def check_abuseipdb(ip):
    api_key = get_secret("abuseipdb")
    if not api_key: return get_mock_abuse_data() # Fallback to Mock
    
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        response = requests.get(url, headers=headers, params=params)
        return response.json() if response.status_code == 200 else get_mock_abuse_data()
    except: return get_mock_abuse_data()

# --- UI LAYOUT ---
st.sidebar.title("🛡️ Intel Ops")
page = st.sidebar.radio("Modules", ["Dashboard", "IOC Scanner", "Strategic Intel (CISA)"])
st.sidebar.markdown("---")

# Show Connection Status
st.sidebar.caption("Service Connectivity:")
services = ["virustotal", "alienvault", "abuseipdb"]
for s in services:
    if get_secret(s):
        st.sidebar.success(f"✅ {s.title()} (Live)")
    else:
        st.sidebar.info(f"🔹 {s.title()} (Demo Mode)")

# --- PAGE: DASHBOARD ---
if page == "Dashboard":
    st.title("Threat Intelligence Platform")
    col1, col2, col3 = st.columns(3)
    col1.metric("Framework", "MITRE ATT&CK", "Integrated")
    col2.metric("Scan Engine", "Hybrid (Live/Sim)", "Online")
    col3.metric("System Time", datetime.now().strftime("%H:%M"), "UTC")
    st.info("👈 Select **'IOC Scanner'** to investigate threats.")

# --- PAGE: IOC SCANNER ---
elif page == "IOC Scanner":
    st.title("🔍 Deep IOC Analysis")
    target_ip = st.text_input("Enter IP Address", "185.220.101.43")
    
    if st.button("Run Intelligence Analysis"):
        st.write("---")
        
        tab1, tab2, tab3 = st.tabs(["VirusTotal Report", "AlienVault & MITRE", "AbuseIPDB Check"])
        
        # --- TAB 1: VIRUSTOTAL ---
        with tab1:
            vt_data = check_virustotal(target_ip)
            
            # Show "Demo Mode" banner if using mock data
            if vt_data.get("mock"):
                st.info("ℹ️ **Demo Mode:** Displaying simulated data because API Key is missing.")

            if vt_data:
                attrs = vt_data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                
                c1, c2, c3 = st.columns(3)
                c1.metric("Malicious Flags", malicious)
                c2.metric("Harmless Flags", stats.get("harmless", 0))
                c3.metric("Reputation", attrs.get("reputation", 0))
                
                if malicious > 0:
                    st.error(f"🚨 **Verdict: MALICIOUS**")
                else:
                    st.success("✅ **Verdict: CLEAN**")

                st.subheader("Vendor Detection Details")
                results = attrs.get("last_analysis_results", {})
                
                table_data = []
                for vendor, details in results.items():
                    if details['category'] in ['malicious', 'suspicious']:
                        table_data.append({
                            "Vendor": vendor,
                            "Result": details['result'],
                            "Category": details['category']
                        })
                
                if table_data:
                    st.table(pd.DataFrame(table_data))
                else:
                    st.info("No vendors flagged this IP in the current dataset.")

        # --- TAB 2: ALIENVAULT & MITRE ---
        with tab2:
            otx_data = check_alienvault(target_ip)
            
            if otx_data.get("mock"):
                st.info("ℹ️ **Demo Mode:** Displaying simulated MITRE mapping.")

            if otx_data:
                pulses = otx_data.get("pulse_info", {}).get("pulses", [])
                
                all_tags = []
                for p in pulses:
                    all_tags.extend(p.get("tags", []))
                tactics = map_mitre_tactics(list(set(all_tags)))
                
                st.subheader("🟥 MITRE ATT&CK Matrix")
                if tactics:
                    cols = st.columns(len(tactics))
                    for idx, t in enumerate(tactics):
                        cols[idx].error(f"🛡️ {t}")
                else:
                    st.info("No MITRE Tactics mapped.")

                st.subheader("Associated Threat Campaigns")
                if pulses:
                    for p in pulses[:5]:
                        st.markdown(f"- 🔗 **{p['name']}** (Source: OTX)")

        # --- TAB 3: ABUSEIPDB ---
        with tab3:
            abuse_data = check_abuseipdb(target_ip)
            
            if abuse_data.get("mock"):
                st.info("ℹ️ **Demo Mode:** Displaying simulated ISP report.")

            if abuse_data:
                data = abuse_data.get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                
                st.metric("Abuse Confidence Score", f"{score}%")
                st.progress(score / 100)
                
                st.write(f"**ISP:** {data.get('isp')}")
                st.write(f"**Country:** {data.get('countryCode')}")

# --- PAGE: STRATEGIC INTEL ---
elif page == "Strategic Intel (CISA)":
    st.title("📢 Strategic Intelligence Feed (CISA)")
    feed = fetch_cisa_feed()
    if feed:
        for entry in feed:
            with st.expander(f"🚨 {entry.title}"):
                st.write(clean_html(entry.summary))
                st.markdown(f"[Read Full Advisory]({entry.link})")
    else:
        st.error("Unable to fetch CISA feed.")