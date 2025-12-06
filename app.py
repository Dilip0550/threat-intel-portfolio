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
        "ddos": "Impact",
        "Trojan": "Persistence"
    }
    detected = []
    for tag in tags:
        for keyword, tactic in mitre_map.items():
            if keyword.lower() in tag.lower():
                detected.append(tactic)
    return list(set(detected))

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
    headers = {"X-OTX-API-KEY": api_key} if api_key else {}
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    try:
        response = requests.get(url, headers=headers)
        return response.json() if response.status_code == 200 else None
    except: return None

def check_abuseipdb(ip):
    """Checks a specific IP against AbuseIPDB"""
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
    target_ip = st.text_input("Enter IP Address", "185.220.101.43") # Default known bad IP
    
    if st.button("Run Intelligence Analysis"):
        st.write("---")
        
        # We use Tabs to organize the 3 feeds clearly
        tab1, tab2, tab3 = st.tabs(["VirusTotal Analysis", "AlienVault & MITRE", "AbuseIPDB Report"])
        
        # --- TAB 1: VIRUSTOTAL (Detailed) ---
        with tab1:
            vt_data = check_virustotal(target_ip)
            if vt_data and vt_data != "MISSING_KEY":
                attrs = vt_data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                
                # Banner
                if stats.get("malicious", 0) > 0:
                    st.error(f"🚨 **MALICIOUS**: {stats.get('malicious')} Vendors Flagged this IP")
                else:
                    st.success("✅ **CLEAN**: 0 Vendors Flagged this IP")

                # Detail Table
                st.subheader("Vendor Detection Details")
                results = attrs.get("last_analysis_results", {})
                
                # Create a list of detections
                detections = []
                for vendor, res in results.items():
                    if res["category"] == "malicious":
                        detections.append({
                            "Vendor": vendor,
                            "Result": res["result"],
                            "Update": "Recent"
                        })
                
                if detections:
                    st.table(pd.DataFrame(detections))
                else:
                    st.info("No detailed malware family names returned.")
            else:
                st.warning("VirusTotal Key missing or API Error.")

        # --- TAB 2: ALIENVAULT & MITRE (Visual) ---
        with tab2:
            otx_data = check_alienvault(target_ip)
            if otx_data:
                # Get Tags
                pulses = otx_data.get("pulse_info", {}).get("pulses", [])
                all_tags = []
                for p in pulses:
                    all_tags.extend(p.get("tags", []))
                
                # Map to MITRE
                tactics = map_mitre_tactics(list(set(all_tags)))
                
                st.subheader("🟥 MITRE ATT&CK Matrix")
                
                # Create a visualization dataframe
                all_tactics = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"]
                
                # Create a row of colors
                matrix_data = {}
                for t in all_tactics:
                    matrix_data[t] = ["DETECTED" if t in tactics else "-"]
                
                df_matrix = pd.DataFrame(matrix_data)
                
                # Display nicely
                st.dataframe(df_matrix, use_container_width=True)
                
                if tactics:
                    st.markdown(f"**Detected Tactics:** {', '.join(tactics)}")
                    st.markdown("[🔗 View Full MITRE Framework on mitre.org](https://attack.mitre.org/)")
                else:
                    st.info("No TTPs could be mapped from current intelligence.")