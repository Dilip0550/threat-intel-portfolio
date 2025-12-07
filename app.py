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
    if not api_key: return "MISSING_KEY"
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        return response.json() if response.status_code == 200 else None
    except: return None

def check_alienvault(ip):
    api_key = get_secret("alienvault")
    # Even if key is missing, we try to return None so UI handles it gracefully
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
st.sidebar.caption("Status:")
if get_secret("virustotal"): st.sidebar.success("VT Key Loaded")
else: st.sidebar.error("VT Key Missing")

# --- DASHBOARD ---
if page == "Dashboard":
    st.title("Threat Intelligence Platform")
    col1, col2, col3 = st.columns(3)
    col1.metric("Framework", "MITRE ATT&CK", "Active")
    col2.metric("Scan Engine", "Multi-Vector", "Online")
    col3.metric("System Time", datetime.now().strftime("%H:%M"), "UTC")
    st.info("👈 Go to **IOC Scanner** to analyze an IP.")

# --- IOC SCANNER ---
elif page == "IOC Scanner":
    st.title("🔍 Deep IOC Analysis")
    target_ip = st.text_input("Enter IP Address", "185.220.101.43")
    
    if st.button("Run Intelligence Analysis"):
        st.write("---")
        
        # TABS FOR CLEAN LAYOUT
        tab1, tab2, tab3 = st.tabs(["VirusTotal Report", "AlienVault & MITRE", "AbuseIPDB Check"])
        
        # --- TAB 1: VIRUSTOTAL (Clean Table, No JSON) ---
        with tab1:
            vt_data = check_virustotal(target_ip)
            
            if vt_data == "MISSING_KEY":
                st.warning("⚠️ VirusTotal API Key is missing.")
            elif vt_data:
                # 1. High Level Stats
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

                # 2. Detailed Vendor Table (Parsing the JSON)
                st.subheader("Vendor Detection Details")
                results = attrs.get("last_analysis_results", {})
                
                # Loop through the JSON and make a list
                table_data = []
                for vendor, details in results.items():
                    # Only show vendors that flagged it or failed, skip the 'undetected' ones to keep it clean
                    if details['category'] in ['malicious', 'suspicious']:
                        table_data.append({
                            "Vendor": vendor,
                            "Result": details['result'],
                            "Category": details['category']
                        })
                
                if table_data:
                    st.table(pd.DataFrame(table_data))
                else:
                    st.info("No vendors flagged this IP as malicious.")
                    
            else:
                st.error("Could not connect to VirusTotal.")

        # --- TAB 2: ALIENVAULT & MITRE ---
        with tab2:
            otx_data = check_alienvault(target_ip)
            
            if otx_data == "MISSING_KEY":
                st.warning("⚠️ AlienVault Key Missing. MITRE matrix disabled.")
                st.markdown("[Get Free Key](https://otx.alienvault.com/)")
            elif otx_data:
                pulses = otx_data.get("pulse_info", {}).get("pulses", [])
                
                # MITRE MAPPING
                all_tags = []
                for p in pulses:
                    all_tags.extend(p.get("tags", []))
                tactics = map_mitre_tactics(list(set(all_tags)))
                
                st.subheader("🟥 MITRE ATT&CK Matrix")
                if tactics:
                    # Visual Matrix
                    cols = st.columns(len(tactics))
                    for idx, t in enumerate(tactics):
                        cols[idx].error(f"🛡️ {t}")
                else:
                    st.info("No MITRE Tactics mapped.")

                # CAMPAIGNS
                st.subheader("Associated Threat Campaigns")
                if pulses:
                    for p in pulses[:5]:
                        st.markdown(f"- 🔗 [{p['name']}](https://otx.alienvault.com/pulse/{p['id']})")
                else:
                    st.write("No known campaigns associated.")

        # --- TAB 3: ABUSEIPDB ---
        with tab3:
            abuse_data = check_abuseipdb(target_ip)
            if abuse_data == "MISSING_KEY":
                st.warning("⚠️ AbuseIPDB Key Missing.")
            elif abuse_data:
                data = abuse_data.get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                
                st.metric("Abuse Confidence Score", f"{score}%")
                st.progress(score / 100)
                
                st.write(f"**ISP:** {data.get('isp')}")
                st.write(f"**Country:** {data.get('countryCode')}")
                
                if score > 50:
                    st.error("High probability of abusive behavior.")
                else:
                    st.success("Low probability of abusive behavior.")

# --- STRATEGIC INTEL ---
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