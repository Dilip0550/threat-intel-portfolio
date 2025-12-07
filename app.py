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
    """Safely get API key or return None if missing/placeholder"""
    if "api_keys" in st.secrets and key_name in st.secrets["api_keys"]:
        key = st.secrets["api_keys"][key_name]
        # Treat placeholders or short dummy keys as "missing"
        if "YOUR_" in key or len(key) < 10: return None
        return key
    return None

def clean_html(raw_html):
    """Removes HTML tags from RSS feeds for clean text display"""
    try:
        soup = BeautifulSoup(raw_html, "html.parser")
        return soup.get_text()
    except:
        return raw_html

def map_mitre_tactics(tags):
    """Maps OTX tags to MITRE ATT&CK Tactics"""
    mitre_map = {
        "Phishing": "Initial Access", "C2": "Command and Control",
        "Botnet": "Command and Control", "Scanner": "Reconnaissance",
        "Exploit": "Execution", "Ransomware": "Impact",
        "Backdoor": "Persistence", "Brute Force": "Credential Access",
        "ddos": "Impact", "Trojan": "Persistence"
    }
    detected = set()
    for tag in tags:
        for keyword, tactic in mitre_map.items():
            if keyword.lower() in tag.lower():
                detected.add(tactic)
    return list(detected)

# --- MOCK DATA GENERATORS (The "Safety Net") ---
def get_mock_vt_data():
    return {"data": {"attributes": {"last_analysis_stats": {"malicious": 8, "suspicious": 2, "harmless": 60, "undetected": 5}, "reputation": -15, "last_analysis_results": {"Kaspersky": {"category": "malicious", "result": "Trojan.Win32.Generic"}, "Sophos": {"category": "malicious", "result": "Mal/Generic-S"}, "Google Safe Browsing": {"category": "harmless", "result": "Clean"}}}}, "mock": True}

def get_mock_otx_data():
    return {"pulse_info": {"pulses": [{"name": "APT29 Phishing Campaign", "id": "mock_1", "tags": ["Phishing", "C2", "APT"]}, {"name": "Cobalt Strike Beacon", "id": "mock_2", "tags": ["Backdoor", "Scanner"]}]}, "mock": True}

def get_mock_abuse_data():
    return {"data": {"abuseConfidenceScore": 95, "isp": "DigitalOcean (Simulated)", "countryCode": "RU", "totalReports": 450}, "mock": True}

# --- API FUNCTIONS ---
@st.cache_data(ttl=1800) # Cache RSS feeds for 30 minutes
def fetch_rss_feed(feed_url):
    try:
        feed = feedparser.parse(feed_url)
        return feed.entries[:10]
    except:
        return []

def check_virustotal(ip):
    api_key = get_secret("virustotal")
    if not api_key: return get_mock_vt_data()
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        return response.json() if response.status_code == 200 else get_mock_vt_data()
    except: return get_mock_vt_data()

def check_alienvault(ip):
    api_key = get_secret("alienvault")
    if not api_key: return get_mock_otx_data()
    
    headers = {"X-OTX-API-KEY": api_key}
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    try:
        response = requests.get(url, headers=headers)
        return response.json() if response.status_code == 200 else get_mock_otx_data()
    except: return get_mock_otx_data()

def check_abuseipdb(ip):
    api_key = get_secret("abuseipdb")
    if not api_key: return get_mock_abuse_data()
    
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        response = requests.get(url, headers=headers, params=params)
        return response.json() if response.status_code == 200 else get_mock_abuse_data()
    except: return get_mock_abuse_data()

# --- UI LAYOUT ---
st.sidebar.title("🛡️ Intel Ops")
page = st.sidebar.radio("Modules", ["Dashboard", "IOC Scanner", "Strategic Intelligence"])
st.sidebar.markdown("---")

# Service Status Indicator
st.sidebar.caption("Service Connectivity:")
services = ["virustotal", "alienvault", "abuseipdb"]
for s in services:
    if get_secret(s): st.sidebar.success(f"✅ {s.title()} (Live)")
    else: st.sidebar.info(f"🔹 {s.title()} (Demo Mode)")

# --- PAGE: DASHBOARD ---
if page == "Dashboard":
    st.title("Threat Intelligence Platform")
    col1, col2, col3 = st.columns(3)
    col1.metric("Framework", "MITRE ATT&CK", "Integrated")
    col2.metric("Feed Sources", "CISA / Krebs / THN", "Live")
    col3.metric("System Time", datetime.now().strftime("%H:%M"), "UTC")
    st.info("👈 Select **'Strategic Intelligence'** to view live cyber news.")
    
# --- PAGE: IOC SCANNER ---
elif page == "IOC Scanner":
    st.title("🔍 Deep IOC Analysis")
    target_ip = st.text_input("Enter IP Address", "185.220.101.43")
    
    if st.button("Run Analysis"):
        st.write("---")
        tab1, tab2, tab3 = st.tabs(["VirusTotal", "AlienVault & MITRE", "AbuseIPDB"])
        
        # TAB 1: VIRUSTOTAL
        with tab1:
            vt_data = check_virustotal(target_ip)
            if vt_data.get("mock"): st.info("ℹ️ Demo Mode: Simulating VirusTotal Data")
            
            stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            
            c1, c2, c3 = st.columns(3)
            c1.metric("Malicious Flags", malicious)
            c2.metric("Harmless", stats.get("harmless", 0))
            c3.metric("Reputation", vt_data.get("data", {}).get("attributes", {}).get("reputation", 0))

            if malicious > 0: st.error(f"🚨 **Verdict: MALICIOUS**")
            else: st.success("✅ **Verdict: CLEAN**")
            
            st.subheader("Vendor Detection Details")
            results = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
            table_data = [{"Vendor": v, "Result": d['result'], "Category": d['category']} for v, d in results.items() if d['category'] in ['malicious', 'suspicious']]
            if table_data: st.table(pd.DataFrame(table_data))
            else: st.info("No vendors flagged this IP.")

        # TAB 2: ALIENVAULT & MITRE
        with tab2:
            otx_data = check_alienvault(target_ip)
            if otx_data.get("mock"): st.info("ℹ️ Demo Mode: Simulating MITRE Mapping")
            
            pulses = otx_data.get("pulse_info", {}).get("pulses", [])
            tags = []
            for p in pulses: tags.extend(p.get("tags", []))
            tactics = map_mitre_tactics(list(set(tags)))
            
            st.subheader("🟥 MITRE ATT&CK Matrix")
            if tactics:
                cols = st.columns(len(tactics))
                for idx, t in enumerate(tactics): cols[idx].error(f"🛡️ {t}")
            else: st.info("No MITRE Tactics mapped.")
            
            st.subheader("Associated Campaigns")
            if pulses:
                for p in pulses[:5]: st.markdown(f"- 🔗 **{p['name']}**")

        # TAB 3: ABUSEIPDB
        with tab3:
            abuse_data = check_abuseipdb(target_ip)
            if abuse_data.get("mock"): st.info("ℹ️ Demo Mode: Simulating ISP Report")
            data = abuse_data.get("data", {})
            
            st.metric("Abuse Confidence", f"{data.get('abuseConfidenceScore')}%")
            st.progress(data.get('abuseConfidenceScore', 0) / 100)
            st.write(f"**ISP:** {data.get('isp')}")
            st.write(f"**Country:** {data.get('countryCode')}")

# --- PAGE: STRATEGIC INTEL (NEWS FEED) ---
elif page == "Strategic Intelligence":
    st.title("📰 Cyber Threat News Feed")
    
    # Layout: Dropdown + Refresh Button
    col1, col2 = st.columns([3, 1])
    with col1:
        news_source = st.selectbox(
            "Select Intelligence Source", 
            ["The Hacker News", "Krebs on Security", "CISA Alerts (US-CERT)", "BleepingComputer"]
        )
    with col2:
        st.write("") # Spacer to align button
        st.write("") 
        if st.button("🔄 Force Refresh"):
            st.cache_data.clear()
            st.rerun()

    # RSS URLs dictionary
    rss_urls = {
        "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
        "Krebs on Security": "https://krebsonsecurity.com/feed/",
        "CISA Alerts (US-CERT)": "https://www.cisa.gov/uscert/ncas/alerts.xml",
        "BleepingComputer": "https://www.bleepingcomputer.com/feed/"
    }
    
    st.write("---")
    
    selected_url = rss_urls[news_source]
    feed = fetch_rss_feed(selected_url)
    
    if feed:
        st.success(f"Latest Updates from **{news_source}**")
        for entry in feed:
            with st.expander(f"📢 {entry.title}"):
                st.caption(f"Published: {entry.get('published', 'N/A')}")
                st.write(clean_html(entry.summary))
                st.markdown(f"[Read Full Article]({entry.link})")
    else:
        st.error("Unable to fetch feed. Check internet connection.")