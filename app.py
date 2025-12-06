import streamlit as st
import pandas as pd
import requests

st.set_page_config(page_title="Threat Intel", page_icon="🛡️")

st.title("🛡️ Threat Intelligence Feed")

# Sidebar
st.sidebar.header("Status")
if "virustotal" in st.secrets["api_keys"]:
    st.sidebar.success("API Keys Loaded")
else:
    st.sidebar.error("Missing API Keys")

# Main App Logic
st.write("### IOC Lookup System")
ip_input = st.text_input("Enter IP to Scan", "8.8.8.8")

if st.button("Scan IP"):
    api_key = st.secrets["api_keys"]["virustotal"]
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_input}"
    headers = {"x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            st.success("Scan Complete")
            st.json(response.json()['data']['attributes']['last_analysis_stats'])
        else:
            st.error(f"Error: {response.status_code}")
    except Exception as e:
        st.error(f"Connection Failed: {e}")