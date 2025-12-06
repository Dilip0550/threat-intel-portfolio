# 🛡️ Threat Intelligence Aggregator

### Automated IOC Analysis & Threat Hunting Dashboard

**Live Demo:** [Click Here to View App](https://share.streamlit.io/YOUR_USERNAME/threat-intel-portfolio)

---

## 🚀 Project Overview
This tool automates the collection and correlation of **Open Source Intelligence (OSINT)** to help Security Operations Centers (SOC) reduce Mean Time to Detect (MTTD). 

Instead of manually checking IP addresses across multiple portals, this dashboard aggregates data from industry-standard APIs into a single pane of glass.

## 🛠️ Tech Stack
* **Core Engine:** Python 3.9+
* **Frontend:** Streamlit
* **Data Processing:** Pandas
* **Integrations (APIs):**
    * **VirusTotal v3:** For reputation scoring and malware association.
    * **AbuseIPDB:** For confidence scoring and ISP context.
    * **AlienVault OTX:** For passive DNS and pulse association.
* **Security:** Environment-variable based secrets management (No hardcoded keys).

## ⚡ Key Features
1.  **Multi-Source Verification:** Cross-references a single IOC against multiple databases simultaneously.
2.  **Live Feed Stream:** Fetches the latest high-confidence malicious IPs globally.
3.  **Rate Limit Handling:** Implements caching (`@st.cache_data`) to optimize API usage and reduce costs.

## 📦 Installation & Local Deployment

```bash
# Clone the repository
git clone [https://github.com/YOUR_USERNAME/threat-intel-portfolio.git](https://github.com/YOUR_USERNAME/threat-intel-portfolio.git)

# Install dependencies
pip install -r requirements.txt

# Configure Secrets
# Create a .streamlit/secrets.toml file and add your API keys:
# [api_keys]
# virustotal = "..."
# abuseipdb = "..."

# Run the app
streamlit run app.py