import streamlit as st
from datetime import datetime
import xml.etree.ElementTree as ET
import re
import requests
import time
#css
st.markdown("""
    <style>
    /* Fond général */
    .stApp {
        background-color: #000000;
        color: #FFFFFF;
    }

    /* Titres */
    h1, h2, h3, h4, h5, h6 {
        color: #00ffcc;
    }

    /* Widgets (boutons, input...) */
    .css-1cpxqw2, .css-14xtw13, .stButton>button {
        background-color: #222222;
        color: white;
        border: 1px solid #00ffcc;
    }

    /* Champs de texte */
    .stTextInput>div>div>input,
    .stTextArea>div>textarea,
    .stSelectbox>div>div>div {
        background-color: #222222;
        color: white;
        border: 1px solid #00ffcc;
    }

    /* Tableaux et DataFrames */
    .dataframe {
        background-color: #111111;
        color: white;
    }

    /* Scrollbar */
    ::-webkit-scrollbar {
        width: 8px;
    }
    ::-webkit-scrollbar-track {
        background: #111111;
    }
    ::-webkit-scrollbar-thumb {
        background: #00ffcc;
    }
    </style>
""", unsafe_allow_html=True)


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_DELAY = 10
MAX_CVES = 10

# ---- Fonctions de ton script ----
def extract_cves_from_xml(xml_content: str) -> list:
    root = ET.fromstring(xml_content)
    pattern = re.compile(r'CVE-\d{4}-\d{4,7}')
    cves = set()
    for elem in root.iter():
        if elem.text:
            for match in pattern.findall(elem.text):
                cves.add(match)
    return sorted(cves)


def get_cve_info(cve_id: str) -> dict:
    params = {"cveId": cve_id}
    try:
        resp = requests.get(NVD_API_URL, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        if data.get("totalResults", 0) == 0 or not data.get("vulnerabilities"):
            return {}

        vuln = data["vulnerabilities"][0]["cve"]

        # CVSS
        cvss_score = "N/A"
        metrics = vuln.get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV30" in metrics:
            cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in metrics:
            cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

        # Description
        description = ""
        for desc in vuln.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "").strip()
                break

        # Références
        references = [ref["url"] for ref in vuln.get("references", []) if ref.get("url")]

        return {
            "id": cve_id,
            "cvss": cvss_score,
            "description": description,
            "references": references[:5]
        }

    except:
        return {}

# ---- Interface Streamlit ----
st.title("🛡️ CVE Vulnerability Management")

uploaded_file = st.file_uploader("Téléversez le fichier XML généré par Nmap", type="xml")

if uploaded_file:
    xml_content = uploaded_file.read().decode("utf-8")
    cves = extract_cves_from_xml(xml_content)

    if cves:
        st.success(f"{len(cves)} CVE(s) détectées.")
        selected_cves = cves[:MAX_CVES]
        report = []

        for idx, cve_id in enumerate(selected_cves):
            with st.spinner(f"Récupération des infos pour {cve_id}..."):
                info = get_cve_info(cve_id)
                if info:
                    st.subheader(f"🔎 {info['id']}")
                    st.write(f"**Score CVSS :** {info['cvss']}")
                    st.write(f"**Description :** {info['description']}")
                    if info["references"]:
                        st.write("**Références :**")
                        for ref in info["references"]:
                            st.write(f"- [{ref}]({ref})")
                    report.append(info)
                time.sleep(API_DELAY)

        if st.button("📄 Télécharger le rapport"):
            report_lines = []
            for info in report:
                report_lines.append(f"CVE: {info['id']}\nCVSS: {info['cvss']}\nDescription: {info['description']}\n")
                report_lines.append("Références:\n" + "\n".join(info['references']) + "\n" + "-"*40 + "\n")
            report_text = "\n".join(report_lines)
            st.download_button("📥 Télécharger en .txt", report_text, file_name="cve_report.txt")

    else:
        st.warning("Aucun CVE trouvé dans le fichier.")