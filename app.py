import streamlit as st
import re
import requests
import time
import xml.etree.ElementTree as ET
import json
import os
import subprocess
import tempfile
import pandas as pd
from datetime import datetime
import ipaddress
import plotly.express as px
import plotly.graph_objects as go

# NVD API endpoint
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_DELAY = 6  # Reduced from 10 to improve user experience

# Set page configuration
st.set_page_config(
    page_title="Vulnerability Scanner",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .reportview-container {
        background-color: #f0f2f6;
    }
    .main {
        background-color: #ffffff;
    }
    .stProgress > div > div {
        background-color: #1e88e5;
    }
    .severity-critical {
        color: #d32f2f;
        font-weight: bold;
    }
    .severity-high {
        color: #f57c00;
        font-weight: bold;
    }
    .severity-medium {
        color: #fbc02d;
        font-weight: bold;
    }
    .severity-low {
        color: #388e3c;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)


def validate_ip(ip):
    """Validate if the input is a valid IP address or hostname."""
    # Check if it's a valid IP address
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        # Check if it might be a hostname
        if re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9.]{0,253}[a-zA-Z0-9]?$', ip):
            return True
        return False


def run_nmap_scan(target_ip, output_file, progress_bar=None, status_area=None):
    """
    Run an Nmap scan with the vulners script against the target IP
    and save the output to an XML file.
    """
    if status_area:
        status_area.info(f"Starting Nmap scan on {target_ip}...")
    
    try:
        # Run Nmap with vulners script and save XML output
        cmd = [
            "nmap", 
            "-sV",                   # Version detection
            "--script=vulners",      # Use vulners script for vulnerability detection
            "-oX", output_file,      # Output to XML
            target_ip
        ]
        
        # Start the process
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        # Get output in real-time
        stdout_output = []
        stderr_output = []
        
        # Update progress periodically
        if progress_bar:
            progress_bar.progress(10)
        
        for line in iter(process.stdout.readline, ''):
            stdout_output.append(line)
            if status_area and line.strip():
                status_area.info(line.strip())
            if progress_bar and "Completed" in line and "%" in line:
                try:
                    # Extract percentage and update progress
                    percentage = re.search(r'Completed (\d+)%', line)
                    if percentage:
                        progress_value = min(10 + float(percentage.group(1)) * 0.6, 70)
                        progress_bar.progress(int(progress_value))
                except:
                    pass
        
        for line in iter(process.stderr.readline, ''):
            stderr_output.append(line)
            if status_area and line.strip():
                status_area.error(line.strip())
        
        process.stdout.close()
        process.stderr.close()
        return_code = process.wait()
        
        if progress_bar:
            progress_bar.progress(70)
        
        if return_code != 0:
            if status_area:
                status_area.error(f"Nmap scan failed with return code {return_code}")
                status_area.error(''.join(stderr_output))
            return False, ''.join(stdout_output), ''.join(stderr_output)
        
        if status_area:
            status_area.success(f"Scan completed successfully!")
        
        return True, ''.join(stdout_output), ''.join(stderr_output)
    
    except FileNotFoundError:
        if status_area:
            status_area.error("Error: Nmap is not installed or not in PATH.")
            status_area.error("Please install Nmap (https://nmap.org/download.html) and try again.")
        return False, "", "Nmap not found. Please install Nmap."
    except Exception as e:
        if status_area:
            status_area.error(f"Error during Nmap scan: {str(e)}")
        return False, "", str(e)


def extract_cves(xml_file, status_area=None):
    """
    Parse XML file and return a sorted list of unique CVE IDs.
    """
    if not os.path.exists(xml_file):
        if status_area:
            status_area.error(f"XML file '{xml_file}' not found.")
        return []
    
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        pattern = re.compile(r'CVE-\d{4}-\d{4,7}')
        cves = set()
        
        # Check if any hosts were scanned
        hosts = root.findall(".//host")
        if not hosts:
            if status_area:
                status_area.warning("No hosts found in scan results.")
            return []
            
        for elem in root.iter():
            if elem.text:
                for match in pattern.findall(elem.text):
                    cves.add(match)
        
        return sorted(cves)
    except ET.ParseError:
        if status_area:
            status_area.error(f"Failed to parse '{xml_file}'. The file may be corrupted or empty.")
        return []
    except Exception as e:
        if status_area:
            status_area.error(f"Error extracting CVEs: {e}")
        return []


def get_cve_info(cve_id, status_area=None):
    """
    Get CVE information from NVD API.
    """
    params = {"cveId": cve_id}
    tries = 3
    
    for attempt in range(tries):
        try:
            if attempt > 0 and status_area:
                status_area.info(f"Retrying... (attempt {attempt+1}/{tries})")
                time.sleep(API_DELAY)
            
            if status_area:
                status_area.info(f"Querying NVD API for {cve_id}...")
            
            resp = requests.get(NVD_API_URL, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()

            if data.get("totalResults", 0) == 0 or not data.get("vulnerabilities"):
                if status_area:
                    status_area.warning(f"No information found for {cve_id}")
                return {}

            vuln = data["vulnerabilities"][0]["cve"]

            # Determine CVSS score (prefer v3.1, then v3.0, then v2)
            cvss_score = "N/A"
            severity = "N/A"
            metrics = vuln.get("metrics", {})
            
            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score = cvss_data["baseScore"]
                severity = metrics["cvssMetricV31"][0].get("baseSeverity", "N/A")
            elif "cvssMetricV30" in metrics:
                cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                cvss_score = cvss_data["baseScore"]
                severity = metrics["cvssMetricV30"][0].get("baseSeverity", "N/A")
            elif "cvssMetricV2" in metrics:
                cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                cvss_score = cvss_data["baseScore"]
                # Calculate severity for CVSS v2
                if cvss_score >= 7.0:
                    severity = "HIGH"
                elif cvss_score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

            # Extract description
            description = ""
            for desc in vuln.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "").strip()
                    break

            # Extract references
            references = [ref["url"] for ref in vuln.get("references", []) if ref.get("url")]

            # Extract published and last modified dates
            published = vuln.get("published", "")
            last_modified = vuln.get("lastModified", "")
            if published:
                published = datetime.fromisoformat(published.replace("Z", "+00:00")).strftime("%Y-%m-%d")
            if last_modified:
                last_modified = datetime.fromisoformat(last_modified.replace("Z", "+00:00")).strftime("%Y-%m-%d")

            return {
                "id": cve_id,
                "cvss": cvss_score,
                "severity": severity,
                "published": published,
                "last_modified": last_modified,
                "description": description,
                "references": references[:5]
            }

        except requests.exceptions.RequestException as e:
            if status_area:
                status_area.error(f"Request failed for {cve_id}: {e}")
        except json.JSONDecodeError:
            if status_area:
                status_area.error(f"Invalid JSON response for {cve_id}")
        except Exception as e:
            if status_area:
                status_area.error(f"Error processing {cve_id}: {e}")

    if status_area:
        status_area.error(f"Failed to fetch info for {cve_id} after {tries} attempts.")
    return {}


def main():
    st.title("Vulnerability Scanner")
    st.write("Scan your target for vulnerabilities and get detailed CVE information.")
    
    # Sidebar for configuration
    st.sidebar.header("Configuration")
    max_cves = st.sidebar.slider("Maximum CVEs to process", 1, 30, 10)
    
    # Advanced options in expander
    with st.sidebar.expander("Advanced Options"):
        use_temp_files = st.checkbox("Use temporary files", value=True, 
                                   help="Use system temp directory for scan results")
        if not use_temp_files:
            xml_file = st.text_input("XML Output File", "scan.xml")
            report_file = st.text_input("Report Output File", "nvd_report.txt")
        else:
            xml_file = os.path.join(tempfile.gettempdir(), f"scan_{int(time.time())}.xml")
            report_file = os.path.join(tempfile.gettempdir(), f"report_{int(time.time())}.txt")
    
    # Check if Nmap is installed
    try:
        subprocess.run(["nmap", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        nmap_installed = True
    except FileNotFoundError:
        nmap_installed = False
    
    if not nmap_installed:
        st.error("⚠️ Nmap is not installed or not in PATH. Please install Nmap to use this application.")
        st.info("Visit https://nmap.org/download.html for installation instructions.")
        st.stop()
    
    # Input form
    with st.form("scan_form"):
        st.subheader("Target Information")
        target_ip = st.text_input("Enter target IP address or hostname:")
        
        col1, col2 = st.columns([1, 5])
        with col1:
            submit_button = st.form_submit_button("Start Scan")
        with col2:
            if submit_button and not target_ip:
                st.error("Please enter a target IP address or hostname.")
    
    # After form submission
    if submit_button and target_ip:
        if not validate_ip(target_ip):
            st.error("Please enter a valid IP address or hostname.")
            st.stop()
        
        # Create a container for scan results
        scan_container = st.container()
        
        with scan_container:
            st.subheader("Scan Progress")
            progress_bar = st.progress(0)
            status_area = st.empty()
            
            # Step 1: Run Nmap scan
            success, stdout, stderr = run_nmap_scan(target_ip, xml_file, progress_bar, status_area)
            
            if not success:
                st.error("Scan failed. Please check the error messages.")
                with st.expander("Error Details"):
                    st.code(stderr)
                st.stop()
            
            # Step 2: Extract CVEs
            progress_bar.progress(75)
            status_area.info("Extracting CVEs from scan results...")
            all_cves = extract_cves(xml_file, status_area)
            
            if not all_cves:
                progress_bar.progress(100)
                status_area.warning("No CVEs found in the scan results.")
                with st.expander("Scan Output"):
                    st.code(stdout)
                st.stop()
            
            # Show found CVEs
            status_area.success(f"Found {len(all_cves)} unique CVEs.")
            progress_bar.progress(80)
            
            # Process CVEs
            status_area.info(f"Processing up to {max_cves} CVEs...")
            cves_to_process = all_cves[:max_cves]
            
            # Display processing progress
            cve_progress_text = st.empty()
            cve_progress_bar = st.progress(0)
            cve_status = st.empty()
            
            results = []
            for idx, cve in enumerate(cves_to_process, 1):
                cve_progress_text.text(f"Processing CVE {idx}/{len(cves_to_process)}: {cve}")
                cve_progress_bar.progress(int((idx-1) / len(cves_to_process) * 100))
                cve_status.info(f"Fetching details for {cve}...")
                
                info = get_cve_info(cve, cve_status)
                if info:
                    results.append(info)
                    cve_status.success(f"Got info for {cve}: CVSS {info['cvss']} ({info['severity']})")
                
                # Sleep between API calls to respect rate limiting
                if idx < len(cves_to_process):
                    time.sleep(API_DELAY)
            
            cve_progress_bar.progress(100)
            progress_bar.progress(100)
            cve_progress_text.empty()
            cve_status.empty()
            status_area.success("Scan and analysis complete!")
            
            # Results section
            st.header("Scan Results")
            
            # Display raw scan output in expander
            with st.expander("Nmap Scan Output", expanded=False):
                st.code(stdout)
            
            if not results:
                st.warning("No CVE information was retrieved.")
                st.stop()
            
            # Convert results to DataFrame for easier manipulation
            df = pd.DataFrame(results)
            
            # Sort by CVSS score
            df['cvss_num'] = pd.to_numeric(df['cvss'], errors='coerce')
            df = df.sort_values('cvss_num', ascending=False).drop('cvss_num', axis=1)
            
            # Create summary
            st.subheader("Vulnerability Summary")
            
            col1, col2 = st.columns(2)
            
            with col1:
                # Create severity counts
                severity_counts = df['severity'].value_counts().reset_index()
                severity_counts.columns = ['Severity', 'Count']
                
                # Ensure all severity levels are present
                all_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'N/A']
                for sev in all_severities:
                    if sev not in severity_counts['Severity'].values:
                        severity_counts = pd.concat([severity_counts, pd.DataFrame({'Severity': [sev], 'Count': [0]})], ignore_index=True)
                
                # Create severity color map
                severity_color_map = {
                    'CRITICAL': '#d32f2f',
                    'HIGH': '#f57c00',
                    'MEDIUM': '#fbc02d',
                    'LOW': '#388e3c',
                    'N/A': '#9e9e9e'
                }
                
                # Set order of severities
                severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'N/A': 4}
                severity_counts['order'] = severity_counts['Severity'].map(severity_order)
                severity_counts = severity_counts.sort_values('order').drop('order', axis=1)
                
                # Create bar chart
                fig = px.bar(
                    severity_counts, 
                    x='Severity', 
                    y='Count',
                    color='Severity',
                    color_discrete_map=severity_color_map,
                    title='Vulnerabilities by Severity',
                    labels={'Count': 'Number of CVEs', 'Severity': ''}
                )
                fig.update_layout(showlegend=False)
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                # Create CVSS distribution
                fig = go.Figure()
                
                fig.add_trace(go.Box(
                    y=df['cvss_num'].dropna(),
                    name='CVSS Scores',
                    marker_color='#1e88e5',
                    boxmean=True
                ))
                
                fig.update_layout(
                    title_text='CVSS Score Distribution',
                    yaxis_title='CVSS Score',
                    yaxis=dict(
                        range=[0, 10]
                    ),
                    showlegend=False
                )
                
                st.plotly_chart(fig, use_container_width=True)
                
                # Summary stats
                st.metric("Highest CVSS Score", df['cvss'].max())
                
                # Count total by severity
                critical = len(df[df['severity'] == 'CRITICAL'])
                high = len(df[df['severity'] == 'HIGH'])
                medium = len(df[df['severity'] == 'MEDIUM'])
                low = len(df[df['severity'] == 'LOW'])
                
                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Critical", critical)
                col2.metric("High", high)
                col3.metric("Medium", medium)
                col4.metric("Low", low)
            
            # Detailed results
            st.subheader("Detailed Findings")
            
            for _, info in df.iterrows():
                severity_class = f"severity-{info['severity'].lower()}" if info['severity'] not in ['N/A', 'NONE'] else ""
                
                with st.expander(f"{info['id']} - CVSS: {info['cvss']} - {info['severity']}"):
                    st.markdown(f"""
                    ### {info['id']}
                    
                    * **CVSS Score:** <span class='{severity_class}'>{info['cvss']} ({info['severity']})</span>
                    * **Published:** {info['published']}
                    * **Last Modified:** {info['last_modified']}
                    
                    **Description:**  
                    {info['description']}
                    """, unsafe_allow_html=True)
                    
                    if info['references']:
                        st.markdown("**References:**")
                        for ref in info['references']:
                            st.markdown(f"* [{ref}]({ref})")
            
            # Export options
            st.subheader("Export Results")
            
            col1, col2 = st.columns(2)
            
            with col1:
                # Generate CSV
                csv = df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name=f"vulnerability_scan_{target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                )
            
            with col2:
                # Generate TXT report
                def generate_text_report(results, target_ip):
                    header = f"NVD CVE Report for {target_ip} - Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    report = [header, "=" * len(header), ""]
                    
                    report.append("SUMMARY")
                    report.append("-------")
                    report.append(f"Total CVEs found: {len(results)}")
                    
                    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "N/A": 0}
                    for info in results:
                        severity_counts[info['severity'] if info['severity'] in severity_counts else "N/A"] += 1
                    
                    report.append("Severity breakdown:")
                    for sev, count in severity_counts.items():
                        if count > 0:
                            report.append(f"  - {sev}: {count}")
                    report.append("\n")
                    
                    report.append("DETAILED FINDINGS")
                    report.append("=================\n")
                    
                    for info in results:
                        report.append("=" * 80)
                        report.append(f"CVE ID: {info['id']}")
                        report.append(f"CVSS Score: {info['cvss']} ({info['severity']})")
                        report.append(f"Published Date: {info['published']}")
                        report.append(f"Last Modified: {info['last_modified']}\n")
                        report.append("Description:")
                        report.append(info['description'] + "\n")
                        if info['references']:
                            report.append("References:")
                            for ref in info['references']:
                                report.append(f"  - {ref}")
                            report.append("")
                        report.append("")
                    
                    return "\n".join(report)
                
                txt_report = generate_text_report(results, target_ip)
                st.download_button(
                    label="Download TXT Report",
                    data=txt_report,
                    file_name=f"vulnerability_report_{target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain",
                )


if __name__ == "__main__":
    main()


   
   

        


