import re
import requests
import time
import xml.etree.ElementTree as ET
import json
from datetime import datetime

# NVD API endpoint
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def extract_cves(xml_file: str) -> list:
    """
    Parse scan.xml and return a sorted list of unique CVE IDs.
    """
    tree = ET.parse(xml_file)
    root = tree.getroot()
    pattern = re.compile(r'CVE-\d{4}-\d{4,7}')
    cves = set()
    for elem in root.iter():
        if elem.text:
            for match in pattern.findall(elem.text):
                cves.add(match)
    return sorted(cves)

def get_cve_info(cve_id: str) -> dict:
    """
    Get CVE information from NVD API.
    """
    params = {"cveId": cve_id}
    tries = 3
    
    for attempt in range(tries):
        try:
            # NVD recommends adding a delay between requests (at least 6 per minute)
            if attempt > 0:
                time.sleep(10)  # Wait longer between retries
                
            print(f"  [*] Sending request for {cve_id}...")
            resp = requests.get(NVD_API_URL, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            
            # Check if we have results
            if data.get("totalResults", 0) == 0 or not data.get("vulnerabilities"):
                print(f"  [-] No data found for {cve_id}")
                return {}
            
            # Extract info from the first vulnerability
            vuln = data["vulnerabilities"][0]["cve"]
            
            # Extract CVSS score - prioritize CVSS 3.x over 2.0
            cvss_score = "N/A"
            cvss_metrics = vuln.get("metrics", {})
            if "cvssMetricV31" in cvss_metrics:
                cvss_score = cvss_metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV30" in cvss_metrics:
                cvss_score = cvss_metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in cvss_metrics:
                cvss_score = cvss_metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
            
            # Extract description (English preferred)
            description = ""
            for desc in vuln.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Build references list
            references = []
            for ref in vuln.get("references", []):
                if ref.get("url"):
                    references.append(ref["url"])
            
            # Extract published and last modified dates
            published = vuln.get("published", "")
            last_modified = vuln.get("lastModified", "")
            
            # Format dates for readability if they exist
            if published:
                published = datetime.fromisoformat(published.replace("Z", "+00:00")).strftime("%Y-%m-%d")
            if last_modified:
                last_modified = datetime.fromisoformat(last_modified.replace("Z", "+00:00")).strftime("%Y-%m-%d")
            
            return {
                "id": cve_id,
                "description": description,
                "cvss": cvss_score,
                "published": published,
                "last_modified": last_modified,
                "references": references[:5]  # Limit to first 5 references
            }
            
        except requests.exceptions.ReadTimeout:
            print(f"  [-] Timeout on {cve_id}. Retrying ({attempt + 1}/{tries})...")
        except requests.exceptions.RequestException as e:
            print(f"  [-] Request failed for {cve_id}: {e}")
        except json.JSONDecodeError:
            print(f"  [-] Invalid JSON response for {cve_id}")
        except Exception as e:
            print(f"  [-] Error processing {cve_id}: {e}")
    
    print(f"  [-] Failed to fetch {cve_id} after {tries} attempts.")
    return {}

def main():
    xml_file = "scan.xml"  # Replace with your actual XML file path
    output_file = "nvd_report.txt"
    max_cves = 10  # Limit to processing only 10 CVEs
    
    # Extract CVEs from XML
    print("[+] Extracting CVEs from XML file...")
    all_cves = extract_cves(xml_file)
    
    # Print all extracted CVEs to the shell for demonstration
    print("\n[+] Found the following CVEs in the scan:")
    print("-" * 50)
    for i, cve in enumerate(all_cves):
        print(f"{i+1}. {cve}")
    print("-" * 50)
    
    # Limit to first 10 CVEs for processing
    cves = all_cves[:max_cves]
    print(f"\n[+] Found {len(all_cves)} unique CVEs, processing first {len(cves)}")
    
    if not cves:
        print("[-] No CVEs found in the XML file.")
        return
    
    # Get details for each CVE
    results = []
    for i, cve_id in enumerate(cves):
        print(f"[+] Processing {cve_id} ({i+1}/{len(cves)})...")
        info = get_cve_info(cve_id)
        if info:
            results.append(info)
        # Add rate limiting to avoid API restrictions (NVD allows ~6 req/minute for unauthenticated users)
        time.sleep(10)  # This is conservative, adjust if needed
    
    # Write results to file
    print(f"[+] Writing {len(results)} results to {output_file}...")
    with open(output_file, "w") as f:
        f.write(f"CVE Report (Limited to {max_cves} CVEs)\n")
        f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        if not results:
            f.write("No CVE data found")
        else:
            for info in results:
                f.write(f"CVE: {info['id']}\n")
                f.write(f"CVSS: {info['cvss']}\n")
                f.write(f"Published: {info['published']}\n")
                f.write(f"Last Modified: {info['last_modified']}\n")
                f.write(f"Description: {info['description']}\n")
                if info['references']:
                    f.write("References:\n")
                    for ref in info['references']:
                        f.write(f"  - {ref}\n")
                f.write("-" * 80 + "\n\n")
    
    print("[+] Done!")

if __name__ == "__main__":
    main()