import re
import requests
import time
import xml.etree.ElementTree as ET
import json
import os
import subprocess
import argparse
from datetime import datetime

# NVD API endpoint
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

MAX_CVES = 10
API_DELAY = 6  # Reduced from 10 to improve user experience


def run_nmap_scan(target_ip, output_file="scan.xml"):
    """
    Run an Nmap scan with the vulners script against the target IP
    and save the output to an XML file.
    """
    print(f"[+] Starting Nmap scan on {target_ip}...")
    
    try:
        # Run Nmap with vulners script and save XML output
        cmd = [
            "nmap", 
            "-sV",                   # Version detection
            "--script=vulners",      # Use vulners script for vulnerability detection
            "-oX", output_file,      # Output to XML
            target_ip
        ]
        
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        
        print(f"[+] Scan completed successfully. Results saved to {output_file}")
        print("\n[*] Nmap scan summary:")
        # Print a summary of the scan output
        for line in process.stdout.splitlines():
            if any(keyword in line for keyword in ["Nmap scan report", "Host is", "PORT", "open", "filtered"]):
                print(f"  {line}")
        
        return True
    
    except subprocess.CalledProcessError as e:
        print(f"[-] Error during Nmap scan: {e}")
        print(f"[-] Error output: {e.stderr}")
        return False
    except FileNotFoundError:
        print("[-] Error: Nmap is not installed or not in PATH.")
        print("[-] Please install Nmap (https://nmap.org/download.html) and try again.")
        return False


def extract_cves(xml_file: str) -> list:
    """
    Parse XML file and return a sorted list of unique CVE IDs.
    """
    if not os.path.exists(xml_file):
        print(f"[-] XML file '{xml_file}' not found.")
        return []
    
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        pattern = re.compile(r'CVE-\d{4}-\d{4,7}')
        cves = set()
        
        # Check if any hosts were scanned
        hosts = root.findall(".//host")
        if not hosts:
            print("[-] No hosts found in scan results.")
            return []
            
        for elem in root.iter():
            if elem.text:
                for match in pattern.findall(elem.text):
                    cves.add(match)
        
        return sorted(cves)
    except ET.ParseError:
        print(f"[-] Failed to parse '{xml_file}'. The file may be corrupted or empty.")
        return []
    except Exception as e:
        print(f"[-] Error extracting CVEs: {e}")
        return []


def get_cve_info(cve_id: str) -> dict:
    """
    Get CVE information from NVD API.
    """
    params = {"cveId": cve_id}
    tries = 3
    for attempt in range(tries):
        try:
            if attempt > 0:
                print(f"  [*] Retrying... (attempt {attempt+1}/{tries})")
                time.sleep(API_DELAY)
            
            print(f"  [*] Querying NVD API for {cve_id}...")
            resp = requests.get(NVD_API_URL, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()

            if data.get("totalResults", 0) == 0 or not data.get("vulnerabilities"):
                print(f"  [-] No information found for {cve_id}")
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
            print(f"  [-] Request failed for {cve_id}: {e}")
        except json.JSONDecodeError:
            print(f"  [-] Invalid JSON response for {cve_id}")
        except Exception as e:
            print(f"  [-] Error processing {cve_id}: {e}")

    print(f"  [-] Failed to fetch info for {cve_id} after {tries} attempts.")
    return {}


def generate_report(results, output_file="nvd_report.txt", target_ip=None):
    """
    Generate a detailed report of the CVE findings.
    """
    if not results:
        print("[-] No CVE information to report.")
        return False
    
    try:
        with open(output_file, "w") as f:
            header = f"NVD CVE Report - Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            if target_ip:
                header = f"NVD CVE Report for {target_ip} - Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            
            f.write(header + "\n" + "=" * len(header) + "\n\n")

            # Sort results by CVSS score (highest first)
            sorted_results = sorted(
                results, 
                key=lambda x: float(x['cvss']) if x['cvss'] != 'N/A' else 0,
                reverse=True
            )

            # Add a summary section
            f.write("SUMMARY\n")
            f.write("-------\n")
            f.write(f"Total CVEs found: {len(sorted_results)}\n")
            
            # Count by severity
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "N/A": 0}
            for info in sorted_results:
                severity_counts[info['severity'] if info['severity'] in severity_counts else "N/A"] += 1
            
            f.write("Severity breakdown:\n")
            for sev, count in severity_counts.items():
                if count > 0:
                    f.write(f"  - {sev}: {count}\n")
            f.write("\n\n")

            # Detailed findings
            f.write("DETAILED FINDINGS\n")
            f.write("=================\n\n")
            
            for info in sorted_results:
                f.write("=" * 80 + "\n")
                f.write(f"CVE ID: {info['id']}\n")
                f.write(f"CVSS Score: {info['cvss']} ({info['severity']})\n")
                f.write(f"Published Date: {info['published']}\n")
                f.write(f"Last Modified: {info['last_modified']}\n\n")
                f.write("Description:\n")
                f.write(info['description'] + "\n\n")
                if info['references']:
                    f.write("References:\n")
                    for ref in info['references']:
                        f.write(f"  - {ref}\n")
                    f.write("\n")
                f.write("\n")

        print(f"[+] Report generated successfully: {output_file}")
        return True
    
    except Exception as e:
        print(f"[-] Error generating report: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Scan a target for vulnerabilities and generate a CVE report")
    parser.add_argument("target", help="Target IP address or hostname to scan")
    parser.add_argument("-o", "--output", default="nvd_report.txt", help="Output report filename (default: nvd_report.txt)")
    parser.add_argument("-m", "--max-cves", type=int, default=MAX_CVES, help=f"Maximum CVEs to process (default: {MAX_CVES})")
    parser.add_argument("-x", "--xml", default="scan.xml", help="XML output filename for Nmap scan (default: scan.xml)")
    parser.add_argument("--skip-scan", action="store_true", help="Skip Nmap scan and use existing XML file")
    
    args = parser.parse_args()
    
    xml_file = args.xml
    output_file = args.output
    max_cves = args.max_cves
    
    print("\nEnhanced CVE Scanner")
    print("===================\n")
    
    # Step 1: Run Nmap scan with vulners script
    if not args.skip_scan:
        if not run_nmap_scan(args.target, xml_file):
            print("[-] Scan failed. Exiting.")
            return
    else:
        print(f"[*] Skipping scan, using existing XML file: {xml_file}")
    
    # Step 2: Extract CVEs from scan results
    print(f"\n[+] Extracting CVEs from '{xml_file}'...")
    all_cves = extract_cves(xml_file)
    if not all_cves:
        print("[-] No CVEs found in the XML file. Exiting.")
        return

    # Print all extracted CVEs to the terminal
    print(f"[+] Total unique CVEs found: {len(all_cves)}")
    print("\n[+] Found the following CVEs:")
    print("-" * 50)
    for i, cve in enumerate(all_cves, 1):
        print(f"{i}. {cve}")
    print("-" * 50)

    # Step 3: Process CVEs through NVD API
    cves_to_process = all_cves[:max_cves]
    print(f"\n[+] Processing first {len(cves_to_process)} CVEs (max set to {max_cves}).")
    
    if not cves_to_process:
        print("[-] No CVEs to process. Exiting.")
        return

    results = []
    for idx, cve in enumerate(cves_to_process, 1):
        print(f"\n[+] ({idx}/{len(cves_to_process)}) Processing {cve}...")
        info = get_cve_info(cve)
        if info:
            results.append(info)
            print(f"  [+] CVSS Score: {info['cvss']} ({info['severity']})")
        
        # Sleep between API calls to respect rate limiting
        if idx < len(cves_to_process):
            print(f"  [*] Waiting {API_DELAY} seconds before next API call...")
            time.sleep(API_DELAY)

    # Step 4: Generate the report
    print(f"\n[+] Writing report to '{output_file}'...")
    generate_report(results, output_file, args.target)
    
    print("\n[+] Scan and analysis complete!")
    print(f"[+] Report saved to: {output_file}")
    
    # Print a summary of severity
    if results:
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "N/A": 0}
        for info in results:
            severity_counts[info['severity'] if info['severity'] in severity_counts else "N/A"] += 1
        
        print("\n[+] Vulnerability summary:")
        for sev, count in severity_counts.items():
            if count > 0:
                print(f"  - {sev}: {count}")


if __name__ == "__main__":
    main()