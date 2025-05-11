# Vulnerabilities_managment_Penetration_testing


![image](https://github.com/user-attachments/assets/51d6970a-d835-445a-8ed2-8b6079cc997d)

# Vulnerability Scanner

Vulnerability Scanner is a  tool that scans a target IP address for vulnerabilities using Nmap and retrieves detailed information about identified CVEs from the National Vulnerability Database (NVD). It generates a comprehensive report that includes CVSS scores, severity levels, descriptions, and references for each CVE.

## Features

* Runs Nmap scan with the vulners script to identify vulnerabilities.
* Extracts CVE identifiers from Nmap XML output.
* Queries the NVD API for CVE details, including severity, CVSS scores, and descriptions.
* Generates a structured report with detailed findings.
* Provides severity breakdown and summary statistics.

## Prerequisites

* Python 3.8+
* Nmap ([https://nmap.org/download.html](https://nmap.org/download.html))
* Internet connection for accessing the NVD API



## Usage

Run the application using the following command:

```bash
streamlit run app.py

```

### Example Commands

* Run a full scan and generate a report:

```bash
python app.py 
```


## Output

* The output report includes a summary of vulnerabilities, severity breakdown, and detailed information for each identified CVE, including:

  * CVE ID
  * CVSS Score and Severity
  * Description
  * References
  * Published and Last Modified Dates

