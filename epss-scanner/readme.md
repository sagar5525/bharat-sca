# EPSS Prioritizer

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.7%2B-blue)](https://www.python.org)

**EPSS Prioritizer** is a lightweight, standalone command-line tool designed to help security teams and developers prioritize software vulnerabilities based on their real-world exploit likelihood. By analyzing a Software Bill of Materials (SBOM) in SPDX format, it identifies known vulnerabilities, fetches their Exploit Prediction Scoring System (EPSS) scores, and generates a rich, actionable report that ranks risks from most to least critical.

Stop guessing which CVEs to fix first. Let EPSS Prioritizer tell you where to focus your remediation efforts.

## Why EPSS Prioritizer Stands Out

In the world of vulnerability management, not all CVEs are created equal. The Common Vulnerability Scoring System (CVSS) tells you *how bad* a vulnerability could be, but EPSS tells you *how likely* it is to be exploited in the wild. EPSS Prioritizer leverages this crucial data to provide a significant advantage:

1.  **Prioritization Based on Real-World Risk:** Instead of being overwhelmed by a long list of vulnerabilities, EPSS Prioritizer sorts them by their EPSS score (0.0 to 1.0). A CVE with a "High" CVSS score but a low EPSS score might be less urgent than a "Medium" CVSS CVE with a high EPSS score.
2.  **Actionable, Executive-Ready Reports:** The generated HTML report includes an executive summary, interactive charts, detailed CVE information, and component upgrade paths, making it easy to communicate risk to both technical and non-technical stakeholders.
3.  **SBOM-First Approach:** It integrates seamlessly into modern DevSecOps pipelines by using the industry-standard SPDX SBOM as its input. This ensures you're analyzing the exact software inventory of your project.
4.  **Rich Data Enrichment:** The report doesn't just list CVEs. It provides:
    *   **EPSS Score:** The probability of exploitation.
    *   **CVSS Score:** The technical severity.
    *   **CVE Description:** A brief summary of the vulnerability.
    *   **Latest Version:** The most recent version available for affected components.
5.  **Standalone and Simple:** Unlike full SCA tools, EPSS Prioritizer has a single, focused purpose. It's easy to install, run, and integrate.

## How EPSS Prioritizer Discovers and Prioritizes Vulnerabilities

EPSS Prioritizer uses a multi-step process to provide accurate and prioritized intelligence:

1.  **SBOM Parsing:** It reads your SPDX SBOM JSON file to extract a list of components (name, version, package manager).
2.  **Vulnerability Discovery:** For each component, it queries the [Open Source Vulnerability (OSV) database](https://osv.dev/) to find known vulnerabilities.
3.  **CVE Enrichment:** It automatically fetches critical details for each identified CVE:
    *   **EPSS Score:** From the [FIRST.org EPSS API](https://first.org/epss/).
    *   **CVSS Score & Description:** From the [NVD API](https://nvd.nist.gov/developers).
4.  **Latest Version Check:** It queries package registries (npm, PyPI) to determine the latest available version for each vulnerable component.
5.  **Prioritization:** All discovered CVEs are sorted in descending order by their EPSS score, creating a prioritized list for remediation.

## How to Use EPSS Prioritizer

### 1. Prerequisites

*   **Python 3.7 or higher:** Ensure Python is installed on your system.
*   **Required Python Packages:** Install the dependencies using pip:
    ```bash
    pip install requests beautifulsoup4
    ```

### 2. Generate an SBOM

EPSS Prioritizer requires an SPDX SBOM as input. You can generate one using various tools. If you use Bharat-SCA, you can generate it like this:
```bash
python bharat_sca.py --audit --dir /path/to/your/project --sbom-output my_project.sbom.json
```

Alternatively, use tools like syft, tern, or cyclonedx-cli.

### 3. Run the EPSS Prioritizer
Execute the scanner with your SBOM file:

```bash

python epss-scanner.py --sbom my_project.sbom.json
 ```
This will generate an epss_report.html file.

### 4. View the Report
Open the generated epss_report.html file in your web browser. The report features:

Executive Summary: A high-level overview with key statistics and charts.
Prioritized CVE List: A detailed table of all vulnerabilities, sorted by EPSS score.
Actionable Insights: For each CVE, you'll see its description, EPSS/CVSS scores, and the latest version available for the affected component.

### 5. Specify Output Options
You can customize the output format and filename:

bash


# Generate a Markdown report
python epss-scanner.py --sbom my_project.sbom.json --output-format markdown --output priorities.md

# Generate a JSON report for integration with other tools
python epss-scanner.py --sbom my_project.sbom.json --output-format json --output priorities.json

# Integrating into Your CI/CD Pipeline
Automate vulnerability prioritization by adding EPSS Prioritizer to your CI/CD workflow (e.g., GitHub Actions, GitLab CI).

Example GitHub Actions Workflow
```bash

name: EPSS Prioritization Scan

on: [push, pull_request]

jobs:
  epss-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'

      - name: Install dependencies
        run: |
          pip install requests beautifulsoup4

      - name: Generate SBOM (using syft, as an example)
        run: |
          # Install syft (or use your preferred tool)
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s --
          ./syft . -o spdx-json=sbom.spdx.json

      - name: Run EPSS Prioritizer
        run: |
          python epss-scanner.py --sbom sbom.spdx.json --output epss_report.html

      - name: Upload EPSS Report
        uses: actions/upload-artifact@v3
        with:
          name: epss-report
          path: epss_report.html
```
This workflow will generate an SBOM, run the EPSS scan on every push, and archive the prioritized report for review.

# Getting Started

1. Clone this repository or download epss-scanner.py.

2. Install the required Python packages: pip install requests beautifulsoup4.

3. Generate an SPDX SBOM for your project.

4. Run the scanner: python epss-scanner.py --sbom your_sbom.json.

5. Open epss_report.html to see your prioritized vulnerability list.

Take the guesswork out of vulnerability management. Prioritize based on real-world exploit risk with EPSS Prioritizer.
