# bharat-sca
Bharat-SCA: Holistic open-source dependency risk analysis for security, legal (license), and maintenance health. It effectively prioritizes risks using CVSS, EPSS, and custom scoring. Generates interactive HTML reports, SBOMs, and integrates into build pipelines.

Tired of hidden landmines in your open-source dependencies? What if you could instantly see not just if a package has vulnerabilities, but how risky it truly is—considering security, legal obligations, and even how well it's maintained?

**Introducing bharat-sca**: Your comprehensive, proactive defense system for your software supply chain.


**What is this tool, and why should I care?**

This isn't just another vulnerability scanner that dumps a list of CVEs. It's a sophisticated analysis engine designed to answer the deeper questions:

-"Is this vulnerable package a real threat to my application?"
-"Could using this library force me to open-source my entire project?"
-"Is this critical dependency slowly being abandoned?"
By combining data from multiple authoritative sources (OSV, NVD, First.org EPSS, npm, PyPI) and applying intelligent risk scoring, this tool gives you a single, prioritized view of your dependency risks.


**Key Features: What Makes This Different?**

**🔍 Holistic Risk Scoring**

Forget simple vulnerability lists. Our core feature is a calculated Risk Score (0-100) for each dependency, combining:

**Security Vulnerabilities:** CVSS scores tell you severity, but we go further by incorporating EPSS (Exploit Prediction Scoring System). This tells you the probability a vulnerability will be exploited in the wild. A high CVSS score is bad, but a high EPSS score means it's likely to be attacked now.
License Compliance & Legal Risk: Automatically detects licenses and flags permissive (MIT, Apache-2.0), weak copyleft (MPL-2.0), and strong copyleft (GPL-3.0, AGPL-3.0) licenses. Understand the legal implications before you integrate.

**Maintenance Health:** 

How old is the latest release? Frequent updates often mean active maintenance, while years of inactivity signal potential abandonment.

**📊 Rich, Actionable Reports**

Interactive HTML Dashboard: A beautiful, self-contained HTML report perfect for sharing. Easily identify your highest-risk dependencies at a glance.
Filterable Tables: Quickly slice through your dependencies by risk level, package type, or specific vulnerabilities. No more sifting through pages of irrelevant data.
Dedicated License Violation Details: See exactly which packages pose legal risks and why (e.g., "Package uses GPL-3.0, which is a strong copyleft license. This may require releasing your source code under the same license.").

**Markdown & JSON Output:** 

Need to integrate findings into other systems or documentation? Generate clean Markdown summaries or detailed JSON data for further processing.

**🧾 Software Bill of Materials (SBOM) Generation**

SPDX Standard: Generate a standardized Software Bill of Materials (SBOM) in SPDX format. This is crucial for compliance, audits, and deeper supply chain analysis using other tools.

**🌐 Multi-Ecosystem Support**

npm (JavaScript/Node.js)
PyPI (Python)
(Easily extensible to Maven, Go, etc.)

**🚀 Smart Data Gathering**

Multiple Data Sources: Doesn't rely on a single API. It intelligently fetches vulnerability details from OSV, cross-references with NVD for CVSS scores, and checks EPSS for exploit likelihood.
Web Scraping Fallbacks: If an API is temporarily unavailable or lacks specific data (like CVSS scores), it intelligently falls back to scraping relevant information from authoritative web pages (like NVD NIST).
🔧 Easy Integration & Configuration

**Simple CLI:** 

Scan your project with a single command: python dependency_radar.py --audit --dir ./my_project.
NVD API Key Support: Configure an NVD API key to significantly increase your request rate limits, ensuring smooth scans for larger projects.


**Who Benefits From This Tool?**

**🛡️ Security Teams (Blue Team)**

Proactive Defense: Identify and prioritize risks before they are exploited. Focus remediation efforts on the highest threats identified by Risk Score and EPSS.
Compliance & Governance: Ensure all dependencies meet organizational licensing policies. The explicit violation details make it easy to justify rejecting a library.
Incident Response Context: When investigating a security incident, quickly check if any recent vulnerabilities (especially high EPSS ones) in your dependencies could be the root cause.

**⚔️ Red Teams / Penetration Testers**

Attack Surface Expansion: Use the list of high-risk, vulnerable dependencies as a potential attack vector during assessments. Packages with high EPSS scores are excellent candidates for exploit research or chaining with other weaknesses.
Supply Chain Reconnaissance: Understand the potential weaknesses in a target application's supply chain, providing context for more sophisticated attacks.

**👷 Developers & DevOps Engineers**

Informed Decision Making: Before adding a new library, run a scan to understand its inherent risks. Make better choices based on data, not just popularity.
Build Pipeline Integration: Crucially, integrate the Radar into your CI/CD pipeline to automatically gate builds based on risk thresholds. 

**🧑‍💼 Legal & Procurement Teams**

License Audits: Easily audit projects for license compliance. The SBOM and license violation reports provide clear evidence for legal reviews.
Vendor Risk Assessment: Evaluate the health and risk profile of third-party software components used by vendors or partners.

**Getting Started**

Clone this repository.

Install dependencies: pip install requests beautifulsoup4 toml, pip install -r requirements.txt

Run the scanner: python bharat-sca-1.0.py --audit --dir /path/to/your/project --output report.html

Explore the generated report.html to see your dependency risks!

Dive in, and take control of your software supply chain risks today!
