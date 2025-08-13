# bharat-sca: Your Comprehensive Software Supply Chain Guardian


Bharat-SCA is not just another dependency scanner. It's a holistic risk intelligence platform designed to proactively identify and prioritize threats lurking within your open-source dependencies. We go beyond simple vulnerability lists to provide a unified risk score that combines security, legal, and maintenance risks, empowering you to make smarter, faster decisions.

**Why bharat-sca Stands Out?**

In a crowded field of security tools, Bharat-SCA distinguishes itself with a unique combination of depth, intelligence, and actionable insights:

**Holistic Risk Scoring (0-100):**

We don't just tell you if a package has a CVE. We tell you how risky it truly is. Our proprietary risk score is calculated by weighing:

**Security Severity (CVSS):**

The technical impact of known vulnerabilities.

**Exploitation Likelihood (EPSS):** 

The probability that a vulnerability will be actively exploited in the wild (a critical factor often overlooked).

**Legal & License Risk:**

Automatically detects and categorizes licenses (e.g., GPL, AGPL) that could force you to open-source your proprietary code, and provides explicit violation details explaining the legal implications.

**Maintenance Health:** 

Flags dependencies that are abandoned or infrequently updated, which are prime candidates for future security issues.

**Proactive, Actionable Intelligence:** 

Bharat-SCA doesn't just dump data. It delivers insights: Explicit License Violation Details: Know exactly why a license is a problem. (e.g., "Package uses GPL-3.0, which is a strong copyleft license. This may require releasing your source code under the same license.").

**Source File Attribution:** 

The report clearly shows which file (e.g., package.json, pom.xml) declared each vulnerable component, making it easy to trace and remediate.

**Filterable, Interactive Reports:** 

Our rich HTML dashboard allows you to filter dependencies by risk level, package type, or vulnerability severity, so you can focus on what matters most.

**Multi-Ecosystem Support: Analyze dependencies across multiple languages and ecosystems, including:**
JavaScript/Node.js (npm)
Python (PyPI)
Java (Maven)
Go (Go Modules)
(Extensible to others)


**SBOM Generation (SPDX):** 

Generate a standardized Software Bill of Materials (SBOM) in the SPDX format. This is essential for compliance, audits, and integrating with other supply chain security tools.

**Built for Automation:** 

Designed from the ground up to be a seamless part of your CI/CD pipeline, ensuring continuous security.

How Bharat-SCA Discovers and Prioritizes Vulnerabilities
Bharat-SCA uses a sophisticated, multi-source approach to ensure comprehensive and accurate vulnerability discovery:

Primary Source - OSV.dev: We query the Open Source Vulnerability (OSV) database, a community-driven, cross-ecosystem vulnerability source, for the most up-to-date vulnerability data.
Enhanced Context - NVD & EPSS: We enrich the vulnerability data by:
Fetching precise CVSS scores from the National Vulnerability Database (NVD).
Integrating Exploit Prediction Scoring System (EPSS) scores to understand the real-world likelihood of exploitation.
Scraping advisory details from sources like GitHub to get accurate CVE IDs and severity levels.
Smart Risk Calculation: By combining the CVSS score (impact) with the EPSS score (likelihood), we can prioritize a "High" severity vulnerability with a 70% chance of being exploited over a "Critical" vulnerability with only a 1% chance, focusing your team's efforts where they are most needed.

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



**Integrating Bharat-SCA into Your CI/CD Pipeline**

The true power of Bharat-SCA is realized when it's automated. Here's how you can integrate it into your build pipeline (e.g., GitHub Actions, GitLab CI, Jenkins) to create a robust security gate:


**Getting Started**

1. Clone this repository.
2. Install the required Python packages: pip install requests beautifulsoup4 toml.
3. Run a scan: python bharat_sca.py --audit --dir /path/to/your/project --output report.html.
4. Open report.html to see your comprehensive dependency risk analysis!


**How to request NVD API Key**

Go to https://nvd.nist.gov/developers/request-an-api-key, fill in the form and request for key.

Take control of your software supply chain today with bharat-sca.

For Queries / Feedback write to srahalkar@proton.me

If you find this tool useful, give a shout out on LinkedIn - https://www.linkedin.com/in/sagarrahalkar/ 



