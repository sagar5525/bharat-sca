#!/usr/bin/env python3
"""
Dependency License & Risk Radar (Bharat-SCA)
CLI tool that combines security, legal, and maintenance risk analysis.
Supports npm, PyPI, Maven, Gradle, and Go.
"""
import json
import sys
import os
import subprocess
import requests
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
import toml
import xml.etree.ElementTree as ET
# Import BeautifulSoup for web scraping
from bs4 import BeautifulSoup
import re
import uuid # For SBOM UUID

class DependencyRadar:
    def __init__(self, nvd_api_key: Optional[str] = None):
        self.risky_licenses = {
            'GPL-2.0', 'GPL-3.0', 'AGPL-3.0', 'LGPL-3.0',
            'GPL-2.0-only', 'GPL-3.0-only', 'AGPL-3.0-only'
        }
        self.warning_licenses = {
            'MPL-2.0', 'CDDL-1.0', 'EPL-1.0', 'EPL-2.0'
        }
        # Store the NVD API key
        self.nvd_api_key = nvd_api_key

    def parse_package_json(self, filepath: str) -> List[Dict[str, str]]:
        """Parse npm package.json dependencies"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            deps = []
            # Handle both dependencies and devDependencies
            for dep_type in ['dependencies', 'devDependencies']:
                if dep_type in data: # FIXED: Missing condition check
                    for name, version in data[dep_type].items():
                        deps.append({
                            'name': name,
                            'version': version,
                            'type': 'npm',
                            'source_file': filepath # Add source file path
                        })
            return deps
        except Exception as e:
            print(f"Error parsing {filepath}: {e}")
            return []

    def parse_requirements_txt(self, filepath: str) -> List[Dict[str, str]]:
        """Parse Python requirements.txt dependencies"""
        deps = []
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Handle various formats: package==1.0.0, package>=1.0, etc.
                        if '==' in line:
                            name, version = line.split('==', 1)
                        elif '>=' in line:
                            name, version = line.split('>=', 1)
                        elif '<=' in line:
                            name, version = line.split('<=', 1)
                        else:
                            name, version = line, 'latest'
                        deps.append({
                            'name': name.strip(),
                            'version': version.strip(),
                            'type': 'pypi',
                            'source_file': filepath # Add source file path
                        })
            return deps
        except Exception as e:
            print(f"Error parsing {filepath}: {e}")
            return []

    def parse_pyproject_toml(self, filepath: str) -> List[Dict[str, str]]:
        """Parse Python pyproject.toml dependencies"""
        try:
            with open(filepath, 'r') as f:
                data = toml.load(f)
            deps = []
            # Handle project dependencies
            project_deps = data.get('project', {}).get('dependencies', [])
            for dep in project_deps:
                if '==' in dep:
                    name, version = dep.split('==', 1)
                elif '>=' in dep:
                    name, version = dep.split('>=', 1)
                elif '<=' in dep:
                    name, version = dep.split('<=', 1)
                else:
                    name, version = dep, 'latest'
                deps.append({
                    'name': name.strip(),
                    'version': version.strip(),
                    'type': 'pypi',
                    'source_file': filepath # Add source file path
                })
            # Handle optional dependencies (extras)
            optional_deps = data.get('project', {}).get('optional-dependencies', {})
            for extra_name, extra_deps in optional_deps.items():
                for dep in extra_deps:
                    if '==' in dep:
                        name, version = dep.split('==', 1)
                    elif '>=' in dep:
                        name, version = dep.split('>=', 1)
                    elif '<=' in dep:
                        name, version = dep.split('<=', 1)
                    else:
                        name, version = dep, 'latest'
                    deps.append({
                        'name': name.strip(),
                        'version': version.strip(),
                        'type': 'pypi',
                        'extra': extra_name,
                        'source_file': filepath # Add source file path
                    })
            return deps
        except Exception as e:
            print(f"Error parsing {filepath}: {e}")
            return []

    def parse_pom_xml(self, filepath: str) -> List[Dict[str, str]]:
        """Parse Maven pom.xml dependencies (direct dependencies only)"""
        deps = []
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()

            # Handle namespace if present (common in pom.xml)
            namespace = {'mvn': 'http://maven.apache.org/POM/4.0.0'}
            ns = namespace if root.tag.startswith('{') else {}

            dependencies = root.find('mvn:dependencies', ns)
            if dependencies is not None:
                for dep in dependencies.findall('mvn:dependency', ns):
                    group_id_elem = dep.find('mvn:groupId', ns)
                    artifact_id_elem = dep.find('mvn:artifactId', ns)
                    version_elem = dep.find('mvn:version', ns)

                    if group_id_elem is not None and artifact_id_elem is not None:
                        group_id = group_id_elem.text
                        artifact_id = artifact_id_elem.text
                        # Combine group_id and artifact_id for Maven package name convention used by OSV
                        name = f"{group_id}:{artifact_id}"
                        version = version_elem.text if version_elem is not None else "latest"
                        deps.append({
                            'name': name,
                            'version': version,
                            'type': 'maven',
                            'source_file': filepath # Add source file path
                        })
            return deps
        except ET.ParseError as e:
            print(f"Error parsing XML in {filepath}: {e}")
            return deps
        except Exception as e:
            print(f"Error parsing {filepath}: {e}")
            return deps

    def parse_build_gradle(self, filepath: str) -> List[Dict[str, str]]:
         """Parse basic Groovy build.gradle dependencies (direct dependencies only, simple format)"""
         # Note: This is a very basic parser and will not handle complex Gradle files with plugins, variables, etc.
         deps = []
         try:
             with open(filepath, 'r') as f:
                 content = f.read()

             # Very basic regex to find 'implementation' or 'compile' dependencies
             # Matches lines like: implementation 'group:name:version'
             # or compile "group:name:version"
             dep_pattern = re.compile(
                 r"(implementation|api|compile|runtimeOnly)\s+['\"]([^:'\"]+):([^:'\"]+):([^:'\"]+)['\"]",
                 re.MULTILINE
             )
             matches = dep_pattern.findall(content)
             for match in matches:
                 # match[1] = group, match[2] = artifact, match[3] = version
                 name = f"{match[1]}:{match[2]}"
                 version = match[3]
                 # Gradle uses 'gradle' type for OSV, though 'maven' might also work depending on source
                 deps.append({
                     'name': name,
                     'version': version,
                     'type': 'gradle', # Or 'maven'?
                     'source_file': filepath # Add source file path
                 })
             return deps
         except Exception as e:
             print(f"Error parsing {filepath}: {e}")
             return deps

    def parse_go_mod(self, filepath: str) -> List[Dict[str, str]]:
        """Parse Go go.mod dependencies (direct dependencies only)"""
        deps = []
        try:
            with open(filepath, 'r') as f:
                lines = f.readlines()

            # Find the require section
            in_require = False
            for line in lines:
                line = line.strip()
                if line == "require (":
                    in_require = True
                    continue
                elif line == ")" and in_require:
                    in_require = False
                    continue

                if in_require and line:
                    # Split the line: module/path version
                    parts = line.split()
                    if len(parts) >= 2:
                        name = parts[0]
                        version = parts[1]
                        deps.append({
                            'name': name,
                            'version': version,
                            'type': 'go',
                            'source_file': filepath # Add source file path
                        })
                elif line.startswith("require ") and not line.endswith("("):
                     # Handle single line require: require module/path v1.2.3
                     parts = line.split()
                     if len(parts) >= 3:
                         name = parts[1]
                         version = parts[2]
                         deps.append({
                             'name': name,
                             'version': version,
                             'type': 'go',
                             'source_file': filepath # Add source file path
                         })
            return deps
        except Exception as e:
            print(f"Error parsing {filepath}: {e}")
            return deps

    def parse_go_sum(self, filepath: str) -> List[Dict[str, str]]:
        """Parse Go go.sum to get ALL modules and versions (including transitive)"""
        deps = []
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        # Format: module/path version/go.mod-hash
                        parts = line.split()
                        if len(parts) >= 2:
                            name_version = parts[0] + " " + parts[1]
                            # Split name and version
                            mod_parts = parts[1].rsplit('-', 1) # Split on last '-'
                            if len(mod_parts) == 2 and mod_parts[1].startswith('go'):
                                # Handle cases like v1.2.3-go.mod
                                version = mod_parts[0]
                            else:
                                # Handle standard cases like v1.2.3
                                version = parts[1]

                            deps.append({
                                'name': parts[0],
                                'version': version,
                                'type': 'go',
                                'source_file': filepath # Add source file path (go.sum)
                            })
            return deps
        except Exception as e:
            print(f"Error parsing {filepath}: {e}")
            return deps

    def get_osv_vulnerabilities(self, package_name: str, version: str, package_type: str) -> List[Dict]:
        """Query OSV database for vulnerabilities"""
        try:
            # OSV API endpoint
            url = "https://api.osv.dev/v1/query"
            # Map package types to ecosystems
            ecosystem_map = {
                'npm': 'npm',
                'pypi': 'PyPI',
                'maven': 'Maven', # Maven for pom.xml
                'gradle': 'Maven', # Gradle often resolves to Maven ecosystem in OSV
                'go': 'Go'
            }
            ecosystem = ecosystem_map.get(package_type, package_type)
            payload = {
                "package": {
                    "name": package_name,
                    "ecosystem": ecosystem
                },
                "version": version
            }
            response = requests.post(url, json=payload, timeout=15)
            if response.status_code == 200:
                data = response.json()
                return data.get('vulns', [])
            else:
                print(f"OSV API error for {package_name} ({version}): {response.status_code}")
                return []
        except Exception as e:
            print(f"Error fetching OSV data for {package_name}: {e}")
            return []

    def get_epss_score(self, cve_id: str) -> Optional[float]:
        """Get EPSS score for a CVE"""
        try:
            # Try First.org API first
            url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and len(data['data']) > 0:
                    return float(data['data'][0]['epss'])
            # Fallback to local calculation if needed
            return None
        except Exception as e:
            # Don't print error for EPSS - many CVEs don't have EPSS data
            # print(f"Error fetching EPSS for {cve_id}: {e}")
            return None

    def get_nvd_cvss_score(self, cve_id: str) -> Optional[float]:
        """Get CVSS score from NVD for a CVE using the API key if available"""
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            headers = {}
            # Add the API key to the headers if provided
            if self.nvd_api_key:
                headers['apiKey'] = self.nvd_api_key

            response = requests.get(url, timeout=15, headers=headers)
            if response.status_code == 200:
                data = response.json()
                if 'vulnerabilities' in data and len(data['vulnerabilities']) > 0:
                    vuln = data['vulnerabilities'][0]
                    metrics = vuln.get('cve', {}).get('metrics', {})
                    # Try CVSS v3.1 first
                    if 'cvssMetricV31' in metrics:
                        return float(metrics['cvssMetricV31'][0]['cvssData']['baseScore'])
                    # Try CVSS v3.0
                    elif 'cvssMetricV30' in metrics:
                        return float(metrics['cvssMetricV30'][0]['cvssData']['baseScore'])
                    # Try CVSS v2.0
                    elif 'cvssMetricV2' in metrics:
                        return float(metrics['cvssMetricV2'][0]['cvssData']['baseScore'])
            elif response.status_code == 403:
                 print(f"NVD API access forbidden for {cve_id}. Check API key validity or rate limits.")
            elif response.status_code == 404:
                 print(f"NVD API reports CVE {cve_id} not found.")
            else:
                 print(f"NVD API error for {cve_id}: {response.status_code}")
            return None
        except requests.exceptions.RequestException as e:
             print(f"Network error fetching NVD data for {cve_id}: {e}")
             return None
        except Exception as e:
            print(f"Error fetching NVD data for {cve_id}: {e}")
            return None

    def get_nvd_cvss_score_from_webpage(self, cve_id: str) -> Optional[float]:
        """Scrape CVSS base score from the NVD webpage for a CVE"""
        try:
            url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            # Add a User-Agent header, as some sites block requests without it
            headers = {'User-Agent': 'Bharat-SCA/1.0'}
            response = requests.get(url, timeout=15, headers=headers)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                # --- Specific Target: data-testid="vuln-cvss3-panel-score" ---
                # Find the element with the specific data-testid for the CVSS3 panel score container
                cvss3_panel_score_container = soup.find(attrs={"data-testid": "vuln-cvss3-panel-score"})
                if cvss3_panel_score_container:
                    # The score itself might be within a child element.
                    # Look for the span containing the actual score value.
                    score_span = cvss3_panel_score_container.find('span') # Find the first <span> inside
                    if score_span:
                        score_text = score_span.get_text(strip=True)
                        if score_text:
                            # Extract the numerical part (e.g., "7.5" from "7.5 HIGH")
                            match = re.search(r"(\d+\.\d+)", score_text)
                            if match:
                                return float(match.group(1))
                    # Fallback: If no span found, try getting text directly from the container
                    container_text = cvss3_panel_score_container.get_text(strip=True)
                    if container_text:
                         match = re.search(r"(\d+\.\d+)", container_text)
                         if match:
                             return float(match.group(1))
                # --- Fallback: data-testid="vuln-cvss2-panel-score" ---
                # If CVSS v3 not found, try the specific selector for CVSS v2
                cvss2_panel_score_container = soup.find(attrs={"data-testid": "vuln-cvss2-panel-score"})
                if cvss2_panel_score_container:
                     # Apply the same logic for CVSS2
                    score_span = cvss2_panel_score_container.find('span')
                    if score_span:
                        score_text = score_span.get_text(strip=True)
                        if score_text:
                             match = re.search(r"(\d+\.\d+)", score_text)
                             if match:
                                 return float(match.group(1))
                    container_text = cvss2_panel_score_container.get_text(strip=True)
                    if container_text:
                         match = re.search(r"(\d+\.\d+)", container_text)
                         if match:
                             return float(match.group(1))
                # --- Even More General Fallback: Find "Base Score" text ---
                # If the specific test IDs didn't work, fall back to the general method
                base_score_labels = soup.find_all(string=re.compile(r"Base Score", re.IGNORECASE))
                for label in base_score_labels:
                    parent = label.parent
                    # Check siblings for the score
                    for sibling in parent.next_siblings:
                        if sibling.name:
                            sibling_text = sibling.get_text(strip=True)
                            match = re.search(r"(\d+\.\d+)", sibling_text)
                            if match:
                                score_candidate = match.group(1)
                                try:
                                    return float(score_candidate)
                                except ValueError:
                                    continue
                        elif isinstance(sibling, str):
                            stripped_text = sibling.strip()
                            match = re.search(r"(\d+\.\d+)", stripped_text)
                            if match:
                                score_candidate = match.group(1)
                                try:
                                    return float(score_candidate)
                                except ValueError:
                                    continue
                    # Check parent text
                    parent_text = parent.get_text(strip=True)
                    match = re.search(r"Base Score.*?(\d+\.\d+)", parent_text, re.IGNORECASE | re.DOTALL)
                    if match:
                        try:
                            return float(match.group(1))
                        except ValueError:
                            continue
            print(f"CVSS score not found on NVD page for {cve_id} (URL: {url})")
            return None
        except requests.exceptions.RequestException as e:
            print(f"Network error fetching NVD page for {cve_id}: {e}")
            return None
        except Exception as e:
            print(f"Error scraping NVD page for {cve_id}: {e}")
            return None

    def get_osv_vulnerability_details(self, vuln_id: str) -> Dict[str, Any]:
        """Fetch detailed vulnerability information from OSV.dev"""
        try:
            url = f"https://api.osv.dev/v1/vulns/{vuln_id}"
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Failed to fetch OSV details for {vuln_id}: {response.status_code}")
                return {}
        except Exception as e:
            print(f"Error fetching OSV details for {vuln_id}: {e}")
            return {}

    # --- MODIFIED get_cve_from_pysec function ---
    def get_cve_from_pysec(self, pysec_id: str) -> Optional[str]:
        """Get associated CVE from PYSEC vulnerability page on OSV.dev"""
        try:
            url = f"https://osv.dev/vulnerability/{pysec_id}"
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                # --- Find the Aliases section using the <dt> tag ---
                aliases_dt = soup.find('dt', string='Aliases')
                if aliases_dt:
                    # The <dd> sibling contains the list of aliases
                    aliases_dd = aliases_dt.find_next_sibling('dd')
                    if aliases_dd:
                        # Find all <a> tags within the <dd> that contain 'CVE-'
                        cve_links = aliases_dd.find_all('a', string=re.compile(r'^CVE-\d{4}-\d+$'))
                        for link in cve_links:
                            cve_id = link.get_text(strip=True)
                            if cve_id.startswith('CVE-'):
                                return cve_id
            print(f"CVE ID not found in aliases for PYSEC ID {pysec_id} (URL: {url})")
            return None
        except requests.exceptions.RequestException as e:
            print(f"Network error fetching PYSEC page for {pysec_id}: {e}")
            return None
        except Exception as e:
            print(f"Error parsing PYSEC page for {pysec_id}: {e}")
            return None

    # --- End of modification ---
    def get_npm_package_info(self, package_name: str) -> Dict:
        """Get npm package metadata"""
        try:
            url = f"https://registry.npmjs.org/{package_name}"
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                return response.json()
            return {}
        except Exception as e:
            print(f"Error fetching npm data for {package_name}: {e}")
            return {}

    def get_pypi_package_info(self, package_name: str) -> Dict:
        """Get PyPI package metadata"""
        try:
            url = f"https://pypi.org/pypi/{package_name}/json"
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                return response.json()
            return {}
        except Exception as e:
            print(f"Error fetching PyPI data for {package_name}: {e}")
            return {}

    def get_latest_version(self, package_name: str, package_type: str) -> Optional[str]:
        """Get the latest version of a package"""
        try:
            if package_type == 'npm':
                info = self.get_npm_package_info(package_name)
                if info and 'dist-tags' in info and 'latest' in info['dist-tags']:
                    return info['dist-tags']['latest']
                elif info and 'versions' in info:
                    # Fallback: Get the last key in the versions dict (often the latest)
                    versions = list(info['versions'].keys())
                    if versions:
                        return versions[-1]
            elif package_type == 'pypi':
                info = self.get_pypi_package_info(package_name)
                if info and 'info' in info and 'version' in info['info']:
                    return info['info']['version']
            # TODO: Implement for Maven and Go
            return None
        except Exception as e:
            print(f"Error fetching latest version for {package_name} ({package_type}): {e}")
            return None

    def get_github_advisory_details(self, ghsa_id: str) -> Dict[str, Any]:
        """
        Fetch CVE ID, Severity, and EPSS from GitHub Advisory page.
        """
        details = {
            'cve_id': 'N/A',
            'severity': 'N/A',
            'epss_score': None
        }
        try:
            url = f"https://github.com/advisories/{ghsa_id}"
            headers = {'User-Agent': 'Bharat-SCA/1.0'} # Good practice for web requests
            response = requests.get(url, timeout=15, headers=headers)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                # --- Extract CVE ID ---
                # Find the link containing the CVE ID text
                cve_link = soup.find('a', string=lambda text: text and text.startswith('CVE-'))
                if cve_link:
                    details['cve_id'] = cve_link.get_text(strip=True)
                # --- Extract Severity ---
                # Look for the severity label. GitHub uses specific classes.
                # The class names might change, so we look for common patterns.
                severity_element = soup.find('span', class_=lambda x: x and ('Label--' in x))
                if severity_element:
                     # Extract text like "High", "Critical", etc.
                    severity_text = severity_element.get_text(strip=True)
                    # Map GitHub severity terms to a more standard format if needed
                    # GitHub uses: "critical", "high", "moderate", "low"
                    # Our code uses: "Critical", "High", "Medium", "Low" (via color functions)
                    # We can just pass the text through for now.
                    details['severity'] = severity_text
                # --- Extract EPSS Score ---
                # EPSS is not directly displayed on the GitHub page.
                # We need to get the CVE ID first, then query the EPSS API.
                # This is handled outside this function, after CVE ID is found.
                # Optional: Print for debugging
                # print(f"Fetched details for {ghsa_id}: {details}")
            else:
                print(f"Failed to fetch {url}, status code: {response.status_code}")
        except Exception as e:
            print(f"Error scraping GitHub advisory {ghsa_id}: {e}")
        return details

    def analyze_license_risk(self, licenses: List[str]) -> Dict[str, Any]:
        """Analyze license risk and provide specific violation details"""
        if not licenses:
            return {
                'risk_level': 'unknown',
                'licenses': [],
                'high_risk_licenses': [],
                'warning_licenses': [],
                'violation_details': [] # Added for explicit violation reporting
            }

        high_risk = [lic for lic in licenses if lic in self.risky_licenses]
        warning_risk = [lic for lic in licenses if lic in self.warning_licenses]

        violation_details = []
        if high_risk:
            risk_level = 'high'
            violation_details = [f"Package uses {lic}, which is a strong copyleft license. This may require releasing your source code under the same license." for lic in high_risk]
        elif warning_risk:
            risk_level = 'warning'
            violation_details = [f"Package uses {lic}, which has potential restrictions or compatibility issues with other licenses." for lic in warning_risk]
        else:
            risk_level = 'low'
            violation_details = ["License is permissive or compatible with most use cases."]

        return {
            'risk_level': risk_level,
            'licenses': licenses,
            'high_risk_licenses': high_risk,
            'warning_licenses': warning_risk,
            'violation_details': violation_details # Include specific violation details
        }

    def analyze_maintenance(self, package_info: Dict) -> Dict[str, Any]:
        """Analyze package maintenance status"""
        try:
            if 'time' in package_info and 'modified' in package_info['time']:
                last_update = package_info['time']['modified']
                # Calculate days since last update
                last_update_date = datetime.fromisoformat(last_update.replace('Z', '+00:00'))
                days_since_update = (datetime.now(last_update_date.tzinfo) - last_update_date).days
                # Simple maintenance score (0-100)
                if days_since_update < 30:
                    maintenance_score = 90
                elif days_since_update < 90:
                    maintenance_score = 70
                elif days_since_update < 365:
                    maintenance_score = 50
                else:
                    maintenance_score = 30
            else:
                last_update = 'Unknown'
                maintenance_score = 50
                days_since_update = 'Unknown'
            # Get issues count if available (approximation)
            issues_count = 'N/A'
            return {
                'last_update': last_update,
                'days_since_update': days_since_update,
                'maintenance_score': maintenance_score,
                'open_issues': issues_count
            }
        except Exception as e:
            print(f"Error analyzing maintenance: {e}")
            return {
                'last_update': 'Unknown',
                'days_since_update': 'Unknown',
                'maintenance_score': 50,
                'open_issues': 'N/A'
            }

    def is_fork(self, package_info: Dict) -> bool:
        """Check if package is a fork"""
        try:
            # For npm packages
            if 'repository' in package_info:
                repo = package_info['repository']
                if isinstance(repo, dict) and 'url' in repo:
                    url = repo['url']
                    # Common fork indicators
                    return 'fork' in url.lower() or '/fork/' in url.lower()
            # For PyPI packages
            if 'info' in package_info and 'project_urls' in package_info['info']:
                urls = package_info['info']['project_urls']
                if urls:
                    for key, url in urls.items():
                        if url and ('fork' in key.lower() or 'fork' in url.lower()):
                            return True
            return False
        except Exception:
            return False

    def calculate_risk_score(self, vulns: List, license_risk: str, maintenance_score: int, is_fork: bool) -> int:
        """Calculate overall risk score (0-100)"""
        # Base score from maintenance
        score = maintenance_score
        # Add vulnerability impact
        vuln_score = 0
        for vuln in vulns:
            # Use the pre-fetched cvss_score if available, otherwise calculate
            cvss = vuln.get('cvss_score', self.get_cvss_score(vuln))
            if cvss >= 9.0:
                vuln_score += 25
            elif cvss >= 7.0:
                vuln_score += 15
            elif cvss >= 4.0:
                vuln_score += 8
            elif cvss > 0:
                vuln_score += 3
        score += min(vuln_score, 50)  # Cap vulnerability impact at 50
        # Add license risk
        if license_risk == 'high':
            score += 20
        elif license_risk == 'warning':
            score += 10
        # Fork penalty
        if is_fork:
            score += 5
        # --- NEW: Add EPSS impact to risk score ---
        # Find the highest EPSS score among vulnerabilities
        highest_epss = None
        for vuln in vulns:
            epss = vuln.get('epss_score')
            if epss is not None:
                if highest_epss is None or epss > highest_epss:
                    highest_epss = epss
        # Add points based on EPSS score (capped at 10)
        if highest_epss is not None:
            if highest_epss >= 0.7:
                score += 10 # High probability of exploitation
            elif highest_epss >= 0.3:
                score += 5  # Medium probability
            elif highest_epss > 0:
                score += 2  # Low probability
        # Cap at 100
        return min(100, score)

    def get_cvss_score(self, vuln: Dict) -> float:
        """Extract CVSS score from vulnerability with multiple fallback methods"""
        try:
            # Method 1: Try OSV severity field (most reliable)
            if 'severity' in vuln:
                # Ensure vuln['severity'] is a list
                if isinstance(vuln['severity'], list):
                    for severity_item in vuln['severity']:
                        # Ensure severity_item is a dictionary before calling .get()
                        if isinstance(severity_item, dict):
                            if severity_item.get('type') == 'CVSS_V3':
                                # OSV often provides the vector string, not the score directly
                                vector = severity_item.get('score', '')
                                score = self._extract_cvss_from_vector(vector)
                                if score is not None:
                                    return score
                            elif severity_item.get('type') == 'CVSS_V2':
                                vector = severity_item.get('score', '')
                                score = self._extract_cvss_from_vector(vector)
                                if score is not None:
                                    # Approximate conversion from CVSS v2 to v3
                                    return min(10.0, score * 1.2)
            # Method 2: Try database_specific field (e.g., GitHub)
            if 'database_specific' in vuln:
                db_specific = vuln['database_specific']
                # Ensure db_specific is a dictionary
                if isinstance(db_specific, dict):
                    # GitHub format
                    if 'cvss' in db_specific:
                        cvss_data = db_specific['cvss']
                        # Ensure cvss_data is a dictionary and has 'score'
                        if isinstance(cvss_data, dict) and 'score' in cvss_data:
                            return float(cvss_data['score'])
                    # Other formats within database_specific
                    for key, value in db_specific.items():
                        if 'cvss' in key.lower() and isinstance(value, (int, float)):
                            return float(value)
            # Method 3: Try impacts field (less common)
            if 'impacts' in vuln:
                 # Ensure vuln['impacts'] is a list
                if isinstance(vuln['impacts'], list):
                    for impact in vuln['impacts']:
                         # Ensure impact is a dictionary before calling .get()
                        if isinstance(impact, dict):
                            if 'cvss_score' in impact:
                                return float(impact['cvss_score'])
            # Fallback if no CVSS found
            # print(f"No CVSS score found for vulnerability {vuln.get('id', 'Unknown')}")
            return 5.0 # Return default score if not found
        except Exception as e:
            print(f"Error extracting CVSS for vulnerability {vuln.get('id', 'Unknown')}: {e}")
            return 5.0 # Return default score on error

    def _extract_cvss_from_vector(self, vector: str) -> Optional[float]:
        """Extract CVSS base score from vector string"""
        try:
            if not vector or not isinstance(vector, str):
                return None
            # Look for CVSS v3 vector pattern and extract score from it
            # Example vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            # OSV doesn't always provide the score directly in the vector string.
            # We need to parse it or look for a separate 'baseScore' if it's a dict.
            # However, the OSV API structure for severity.score is usually the vector string.
            # If it's a structured dict (less common in OSV API), extract baseScore.
            if isinstance(vector, dict) and 'baseScore' in vector:
                return float(vector['baseScore'])
            # For standard vector strings, parsing to calculate score is complex.
            # OSV API usually provides the score separately if available.
            # Since the primary source (vuln['severity']) didn't yield a score,
            # and we are parsing the vector string, we might not be able to extract it easily here.
            # A more robust solution would involve a CVSS library, but for simplicity,
            # we'll assume if we reach this point and have a vector string, we might need to
            # accept that the score isn't directly extractable without calculation.
            # Let's check if the vector string contains a known score format or reference.
            # Often, the score is not directly in the string provided by OSV.
            # We'll return None here to indicate it couldn't be extracted from the vector alone.
            # The primary logic in get_cvss_score should have found it elsewhere.
            return None
        except Exception as e:
            print(f"Error parsing CVSS vector '{vector}': {e}")
            return None

    def get_vulnerability_link(self, vuln_id: str) -> str:
        """Generate hyperlink for vulnerability details"""
        if vuln_id.startswith('CVE-'):
            return f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
        elif vuln_id.startswith('GHSA-'):
            return f"https://github.com/advisories/{vuln_id}"
        elif vuln_id.startswith('PYSEC-'):
            return f"https://osv.dev/vulnerability/{vuln_id}"
        else:
            return f"https://osv.dev/vulnerability/{vuln_id}"

    def get_risk_color(self, risk_score: int) -> str:
        """Get color based on risk score"""
        if risk_score >= 80:
            return '#dc3545'  # Red
        elif risk_score >= 50:
            return '#ffc107'  # Yellow
        else:
            return '#28a745'  # Green

    def get_license_risk_color(self, license_risk: str) -> str:
        """Get color based on license risk"""
        if license_risk == 'high':
            return '#dc3545'  # Red
        elif license_risk == 'warning':
            return '#ffc107'  # Yellow
        else:
            return '#28a745'  # Green

    def get_cvss_color(self, cvss_score: float) -> str:
        """Get color based on CVSS score"""
        if cvss_score >= 9.0:
            return '#dc3545'  # Critical
        elif cvss_score >= 7.0:
            return '#dc3545'  # High
        elif cvss_score >= 4.0:
            return '#ffc107'  # Medium
        elif cvss_score > 0:
            return '#28a745'  # Low
        else:
            return '#6c757d'  # None/Unknown

    def get_epss_color(self, epss_score: float) -> str:
        """Get color based on EPSS score"""
        if epss_score is None:
            return '#6c757d'  # Gray for unknown
        elif epss_score >= 0.5:
            return '#dc3545'  # High probability
        elif epss_score >= 0.1:
            return '#ffc107'  # Medium probability
        else:
            return '#28a745'  # Low probability

    def generate_html_report(self, results: List[Dict], output_file: str):
        """Generate rich HTML report with enhanced vulnerability details and filterable tables"""
        # Sort results by risk score
        sorted_results = sorted(results, key=lambda x: x['risk_score'], reverse=True)
        # Calculate summary statistics
        total_deps = len(results)
        high_risk_deps = sum(1 for r in results if r['risk_score'] >= 80)
        medium_risk_deps = sum(1 for r in results if 50 <= r['risk_score'] < 80)
        low_risk_deps = sum(1 for r in results if r['risk_score'] < 50)
        # Get high risk dependencies for special section (will be removed from output)
        # high_risk = [r for r in results if r['risk_score'] >= 80]
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bharat-SCA Dependency Risk Report</title>
    <style>
        :root {{
            --primary: #007bff;
            --danger: #dc3545;
            --warning: #ffc107;
            --success: #28a745;
            --info: #17a2b8;
            --light: #f8f9fa;
            --dark: #343a40;
        }}
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f7fa;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}
        header {{
            background: linear-gradient(135deg, var(--primary), #0056b3);
            color: white;
            padding: 30px 0;
            text-align: center;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
        }}
        .subtitle {{
            font-size: 1.1rem;
            opacity: 0.9;
        }}
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background: white;
            border-radius: 8px;
            padding: 25px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
            text-align: center;
            transition: transform 0.3s ease;
        }}
        .card:hover {{
            transform: translateY(-5px);
        }}
        .card.high-risk {{
            border-top: 5px solid var(--danger);
        }}
        .card.medium-risk {{
            border-top: 5px solid var(--warning);
        }}
        .card.low-risk {{
            border-top: 5px solid var(--success);
        }}
        .card.total {{
            border-top: 5px solid var(--primary);
        }}
        .card-number {{
            font-size: 2.5rem;
            font-weight: bold;
            margin: 10px 0;
        }}
        .card-label {{
            font-size: 1.1rem;
            color: #666;
        }}
        .section {{
            background: white;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        }}
        .section-title {{
            font-size: 1.5rem;
            margin-bottom: 20px;
            color: var(--dark);
            border-bottom: 2px solid var(--light);
            padding-bottom: 10px;
        }}
        /* .high-risk-item {{
            background: #fff5f5;
            border-left: 4px solid var(--danger);
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 0 8px 8px 0;
        }} */
        .dependency-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        .dependency-table th {{
            background-color: var(--primary);
            color: white;
            text-align: left;
            padding: 15px;
            font-weight: 600;
        }}
        .dependency-table td {{
            padding: 12px 15px;
            border-bottom: 1px solid #eee;
        }}
        .dependency-table tr:hover {{
            background-color: #f8f9fa;
        }}
        .risk-badge {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
            text-align: center;
        }}
        .risk-high {{
            background-color: #f8d7da;
            color: #721c24;
        }}
        .risk-medium {{
            background-color: #fff3cd;
            color: #856404;
        }}
        .risk-low {{
            background-color: #d4edda;
            color: #155724;
        }}
        .vuln-list {{
            margin: 10px 0;
            padding-left: 20px;
        }}
        .vuln-item {{
            margin: 8px 0;
            border-radius: 6px;
            border-left: 3px solid #007bff;
            overflow: hidden;
        }}
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px;
            background: #f8f9fa;
            cursor: pointer;
            font-weight: 600;
        }}
        .vuln-header:hover {{
            background: #e9ecef;
        }}
        .vuln-id {{
            color: var(--primary);
            text-decoration: none;
        }}
        .vuln-id:hover {{
            text-decoration: underline;
        }}
        .expand-icon {{
            font-size: 1.2rem;
            transition: transform 0.3s ease;
        }}
        .vuln-details {{
            padding: 0;
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease, padding 0.3s ease;
            background: white;
        }}
        .vuln-details.expanded {{
            padding: 12px;
            max-height: 500px;
        }}
        .vuln-content {{
            padding: 10px;
        }}
        .cvss-score {{
            font-weight: bold;
            padding: 2px 8px;
            border-radius: 4px;
        }}
        .epss-score {{
            font-weight: bold;
            padding: 2px 8px;
            border-radius: 4px;
            margin-left: 8px;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9rem;
            margin-top: 30px;
        }}
        .timestamp {{
            font-size: 0.9rem;
            color: #666;
            margin-top: 10px;
        }}
        .package-name {{
            font-weight: 600;
            color: var(--dark);
        }}
        .package-version {{
            color: #666;
            font-size: 0.9rem;
        }}
        .tooltip {{
            position: relative;
            display: inline-block;
            border-bottom: 1px dotted black;
        }}
        .tooltip .tooltiptext {{
            visibility: hidden;
            width: 200px;
            background-color: #555;
            color: #fff;
            text-align: center;
            border-radius: 6px;
            padding: 8px;
            position: absolute;
            z-index: 1;
            bottom: 125%;
            left: 50%;
            margin-left: -100px;
            opacity: 0;
            transition: opacity 0.3s;
            font-size: 0.85rem;
        }}
        .tooltip:hover .tooltiptext {{
            visibility: visible;
            opacity: 1;
        }}
        .external-link-icon {{
            margin-left: 4px;
            font-size: 0.8em;
        }}
        .summary-text {{
            font-size: 0.9rem;
            color: #666;
            margin-top: 8px;
        }}
        .detail-row {{
            margin: 5px 0;
            font-size: 0.9rem;
        }}
        .detail-label {{
            font-weight: 600;
            display: inline-block;
            width: 120px; /* Increased width for labels */
        }}
        /* Filter styles */
        .filter-container {{
            margin-bottom: 15px;
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            align-items: center;
        }}
        .filter-container label {{
            font-weight: bold;
            margin-right: 5px;
        }}
        .filter-container select, .filter-container input {{
            padding: 5px;
            border: 1px solid #ccc;
            border-radius: 4px;
        }}
        .filter-container input[type="text"] {{
            flex-grow: 1;
            min-width: 150px;
        }}
        /* Responsive table */
        .table-container {{
            overflow-x: auto;
            margin-top: 10px;
        }}
        /* Source file styling */
        .source-file {{
            font-size: 0.8rem;
            color: #666;
            font-family: monospace; /* Monospace for file paths */
            word-break: break-all; /* Break long paths */
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Bharat-SCA Dependency Risk Report</h1>
            <div class="subtitle">Comprehensive Security, License & Maintenance Analysis</div>
            <div class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </header>
        <div class="summary-cards">
            <div class="card total">
                <div class="card-label">Total Dependencies</div>
                <div class="card-number">{total_deps}</div>
            </div>
            <div class="card high-risk">
                <div class="card-label">High Risk</div>
                <div class="card-number">{high_risk_deps}</div>
            </div>
            <div class="card medium-risk">
                <div class="card-label">Medium Risk</div>
                <div class="card-number">{medium_risk_deps}</div>
            </div>
            <div class="card low-risk">
                <div class="card-label">Low Risk</div>
                <div class="card-number">{low_risk_deps}</div>
            </div>
        </div>
        """
        # --- REMOVED: High risk dependencies section ---
        # All dependencies table
        html_content += """
        <div class="section">
            <h2 class="section-title">📋 All Dependencies</h2>
            <div id="all-deps-filters" class="filter-container">
                <label for="all-deps-search">Search:</label>
                <input type="text" id="all-deps-search" placeholder="Filter packages...">
                <label for="all-deps-risk-filter">Risk:</label>
                <select id="all-deps-risk-filter">
                    <option value="all">All</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
                <label for="all-deps-type-filter">Type:</label>
                <select id="all-deps-type-filter">
                    <option value="all">All</option>
                    <option value="npm">npm</option>
                    <option value="pypi">PyPI</option>
                    <option value="maven">Maven</option>
                    <option value="gradle">Gradle</option>
                    <option value="go">Go</option>
                </select>
            </div>
            <div class="table-container">
            <table class="dependency-table" id="all-deps-table">
                <thead>
                    <tr>
                        <th>Package</th>
                        <th>Version</th>
                        <th>Latest Version Available</th>
                        <th>Type</th>
                        <th>Source File</th> <!-- NEW COLUMN -->
                        <th>Risk Score</th>
                        <th>License Risk</th>
                        <th>
                            <div class="tooltip">Vulns
                                <span class="tooltiptext">Number of vulnerabilities found</span>
                            </div>
                        </th>
                        <th>
                            <div class="tooltip">EPSS
                                <span class="tooltiptext">Exploit Prediction Scoring System (probability of exploitation)</span>
                            </div>
                        </th>
                        <th>Last Update</th>
                    </tr>
                </thead>
                <tbody>
        """
        for dep in sorted_results:
            risk_color = self.get_risk_color(dep['risk_score'])
            license_risk = dep['license_info'].get('risk_level', 'unknown')
            license_risk_color = self.get_license_risk_color(license_risk)
            vuln_count = len(dep['vulnerabilities'])
            days_since = dep['maintenance_info'].get('days_since_update', 'Unknown')
            days_str = str(days_since) if days_since != 'Unknown' else 'Unknown'
            # Risk badge class
            if dep['risk_score'] >= 80:
                risk_badge_class = 'risk-high'
                risk_text = 'High'
            elif dep['risk_score'] >= 50:
                risk_badge_class = 'risk-medium'
                risk_text = 'Medium'
            else:
                risk_badge_class = 'risk-low'
                risk_text = 'Low'
            # License badge class
            if license_risk == 'high':
                license_badge_class = 'risk-high'
                license_text = 'High'
            elif license_risk == 'warning':
                license_badge_class = 'risk-medium'
                license_text = 'Warning'
            else:
                license_badge_class = 'risk-low'
                license_text = 'Low'
            # Get highest EPSS score for this dependency
            highest_epss = None
            for vuln in dep['vulnerabilities']:
                epss = vuln.get('epss_score')
                if epss is not None:
                    if highest_epss is None or epss > highest_epss:
                        highest_epss = epss
            epss_color = self.get_epss_color(highest_epss)
            epss_display = f"{highest_epss:.4f}" if highest_epss is not None else "N/A"
            # --- NEW: Get Latest Version ---
            latest_version = dep.get('latest_version', 'N/A')
            # --- NEW: Get Source File ---
            source_file = dep.get('source_file', 'N/A')
            html_content += f"""
                    <tr data-risk="{risk_text.lower()}" data-type="{dep['type']}">
                        <td>
                            <div class="package-name">{dep['name']}</div>
                        </td>
                        <td>
                            <div class="package-version">{dep['version']}</div>
                        </td>
                        <td>
                            <div class="package-version">{latest_version}</div>
                        </td>
                        <td>{dep['type']}</td>
                        <td> <!-- NEW COLUMN DATA -->
                            <div class="source-file">{source_file}</div>
                        </td>
                        <td>
                            <span class="risk-badge {risk_badge_class}" style="background-color: {risk_color}20; color: {risk_color};">
                                {dep['risk_score']}
                            </span>
                        </td>
                        <td>
                            <span class="risk-badge {license_badge_class}" style="background-color: {license_risk_color}20; color: {license_risk_color};">
                                {license_text}
                            </span>
                        </td>
                        <td>{vuln_count}</td>
                        <td>
                            <span class="epss-score" style="background-color: {epss_color}20; color: {epss_color};">
                                {epss_display}
                            </span>
                        </td>
                        <td>{days_str} days</td>
                    </tr>
            """
        html_content += """
                </tbody>
            </table>
            </div>
        </div>
        """
        # Vulnerability Details Section
        html_content += """
        <div class="section">
            <h2 class="section-title">🔍 Vulnerability Details</h2>
            <div id="vuln-details-filters" class="filter-container">
                <label for="vuln-details-search">Search:</label>
                <input type="text" id="vuln-details-search" placeholder="Filter packages or CVEs...">
                <label for="vuln-details-severity-filter">Severity:</label>
                <select id="vuln-details-severity-filter">
                    <option value="all">All</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
                <label for="vuln-details-type-filter">Package Type:</label>
                <select id="vuln-details-type-filter">
                    <option value="all">All</option>
                    <option value="npm">npm</option>
                    <option value="pypi">PyPI</option>
                    <option value="maven">Maven</option>
                    <option value="gradle">Gradle</option>
                    <option value="go">Go</option>
                </select>
            </div>
            <div class="table-container">
            <table class="dependency-table" id="vuln-details-table">
                <thead>
                    <tr>
                        <th>Package</th>
                        <th>Version</th>
                        <th>Source File</th> <!-- NEW COLUMN -->
                        <th>Vulnerability ID</th>
                        <th>CVE ID</th>
                        <th>Severity</th>
                        <th>CVSS Score</th>
                        <th>EPSS Score</th>
                        <th>Summary</th>
                    </tr>
                </thead>
                <tbody>
        """
        # Collect all vulnerabilities
        all_vulns = []
        for dep in sorted_results:
            for vuln in dep['vulnerabilities']:
                vuln_data = {
                    'package': dep['name'],
                    'version': dep['version'],
                    'source_file': dep.get('source_file', 'N/A'), # Add source file
                    'vuln_id': vuln.get('id', 'Unknown'),
                    'cve_id': vuln.get('cve_id', 'N/A'),
                    'severity': vuln.get('severity', 'N/A'),
                    'summary': vuln.get('summary', vuln.get('details', 'No details available')[:150] + "..."),
                    'cvss': vuln.get('cvss_score', self.get_cvss_score(vuln)), # This will now use the fetched score
                    'epss': vuln.get('epss_score'),
                    'package_type': dep['type'] # Add package type for filtering
                }
                # Determine severity text for filtering
                cvss_score = vuln_data['cvss']
                if cvss_score >= 9.0:
                    vuln_data['severity_text'] = 'critical'
                elif cvss_score >= 7.0:
                    vuln_data['severity_text'] = 'high'
                elif cvss_score >= 4.0:
                    vuln_data['severity_text'] = 'medium'
                elif cvss_score > 0:
                    vuln_data['severity_text'] = 'low'
                else:
                    vuln_data['severity_text'] = 'unknown'

                all_vulns.append(vuln_data)
        # Sort by CVSS score (highest first)
        all_vulns.sort(key=lambda x: x['cvss'], reverse=True)
        # --- FIX: Iterate through ALL vulnerabilities, not just the first 20 ---
        # for vuln in all_vulns[:20]:  # Show top 20 vulnerabilities
        for vuln in all_vulns: # Show ALL vulnerabilities
            vuln_link = self.get_vulnerability_link(vuln['vuln_id'])
            cvss_color = self.get_cvss_color(vuln['cvss'])
            epss_color = self.get_epss_color(vuln['epss'])
            epss_display = f"{vuln['epss']:.4f}" if vuln['epss'] is not None else "N/A"
            # --- NEW: Get Source File ---
            source_file = vuln.get('source_file', 'N/A')
            html_content += f"""
                    <tr data-severity="{vuln['severity_text']}" data-package-type="{vuln['package_type']}">
                        <td>
                            <div class="package-name">{vuln['package']}</div>
                        </td>
                        <td>
                            <div class="package-version">{vuln['version']}</div>
                        </td>
                        <td> <!-- NEW COLUMN DATA -->
                            <div class="source-file">{source_file}</div>
                        </td>
                        <td>
                            <a href="{vuln_link}" target="_blank" class="vuln-id">
                                {vuln['vuln_id']} ↗
                            </a>
                        </td>
                        <td>{vuln['cve_id']}</td>
                        <td>{vuln['severity']}</td>
                        <td>
                            <span class="cvss-score" style="background-color: {cvss_color}20; color: {cvss_color};">
                                {vuln['cvss']}
                            </span>
                        </td>
                        <td>
                            <span class="epss-score" style="background-color: {epss_color}20; color: {epss_color};">
                                {epss_display}
                            </span>
                        </td>
                        <td>
                            <div style="font-size: 0.9rem; color: #666;">
                                {vuln['summary']}
                            </div>
                        </td>
                    </tr>
            """
        html_content += """
                </tbody>
            </table>
            </div>
        </div>
        """
        # License Violation Details Section
        html_content += """
        <div class="section">
            <h2 class="section-title">⚖️ License Violation Details</h2>
            <div id="license-violations-filters" class="filter-container">
                <label for="license-violations-search">Search:</label>
                <input type="text" id="license-violations-search" placeholder="Filter packages...">
                <label for="license-violations-risk-filter">Risk:</label>
                <select id="license-violations-risk-filter">
                    <option value="all">All</option>
                    <option value="high">High</option>
                    <option value="warning">Warning</option>
                </select>
                <label for="license-violations-type-filter">Type:</label>
                <select id="license-violations-type-filter">
                    <option value="all">All</option>
                    <option value="npm">npm</option>
                    <option value="pypi">PyPI</option>
                    <option value="maven">Maven</option>
                    <option value="gradle">Gradle</option>
                    <option value="go">Go</option>
                </select>
            </div>
            <div class="table-container">
            <table class="dependency-table" id="license-violations-table">
                <thead>
                    <tr>
                        <th>Package</th>
                        <th>Version</th>
                        <th>Type</th>
                        <th>Source File</th> <!-- NEW COLUMN -->
                        <th>License Risk</th>
                        <th>Detected Licenses</th>
                        <th>Violation Details</th>
                    </tr>
                </thead>
                <tbody>
        """
        # Collect license violation details
        license_violations = []
        for dep in sorted_results:
            license_info = dep['license_info']
            risk_level = license_info.get('risk_level', 'unknown')
            if risk_level in ['high', 'warning']:
                license_violations.append({
                    'package': dep['name'],
                    'version': dep['version'],
                    'type': dep['type'],
                    'source_file': dep.get('source_file', 'N/A'), # Add source file
                    'risk_level': risk_level,
                    'licenses': ', '.join(license_info.get('licenses', [])),
                    'violation_details': '; '.join(license_info.get('violation_details', []))
                })

        for violation in license_violations:
            # License risk badge
            if violation['risk_level'] == 'high':
                license_badge_class = 'risk-high'
                license_text = 'High'
                license_color = '#dc3545'
            elif violation['risk_level'] == 'warning':
                license_badge_class = 'risk-medium'
                license_text = 'Warning'
                license_color = '#ffc107'
            else:
                license_badge_class = 'risk-low'
                license_text = 'Low'
                license_color = '#28a745'

            html_content += f"""
                    <tr data-license-risk="{violation['risk_level']}" data-type="{violation['type']}">
                        <td>
                            <div class="package-name">{violation['package']}</div>
                        </td>
                        <td>
                            <div class="package-version">{violation['version']}</div>
                        </td>
                        <td>{violation['type']}</td>
                        <td> <!-- NEW COLUMN DATA -->
                            <div class="source-file">{violation['source_file']}</div>
                        </td>
                        <td>
                            <span class="risk-badge {license_badge_class}" style="background-color: {license_color}20; color: {license_color};">
                                {license_text}
                            </span>
                        </td>
                        <td>{violation['licenses']}</td>
                        <td>{violation['violation_details']}</td>
                    </tr>
            """
        html_content += """
                </tbody>
            </table>
            </div>
        </div>
        """
        # Footer with legend
        html_content += f"""
        <div class="section">
            <h2 class="section-title">📊 Legend</h2>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px;">
                <div>
                    <h3>Risk Scores</h3>
                    <p><span style="color: #dc3545;">🔴 High Risk:</span> 80-100 (Immediate action required)</p>
                    <p><span style="color: #ffc107;">🟡 Medium Risk:</span> 50-79 (Review recommended)</p>
                    <p><span style="color: #28a745;">🟢 Low Risk:</span> 0-49 (Acceptable risk)</p>
                </div>
                <div>
                    <h3>CVSS Scores</h3>
                    <p><span style="color: #dc3545;">🔴 Critical:</span> 9.0-10.0</p>
                    <p><span style="color: #dc3545;">🔴 High:</span> 7.0-8.9</p>
                    <p><span style="color: #ffc107;">🟡 Medium:</span> 4.0-6.9</p>
                    <p><span style="color: #28a745;">🟢 Low:</span> 0.1-3.9</p>
                    <p><span style="color: #6c757d;">⚪ None:</span> 0.0</p>
                </div>
                <div>
                    <h3>EPSS Scores</h3>
                    <p><span style="color: #dc3545;">🔴 High Probability:</span> ≥ 0.5 (50%+ chance of exploitation)</p>
                    <p><span style="color: #ffc107;">🟡 Medium Probability:</span> 0.1-0.49</p>
                    <p><span style="color: #28a745;">🟢 Low Probability:</span> < 0.1</p>
                    <p><span style="color: #6c757d;">⚪ Unknown:</span> No EPSS data available</p>
                </div>
            </div>
        </div>
        """
        # JavaScript for expandable details and filtering
        html_content += """
        <script>
        // Generic filter function
        function setupTableFilter(tableId, searchInputId, riskFilterId, typeFilterId, severityFilterId, licenseRiskFilterId) {
            const table = document.getElementById(tableId);
            const searchInput = document.getElementById(searchInputId);
            const riskFilter = document.getElementById(riskFilterId);
            const typeFilter = document.getElementById(typeFilterId);
            const severityFilter = document.getElementById(severityFilterId); // Optional
            const licenseRiskFilter = document.getElementById(licenseRiskFilterId); // Optional

            function filterTable() {
                const searchTerm = searchInput ? searchInput.value.toLowerCase() : '';
                const riskValue = riskFilter ? riskFilter.value : 'all';
                const typeValue = typeFilter ? typeFilter.value : 'all';
                const severityValue = severityFilter ? severityFilter.value : 'all';
                const licenseRiskValue = licenseRiskFilter ? licenseRiskFilter.value : 'all';

                const rows = table.querySelectorAll('tbody tr');
                rows.forEach(row => {
                    const packageName = row.cells[0].textContent.toLowerCase();
                    const packageVersion = row.cells[1] ? row.cells[1].textContent.toLowerCase() : '';
                    const rowRisk = row.getAttribute('data-risk') || '';
                    const rowType = row.getAttribute('data-type') || '';
                    const rowSeverity = row.getAttribute('data-severity') || '';
                    const rowLicenseRisk = row.getAttribute('data-license-risk') || '';
                    const rowPackageType = row.getAttribute('data-package-type') || '';

                    const matchesSearch = searchTerm === '' ||
                                          packageName.includes(searchTerm) ||
                                          packageVersion.includes(searchTerm) ||
                                          (row.cells[3] && row.cells[3].textContent.toLowerCase().includes(searchTerm)); // CVE ID or Source File in vuln table

                    const matchesRisk = riskValue === 'all' || rowRisk === riskValue || rowLicenseRisk === riskValue;
                    const matchesType = typeValue === 'all' || rowType === typeValue || rowPackageType === typeValue;
                    const matchesSeverity = severityValue === 'all' || rowSeverity === severityValue;
                    const matchesLicenseRisk = licenseRiskValue === 'all' || rowLicenseRisk === licenseRiskValue;

                    if (matchesSearch && matchesRisk && matchesType && matchesSeverity && matchesLicenseRisk) {
                        row.style.display = '';
                    } else {
                        row.style.display = 'none';
                    }
                });
            }

            if (searchInput) searchInput.addEventListener('input', filterTable);
            if (riskFilter) riskFilter.addEventListener('change', filterTable);
            if (typeFilter) typeFilter.addEventListener('change', filterTable);
            if (severityFilter) severityFilter.addEventListener('change', filterTable);
            if (licenseRiskFilter) licenseRiskFilter.addEventListener('change', filterTable);
        }

        // Setup filters for each table after the page loads
        document.addEventListener('DOMContentLoaded', function() {
            setupTableFilter('all-deps-table', 'all-deps-search', 'all-deps-risk-filter', 'all-deps-type-filter', null, null);
            setupTableFilter('vuln-details-table', 'vuln-details-search', null, 'vuln-details-type-filter', 'vuln-details-severity-filter', null);
            setupTableFilter('license-violations-table', 'license-violations-search', null, 'license-violations-type-filter', null, 'license-violations-risk-filter');
        });
        </script>
        """
        # Footer
        html_content += f"""
        <div class="footer">
            <p>Bharat-SCA Dependency Risk Report</p>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><small>Data sources: OSV, First.org EPSS, npm, PyPI, GitHub Advisories, NVD</small></p>
        </div>
    </div>
</body>
</html>
        """
        with open(output_file, 'w') as f:
            f.write(html_content)

    def generate_markdown_report(self, results: List[Dict], output_file: str):
        """Generate markdown report with enhanced vulnerability details"""
        with open(output_file, 'w') as f:
            f.write("# Bharat-SCA Dependency Risk Report\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            # Summary
            total_deps = len(results)
            high_risk_deps = sum(1 for r in results if r['risk_score'] >= 80)
            medium_risk_deps = sum(1 for r in results if 50 <= r['risk_score'] < 80)
            low_risk_deps = sum(1 for r in results if r['risk_score'] < 50)
            f.write("## Summary\n")
            f.write(f"- Total Dependencies: {total_deps}\n")
            f.write(f"- High Risk: {high_risk_deps}\n")
            f.write(f"- Medium Risk: {medium_risk_deps}\n")
            f.write(f"- Low Risk: {low_risk_deps}\n")
            # --- REMOVED: High risk dependencies section ---
            # All dependencies table
            f.write("## All Dependencies\n")
            # --- MODIFIED: Updated column headers to include Latest Version and Source File ---
            f.write("| Package | Version | Latest Version Available | Type | Source File | Risk Score | License Risk | Vulns | Highest EPSS | Last Update |\n")
            f.write("|---------|---------|--------------------------|------|-------------|------------|--------------|-------|--------------|-------------|\n")
            for dep in results:
                vuln_count = len(dep['vulnerabilities'])
                license_risk = dep['license_info'].get('risk_level', 'unknown')
                days_since = dep['maintenance_info'].get('days_since_update', 'Unknown')
                days_str = str(days_since) if days_since != 'Unknown' else 'Unknown'
                # Get highest EPSS score
                highest_epss = None
                for vuln in dep['vulnerabilities']:
                     epss = vuln.get('epss_score')
                     if epss is not None:
                        if highest_epss is None or epss > highest_epss:
                            highest_epss = epss
                epss_display = f"{highest_epss:.4f}" if highest_epss is not None else "N/A"
                # --- NEW: Get Latest Version and Source File ---
                latest_version = dep.get('latest_version', 'N/A')
                source_file = dep.get('source_file', 'N/A')
                f.write(f"| {dep['name']} | {dep['version']} | {latest_version} | {dep['type']} | {source_file} | {dep['risk_score']} | {license_risk} | {vuln_count} | {epss_display} | {days_str} |\n")

            # License Violation Details Section
            f.write("\n## ⚖️ License Violation Details\n")
            f.write("| Package | Version | Type | Source File | License Risk | Detected Licenses | Violation Details |\n")
            f.write("|---------|---------|------|-------------|--------------|-------------------|-------------------|\n")
            for dep in results:
                license_info = dep['license_info']
                risk_level = license_info.get('risk_level', 'unknown')
                if risk_level in ['high', 'warning']:
                    licenses_str = ', '.join(license_info.get('licenses', []))
                    violations_str = '; '.join(license_info.get('violation_details', []))
                    source_file = dep.get('source_file', 'N/A')
                    f.write(f"| {dep['name']} | {dep['version']} | {dep['type']} | {source_file} | {risk_level} | {licenses_str} | {violations_str} |\n")

            # Vulnerability Details Section
            f.write("\n## 🔍 Vulnerability Details\n")
            f.write("| Package | Version | Source File | Vulnerability | CVE ID | Severity | CVSS | EPSS | Details |\n")
            f.write("|---------|---------|-------------|---------------|--------|----------|------|------|---------|\n")
            # Collect all vulnerabilities
            all_vulns = []
            for dep in results:
                for vuln in dep['vulnerabilities']:
                    vuln_data = {
                        'package': dep['name'],
                        'version': dep['version'],
                        'source_file': dep.get('source_file', 'N/A'), # Add source file
                        'vuln_id': vuln.get('id', 'Unknown'),
                        'cve_id': vuln.get('cve_id', 'N/A'),
                        'severity': vuln.get('severity', 'N/A'),
                        'summary': vuln.get('summary', vuln.get('details', 'No details available')[:80] + "..."),
                        'cvss': vuln.get('cvss_score', self.get_cvss_score(vuln)), # This will now use the fetched score
                        'epss': vuln.get('epss_score')
                    }
                    all_vulns.append(vuln_data)
            # Sort by CVSS score (highest first)
            all_vulns.sort(key=lambda x: x['cvss'], reverse=True)
            # --- FIX: Iterate through ALL vulnerabilities, not just the first 20 ---
            # for vuln in all_vulns[:20]:  # Show top 20 vulnerabilities
            for vuln in all_vulns: # Show ALL vulnerabilities
                vuln_link = self.get_vulnerability_link(vuln['vuln_id'])
                epss_display = f"{vuln['epss']:.4f}" if vuln['epss'] is not None else "N/A"
                summary = vuln['summary'][:80] + "..." if len(vuln['summary']) > 80 else vuln['summary']
                source_file = vuln.get('source_file', 'N/A')
                f.write(f"| {vuln['package']} | {vuln['version']} | {source_file} | [{vuln['vuln_id']}]({vuln_link}) | {vuln['cve_id']} | {vuln['severity']} | {vuln['cvss']} | {epss_display} | {summary} |\n")

    def generate_json_output(self, results: List[Dict], output_file: str):
        """Generate JSON output with enhanced vulnerability data"""
        # The results already contain the enhanced vulnerability data
        output_data = {
            'generated_at': datetime.now().isoformat(),
            'total_dependencies': len(results),
            'dependencies': results # Pass the already enhanced results
        }
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)

    def generate_spdx_sbom(self, results: List[Dict], output_file: str):
        """Generate SBOM in SPDX format"""
        # SPDX Document Creation Info
        document_name = f"Bharat-SCA-SBOM-{datetime.now().strftime('%Y-%m-%d')}"
        document_namespace = f"https://bharat-sca.example.com/spdxdocs/{uuid.uuid4()}"
        created_timestamp = datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')

        spdx_data = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": document_name,
            "documentNamespace": document_namespace,
            "creationInfo": {
                "creators": ["Tool: Bharat-SCA"],
                "created": created_timestamp
            },
            "packages": [],
            "relationships": []
        }

        # Add packages and their relationships
        for i, dep in enumerate(results):
            package_spdx_id = f"SPDXRef-Package-{i+1}"

            # Extract license expressions
            licenses = dep['license_info'].get('licenses', [])
            if licenses:
                # SPDX expects a valid license expression. For simplicity, join with OR.
                # A more robust implementation would validate against SPDX license list.
                license_concluded = " OR ".join(licenses)
            else:
                license_concluded = "NOASSERTION"

            # Create package entry
            package_entry = {
                "name": dep['name'],
                "SPDXID": package_spdx_id,
                "versionInfo": dep['version'],
                "downloadLocation": "NOASSERTION", # We don't have this info from OSV/npm/PyPI calls
                "licenseConcluded": license_concluded,
                "licenseDeclared": license_concluded, # Often the same for simple cases
                "copyrightText": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl", # Using purl (Package URL) as a standard ref
                        "referenceLocator": self._generate_purl(dep['name'], dep['version'], dep['type'])
                    }
                ]
            }
            # Add source file if available
            source_file = dep.get('source_file')
            if source_file:
                 package_entry["comment"] = f"Declared in: {source_file}"

            spdx_data["packages"].append(package_entry)

            # Add vulnerabilities as relationships and external references if needed
            # SPDX 2.3 has limited native vulnerability support, often done via externalRefs or annotations
            # For simplicity here, we just list them in the package's comment or description.
            # A full implementation might use the SPDX Vulnerability Extension if available.
            vuln_ids = [vuln.get('id') for vuln in dep['vulnerabilities'] if vuln.get('id')]
            if vuln_ids:
                # Add vulnerabilities to the package description
                vuln_list_str = ", ".join(vuln_ids)
                if "comment" in package_entry:
                    package_entry["comment"] += f"; Identified Vulnerabilities: {vuln_list_str}"
                else:
                    package_entry["comment"] = f"Identified Vulnerabilities: {vuln_list_str}"

        # Write SPDX JSON to file
        with open(output_file, 'w') as f:
            json.dump(spdx_data, f, indent=2)
        print(f"SPDX SBOM generated: {output_file}")

    def _generate_purl(self, name: str, version: str, package_type: str) -> str:
        """Generate a Package URL (purl) for a dependency"""
        type_map = {
            'npm': 'npm',
            'pypi': 'pypi',
            'maven': 'maven', # Assuming maven group:artifact format
            'gradle': 'maven', # Gradle often resolves to Maven
            'go': 'golang'
            # Add more mappings as needed
        }
        purl_type = type_map.get(package_type, package_type)
        # Basic purl format. Does not encode special characters.
        return f"pkg:{purl_type}/{name}@{version}"

    def scan_directory(self, directory: str = '.') -> List[Dict]:
        """Scan directory for dependency files and analyze them"""
        results = []
        # Find dependency files
        dep_files = []
        transitive_dep_files = [] # To store files for transitive deps
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file in ['package.json', 'requirements.txt', 'pyproject.toml', 'pom.xml', 'build.gradle', 'go.mod']:
                    dep_files.append(os.path.join(root, file))
                elif file == 'go.sum': # Special handling for Go transitive deps
                     transitive_dep_files.append(os.path.join(root, file))
                # TODO: Add handling for npm lock files, pipenv lock files, poetry.lock etc. for transitive deps

        all_deps = []
        for file_path in dep_files:
            if file_path.endswith('package.json'):
                all_deps.extend(self.parse_package_json(file_path))
            elif file_path.endswith('requirements.txt'):
                all_deps.extend(self.parse_requirements_txt(file_path))
            elif file_path.endswith('pyproject.toml'):
                all_deps.extend(self.parse_pyproject_toml(file_path))
            elif file_path.endswith('pom.xml'):
                all_deps.extend(self.parse_pom_xml(file_path))
            elif file_path.endswith('build.gradle'):
                all_deps.extend(self.parse_build_gradle(file_path))
            elif file_path.endswith('go.mod'):
                all_deps.extend(self.parse_go_mod(file_path))

        # --- NEW: Attempt to add transitive dependencies for Go ---
        # This is a simple approach using go.sum. A more robust way would be `go list -m all`.
        for file_path in transitive_dep_files:
             if file_path.endswith('go.sum'):
                 # Parse go.sum for *all* modules
                 transitive_deps = self.parse_go_sum(file_path)
                 # Add transitive deps, potentially marking them
                 for dep in transitive_deps:
                     # Avoid duplicates if a transitive dep is also a direct dep
                     # This is a simple check, might not be perfect
                     is_direct = any(d['name'] == dep['name'] and d['version'] == dep['version'] for d in all_deps)
                     if not is_direct:
                         dep['source'] = 'transitive' # Mark as transitive
                         all_deps.append(dep)
                     # else: It's a direct dependency, already analyzed

        # Analyze each dependency
        for dep in all_deps:
            print(f"Analyzing {dep['name']} ({dep['version']}) [{dep['type']}]{' (Transitive)' if dep.get('source') == 'transitive' else ''}...")
            # Get vulnerabilities
            vulns = self.get_osv_vulnerabilities(dep['name'], dep['version'], dep['type'])
            # Enhance vulnerability data
            enhanced_vulns = []
            for vuln in vulns:
                enhanced_vuln = vuln.copy()
                vuln_id = vuln.get('id')
                # Get CVSS score and store it in the enhanced vuln object
                cvss_score = self.get_cvss_score(vuln)
                enhanced_vuln['cvss_score'] = cvss_score
                # Initialize fields for additional data
                enhanced_vuln['cve_id'] = 'N/A'
                enhanced_vuln['severity'] = 'N/A'
                enhanced_vuln['epss_score'] = None
                # --- MODIFIED: Fetch CVE ID and NVD CVSS Score ---
                # Priority: 1. Direct CVE ID (if vuln_id is CVE-*) or from GitHub Advisory
                #           2. CVE ID from PYSEC
                #           3. Fetch NVD CVSS based on found CVE ID
                if vuln_id and vuln_id.startswith('GHSA-'):
                    # Fetch details from GitHub Advisory
                    ghsa_details = self.get_github_advisory_details(vuln_id)
                    enhanced_vuln.update(ghsa_details)
                    # If CVE ID was found, get EPSS and NVD CVSS for it
                    if enhanced_vuln['cve_id'] and enhanced_vuln['cve_id'] != 'N/A':
                        epss = self.get_epss_score(enhanced_vuln['cve_id'])
                        if epss is not None:
                            enhanced_vuln['epss_score'] = epss
                        # Fetch CVSS from NVD API (now using the key)
                        nvd_cvss = self.get_nvd_cvss_score(enhanced_vuln['cve_id'])
                        if nvd_cvss is not None:
                            enhanced_vuln['cvss_score'] = nvd_cvss
                        else:
                            # Fallback to webpage scraping if API fails
                            nvd_cvss_fallback = self.get_nvd_cvss_score_from_webpage(enhanced_vuln['cve_id'])
                            if nvd_cvss_fallback is not None:
                                enhanced_vuln['cvss_score'] = nvd_cvss_fallback
                elif vuln_id and vuln_id.startswith('CVE-'):
                    # For CVEs, directly get EPSS, set CVE ID, and fetch NVD CVSS
                    enhanced_vuln['cve_id'] = vuln_id
                    epss = self.get_epss_score(vuln_id)
                    if epss is not None:
                        enhanced_vuln['epss_score'] = epss
                    # Fetch CVSS from NVD API (now using the key)
                    nvd_cvss = self.get_nvd_cvss_score(vuln_id)
                    if nvd_cvss is not None:
                        enhanced_vuln['cvss_score'] = nvd_cvss
                    else:
                        # Fallback to webpage scraping if API fails
                        nvd_cvss_fallback = self.get_nvd_cvss_score_from_webpage(vuln_id)
                        if nvd_cvss_fallback is not None:
                            enhanced_vuln['cvss_score'] = nvd_cvss_fallback
                elif vuln_id and vuln_id.startswith('PYSEC-'):
                    # For PYSEC, get associated CVE and fetch CVSS from NVD
                    # --- MODIFIED: Use the new get_cve_from_pysec function ---
                    cve_id = self.get_cve_from_pysec(vuln_id)
                    if cve_id:
                        enhanced_vuln['cve_id'] = cve_id
                        # Fetch CVSS from NVD API (now using the key)
                        nvd_cvss = self.get_nvd_cvss_score(cve_id)
                        if nvd_cvss is not None:
                            enhanced_vuln['cvss_score'] = nvd_cvss
                        else:
                            # Fallback to webpage scraping if API fails
                            nvd_cvss_fallback = self.get_nvd_cvss_score_from_webpage(cve_id)
                            if nvd_cvss_fallback is not None:
                                enhanced_vuln['cvss_score'] = nvd_cvss_fallback
                        # Get EPSS score
                        epss = self.get_epss_score(cve_id)
                        if epss is not None:
                            enhanced_vuln['epss_score'] = epss
                # Add vulnerability link
                enhanced_vuln['link'] = self.get_vulnerability_link(vuln_id) if vuln_id else None
                enhanced_vulns.append(enhanced_vuln)
            # Get package info
            if dep['type'] == 'npm':
                pkg_info = self.get_npm_package_info(dep['name'])
            elif dep['type'] == 'pypi':
                pkg_info = self.get_pypi_package_info(dep['name'])
            else:
                pkg_info = {} # Placeholder for other ecosystems
            # Extract licenses (basic implementation)
            licenses = []
            if dep['type'] == 'npm' and 'license' in pkg_info:
                license_field = pkg_info['license']
                if isinstance(license_field, str):
                    licenses = [license_field]
                elif isinstance(license_field, list):
                    licenses = license_field
            elif dep['type'] == 'pypi' and 'info' in pkg_info:
                license_str = pkg_info['info'].get('license', '')
                if license_str:
                    # PyPI license field can be complex, often just a string name
                    licenses = [license_str]
            # TODO: Extract licenses for Maven and Go if possible (might require parsing POMs or using APIs)
            # Analyze license risk
            license_info = self.analyze_license_risk(licenses)
            # Analyze maintenance
            maintenance_info = self.analyze_maintenance(pkg_info)
            # Check if fork
            is_fork = self.is_fork(pkg_info)
            # --- NEW: Get latest version ---
            latest_version = self.get_latest_version(dep['name'], dep['type'])
            # Calculate risk score using the enhanced vulnerabilities (with pre-fetched CVSS)
            # The calculate_risk_score method now also considers EPSS
            risk_score = self.calculate_risk_score(enhanced_vulns, license_info['risk_level'],
                                                 maintenance_info['maintenance_score'], is_fork)
            # Build result with full enhanced vulnerability details for later use
            result = {
                'name': dep['name'],
                'version': dep['version'],
                'type': dep['type'],
                'source_file': dep.get('source_file', 'N/A'), # Add source file path
                'vulnerabilities': enhanced_vulns, # Pass full enhanced vuln object
                'license_info': license_info,
                'maintenance_info': maintenance_info,
                'is_fork': is_fork,
                'risk_score': risk_score,
                'latest_version': latest_version # Add latest version to the result
            }
            # Add transitive marker if present
            if dep.get('source') == 'transitive':
                result['source'] = 'transitive'

            results.append(result)
        return results

def main():
    parser = argparse.ArgumentParser(
        description='Bharat-SCA: Dependency License & Risk Radar',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --audit --dir ./my_project
  %(prog)s --audit --output report.md
  %(prog)s --audit --nvd-api-key your_api_key_here
  %(prog)s --audit --sbom-output sbom.spdx.json
        """
    )
    parser.add_argument('--audit', action='store_true', help='Audit dependencies')
    parser.add_argument('--output', type=str, default='security.html', help='Output file (html, markdown or JSON)')
    parser.add_argument('--dir', type=str, default='.', help='Directory to scan')
    # Add argument for NVD API key
    parser.add_argument('--nvd-api-key', type=str, help='NVD API key for improved rate limits and access')
    # Add argument for SPDX SBOM output
    parser.add_argument('--sbom-output', type=str, help='Generate SBOM in SPDX format (e.g., sbom.spdx.json)')
    args = parser.parse_args()

    if not args.audit:
        parser.print_help()
        return

    # Pass the NVD API key to the DependencyRadar instance
    radar = DependencyRadar(nvd_api_key=args.nvd_api_key)
    results = radar.scan_directory(args.dir)

    # Sort by risk score (highest first)
    results.sort(key=lambda x: x['risk_score'], reverse=True)

    # Generate main output report
    if args.output:
        if args.output.endswith('.json'):
            radar.generate_json_output(results, args.output)
        elif args.output.endswith('.md'):
            radar.generate_markdown_report(results, args.output)
        else:  # Default to HTML
            radar.generate_html_report(results, args.output)
        print(f"Report generated: {args.output}")

    # Generate SPDX SBOM if requested
    if args.sbom_output:
        radar.generate_spdx_sbom(results, args.sbom_output)

    # Print summary to console
    high_risk = sum(1 for r in results if r['risk_score'] >= 80)
    if high_risk > 0:
        print(f"\n⚠️  {high_risk} high-risk dependencies found!")
        print("Check the report for details.")

if __name__ == '__main__':
    main()
