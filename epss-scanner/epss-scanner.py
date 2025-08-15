#!/usr/bin/env python3
"""
EPSS Prioritizer
Standalone utility to analyze an SPDX SBOM and prioritize CVEs by EPSS score.
"""
import json
import sys
import os
import requests
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional
from bs4 import BeautifulSoup
import re

class EPPSPrioritizer:
    def __init__(self):
        pass

    def parse_spdx_sbom(self, sbom_file_path: str) -> List[Dict[str, str]]:
        """Parse an SPDX SBOM (JSON format) to extract components."""
        components = []
        try:
            with open(sbom_file_path, 'r') as f:
                sbom_data = json.load(f)

            packages = sbom_data.get('packages', [])
            for package in packages:
                comp_name = package.get('name')
                comp_version = package.get('versionInfo', 'latest')
                
                # Attempt to infer package type from PURL
                purl = None
                package_manager = 'unknown'
                external_refs = package.get('externalRefs', [])
                for ref in external_refs:
                    if ref.get('referenceType') == 'purl':
                        purl = ref.get('referenceLocator')
                        # Infer package manager from PURL
                        if purl.startswith('pkg:npm/'):
                            package_manager = 'npm'
                        elif purl.startswith('pkg:pypi/'):
                            package_manager = 'pypi'
                        elif purl.startswith('pkg:maven/'):
                            package_manager = 'maven'
                        elif purl.startswith('pkg:golang/'):
                            package_manager = 'go'
                        # Add more PURL types as needed
                        break

                # Fallback type inference based on name if PURL not helpful
                if package_manager == 'unknown':
                    if ':' in comp_name and len(comp_name.split(':')) >= 2:
                        package_manager = 'maven' # Heuristic

                if comp_name:
                    components.append({
                        'name': comp_name,
                        'version': comp_version,
                        'package_manager': package_manager,
                        'purl': purl
                    })
            return components
        except Exception as e:
            print(f"Error parsing SPDX SBOM {sbom_file_path}: {e}")
            return []

    def _map_package_manager_to_osv_ecosystem(self, package_manager: str) -> str:
        """Map package manager name to OSV ecosystem name."""
        ecosystem_map = {
            'npm': 'npm',
            'pypi': 'PyPI',
            'maven': 'Maven',
            'gradle': 'Maven', # Gradle resolves to Maven in OSV
            'go': 'Go'
            # Add more mappings as needed
        }
        return ecosystem_map.get(package_manager, package_manager)

    def get_osv_vulnerabilities(self, package_name: str, version: str, package_manager: str) -> List[Dict]:
        """Query OSV database for vulnerabilities."""
        try:
            url = "https://api.osv.dev/v1/query"
            ecosystem = self._map_package_manager_to_osv_ecosystem(package_manager)
            
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
                if response.status_code != 404:
                    print(f"  OSV API error for {package_name}@{version} [{ecosystem}]: {response.status_code}")
                return []
        except Exception as e:
            print(f"  Error fetching OSV data for {package_name}@{version}: {e}")
            return []

    def extract_cve_ids(self, osv_vulns: List[Dict]) -> List[str]:
        """Extract CVE IDs from OSV vulnerability response."""
        cve_ids = []
        for vuln in osv_vulns:
            vuln_id = vuln.get('id')
            if vuln_id and vuln_id.startswith('CVE-'):
                if vuln_id not in cve_ids: # Avoid duplicates from this source
                    cve_ids.append(vuln_id)
            elif vuln_id:
                # Check aliases for CVEs if the main ID isn't a CVE
                aliases = vuln.get('aliases', [])
                for alias in aliases:
                    if alias.startswith('CVE-') and alias not in cve_ids:
                        cve_ids.append(alias)
        return cve_ids

    def get_epss_score(self, cve_id: str) -> Optional[float]:
        """Get EPSS score for a CVE from First.org."""
        try:
            cve_id = cve_id.strip()
            if not cve_id.startswith("CVE-"):
                 return None

            url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
            response = requests.get(url, timeout=20)

            if response.status_code == 200:
                data = response.json()
                if 'data' in data and len(data['data']) > 0 and 'epss' in data['data'][0]:
                    epss_str = data['data'][0]['epss']
                    if epss_str:
                        return float(epss_str)
            return None
        except requests.exceptions.Timeout:
            print(f"    ERROR: Timeout while fetching EPSS for {cve_id}")
            return None
        except requests.exceptions.RequestException as e:
            print(f"    ERROR: Network error fetching EPSS for {cve_id}: {e}")
            return None
        except ValueError as e:
            print(f"    ERROR: Value error processing EPSS data for {cve_id}: {e}")
            return None
        except Exception as e:
            print(f"    ERROR: Unexpected error fetching EPSS for {cve_id}: {e}")
            return None

    def get_cve_details(self, cve_id: str) -> Dict[str, Any]:
        """Get CVE description and CVSS score from NVD."""
        details = {'description': 'N/A', 'cvss_score': 'N/A'}
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                if 'vulnerabilities' in data and len(data['vulnerabilities']) > 0:
                    vuln = data['vulnerabilities'][0]
                    # Get description
                    descriptions = vuln.get('cve', {}).get('descriptions', [])
                    if descriptions:
                        # Prefer English description
                        en_desc = next((d['value'] for d in descriptions if d.get('lang') == 'en'), None)
                        details['description'] = en_desc if en_desc else descriptions[0].get('value', 'N/A')
                    
                    # Get CVSS score
                    metrics = vuln.get('cve', {}).get('metrics', {})
                    # Try CVSS v3.1 first
                    if 'cvssMetricV31' in metrics:
                        details['cvss_score'] = float(metrics['cvssMetricV31'][0]['cvssData']['baseScore'])
                    # Try CVSS v3.0
                    elif 'cvssMetricV30' in metrics:
                        details['cvss_score'] = float(metrics['cvssMetricV30'][0]['cvssData']['baseScore'])
                    # Try CVSS v2.0
                    elif 'cvssMetricV2' in metrics:
                        details['cvss_score'] = float(metrics['cvssMetricV2'][0]['cvssData']['baseScore'])
            return details
        except Exception as e:
            print(f"    Error fetching details for {cve_id} from NVD: {e}")
            return details

    def get_latest_version(self, package_name: str, package_manager: str) -> Optional[str]:
        """Get the latest version of a package."""
        try:
            if package_manager == 'npm':
                url = f"https://registry.npmjs.org/{package_name}"
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if 'dist-tags' in data and 'latest' in data['dist-tags']:
                        return data['dist-tags']['latest']
            elif package_manager == 'pypi':
                url = f"https://pypi.org/pypi/{package_name}/json"
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if 'info' in data and 'version' in data['info']:
                        return data['info']['version']
            elif package_manager == 'maven':
                return "Check Maven Central"
            elif package_manager == 'go':
                return "Check Go Module Proxy"
            return "N/A"
        except Exception as e:
            print(f"    Error fetching latest version for {package_name} ({package_manager}): {e}")
            return "Error"

    def prioritize_cves(self, sbom_file_path: str) -> List[Dict]:
        """
        Main function to prioritize CVEs from an SBOM based on EPSS.
        """
        print(f"Analyzing SBOM for EPSS prioritization: {sbom_file_path}")
        components = self.parse_spdx_sbom(sbom_file_path)
        if not components:
            print("No components found in SBOM.")
            return []

        print(f"Found {len(components)} components. Querying OSV for vulnerabilities...")
        cve_to_components = {} # Map CVE ID to list of components

        total_components = len(components)
        for idx, component in enumerate(components, 1):
            name = component['name']
            version = component['version']
            pkg_manager = component['package_manager']
            print(f"  [{idx}/{total_components}] Checking {name}@{version} ({pkg_manager})...")
            
            vulns = self.get_osv_vulnerabilities(name, version, pkg_manager)
            cve_ids = self.extract_cve_ids(vulns)
            
            for cve_id in cve_ids:
                if cve_id not in cve_to_components:
                    cve_to_components[cve_id] = []
                if component not in cve_to_components[cve_id]:
                     cve_to_components[cve_id].append(component)

        unique_cve_count = len(cve_to_components)
        if unique_cve_count == 0:
            print("No CVEs found for any components in the SBOM.")
            return []

        print(f"Found {unique_cve_count} unique CVEs. Fetching EPSS scores and details...")
        prioritized_cve_data = []
        cve_counter = 0
        for cve_id, affected_components in cve_to_components.items():
            cve_counter += 1
            print(f"  [{cve_counter}/{unique_cve_count}] Fetching data for {cve_id}...")
            epss_score = self.get_epss_score(cve_id)
            cve_details = self.get_cve_details(cve_id)
            
            # Get latest versions for affected components
            enriched_components = []
            for comp in affected_components:
                latest_ver = self.get_latest_version(comp['name'], comp['package_manager'])
                enriched_components.append({
                    **comp,
                    'latest_version': latest_ver
                })

            prioritized_cve_data.append({
                'cve_id': cve_id,
                'epss_score': epss_score,
                'cvss_score': cve_details.get('cvss_score'),
                'description': cve_details.get('description'),
                'components': enriched_components
            })
        
        # Sort by EPSS score descending (None scores go last)
        sorted_cve_data = sorted(prioritized_cve_data, key=lambda x: x.get('epss_score') or -1.0, reverse=True)
        print("EPSS prioritization complete.")
        return sorted_cve_data

    def generate_report(self, sorted_cve_data: List[Dict], output_file: str, format: str = 'html'):
        """Generate a report sorted by EPSS score."""
        if format == 'json':
            self._generate_json_report(sorted_cve_data, output_file)
        elif format == 'markdown':
            self._generate_markdown_report(sorted_cve_data, output_file)
        else: # Default to HTML
            self._generate_html_report(sorted_cve_data, output_file)

        # --- CORRECTED METHOD SIGNATURE AND IMPROVED CHART SCRIPT ---
    def _generate_html_report(self, sorted_cve_data: List[Dict], output_file: str):
        """Generate HTML report with summary, charts, and details."""
        # --- Summary Statistics ---
        total_cves = len(sorted_cve_data)
        high_epss_count = sum(1 for item in sorted_cve_data if (item.get('epss_score') or 0) >= 0.5)
        medium_epss_count = sum(1 for item in sorted_cve_data if 0.1 <= (item.get('epss_score') or 0) < 0.5)
        low_epss_count = sum(1 for item in sorted_cve_data if (item.get('epss_score') or -1) < 0.1) # Includes None

        # --- Chart Data (as JSON strings for safer JS injection) ---
        import json # Make sure json is imported at the top of your file, or import it here locally
        chart_labels_json = json.dumps(["High (>=0.5)", "Medium (0.1-0.49)", "Low/None (<0.1)"])
        chart_data_json = json.dumps([high_epss_count, medium_epss_count, low_epss_count])
        chart_colors_json = json.dumps(["#dc3545", "#ffc107", "#28a745"]) # Red, Yellow, Green

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EPSS Prioritizer Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
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
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background-color: #f5f7fa; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, var(--primary), #0056b3); color: white; padding: 20px; text-align: center; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        h1 {{ font-size: 2rem; margin-bottom: 10px; }}
        .subtitle {{ font-size: 1rem; opacity: 0.9; }}
        .timestamp {{ font-size: 0.9rem; color: #e9ecef; margin-top: 5px; }}
        
        .section {{ background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
        .section-title {{ font-size: 1.5rem; margin-bottom: 15px; color: var(--dark); border-bottom: 2px solid var(--light); padding-bottom: 8px; }}
        
        .exec-summary {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        .summary-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }}
        .card {{ background: #f8f9fa; border-left: 5px solid var(--primary); padding: 15px; border-radius: 0 5px 5px 0; }}
        .card.high {{ border-left-color: var(--danger); }}
        .card.medium {{ border-left-color: var(--warning); }}
        .card.low {{ border-left-color: var(--success); }}
        .card-number {{ font-size: 2rem; font-weight: bold; }}
        .card-label {{ font-size: 0.9rem; color: #666; }}
        
        .chart-container {{ height: 300px; position: relative; }} /* Added position: relative */
        
        .epss-table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        .epss-table th {{ background-color: var(--primary); color: white; text-align: left; padding: 12px 15px; font-weight: 600; }}
        .epss-table td {{ padding: 12px 15px; border-bottom: 1px solid #eee; }}
        .epss-table tr:hover {{ background-color: #f8f9fa; }}
        .epss-score {{ font-weight: bold; padding: 4px 8px; border-radius: 4px; }}
        .epss-high {{ background-color: #f8d7da80; color: #721c24; }}
        .epss-medium {{ background-color: #fff3cd80; color: #856404; }}
        .epss-low {{ background-color: #d4edda80; color: #155724; }}
        .epss-none {{ background-color: #e2e3e580; color: #383d41; }}
        .cve-link {{ color: var(--primary); text-decoration: none; font-weight: 500; }}
        .cve-link:hover {{ text-decoration: underline; }}
        .component-details {{ font-size: 0.85rem; margin-top: 5px; }}
        .component-name {{ font-weight: 500; }}
        .no-data {{ color: #6c757d; font-style: italic; }}
        .cve-description {{ font-size: 0.9rem; color: #555; margin-top: 8px; }}
        
        .footer {{ text-align: center; padding: 15px; color: #666; font-size: 0.8rem; margin-top: 20px; }}
        
        @media (max-width: 768px) {{
            .exec-summary {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>EPSS Prioritizer Report</h1>
            <div class="subtitle">Vulnerabilities Ranked by Exploit Probability</div>
            <div class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </header>

        <div class="section">
            <h2 class="section-title">Executive Summary</h2>
            <div class="exec-summary">
                <div>
                    <div class="summary-cards">
                        <div class="card high">
                            <div class="card-number">{high_epss_count}</div>
                            <div class="card-label">High EPSS (>= 0.5)</div>
                        </div>
                        <div class="card medium">
                            <div class="card-number">{medium_epss_count}</div>
                            <div class="card-label">Medium EPSS (0.1 - 0.49)</div>
                        </div>
                        <div class="card low">
                            <div class="card-number">{low_epss_count}</div>
                            <div class="card-label">Low/No EPSS (< 0.1)</div>
                        </div>
                        <div class="card">
                            <div class="card-number">{total_cves}</div>
                            <div class="card-label">Total Unique CVEs</div>
                        </div>
                    </div>
                    <p><strong>Key Insights:</strong></p>
                    <ul>
                        <li>Prioritize fixing vulnerabilities with <span style="color:var(--danger); font-weight:bold;">High EPSS scores</span> first, as they have the highest probability of being exploited.</li>
                        <li>Vulnerabilities with <span style="color:var(--warning); font-weight:bold;">Medium EPSS scores</span> should be addressed in the next phase.</li>
                        <li>Those with Low/No EPSS data can be reviewed later or if other factors (CVSS, asset criticality) indicate higher risk.</li>
                    </ul>
                </div>
                <div>
                    <h3>EPSS Score Distribution</h3>
                    <div class="chart-container">
                        <canvas id="epssChart"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">Prioritized CVE List</h2>
            <table class="epss-table">
                <thead>
                    <tr>
                        <th>CVE ID</th>
                        <th>EPSS Score</th>
                        <th>CVSS Score</th>
                        <th>Description</th>
                        <th>Affected Components</th>
                    </tr>
                </thead>
                <tbody>
"""
        for item in sorted_cve_data:
            cve_id = item['cve_id']
            epss_score = item.get('epss_score')
            cvss_score = item.get('cvss_score')
            description = item.get('description', 'N/A')
            components = item.get('components', [])

            # Determine EPSS styling
            if epss_score is None:
                epss_class = "epss-none"
                epss_display = "<span class='no-data'>No Data</span>"
            elif epss_score >= 0.5:
                epss_class = "epss-high"
                epss_display = f"{epss_score:.4f}"
            elif epss_score >= 0.1:
                epss_class = "epss-medium"
                epss_display = f"{epss_score:.4f}"
            else:
                epss_class = "epss-low"
                epss_display = f"{epss_score:.4f}"
            
            # CVSS Display
            cvss_display = f"{cvss_score:.1f}" if isinstance(cvss_score, (int, float)) else "<span class='no-data'>N/A</span>"

            # Truncate description
            truncated_desc = (description[:200] + '...') if len(description) > 200 else description

            # Format component list
            component_rows = ""
            if components:
                for c in components:
                    comp_name = c['name']
                    comp_version = c['version']
                    comp_pm = c.get('package_manager', 'N/A')
                    comp_latest = c.get('latest_version', 'N/A')
                    component_rows += f"""
                    <div class="component-details">
                        <span class="component-name">{comp_name}</span> 
                        (<span title="Current Version">v{comp_version}</span> | 
                         <span title="Latest Version">Latest: {comp_latest}</span> | 
                         <span title="Package Manager">{comp_pm}</span>)
                    </div>
                    """
            else:
                component_rows = "<div class='no-data'>Component info not available</div>"

            html_content += f"""
                <tr>
                    <td><a href="https://nvd.nist.gov/vuln/detail/{cve_id}" target="_blank" class="cve-link">{cve_id}</a></td>
                    <td><span class="epss-score {epss_class}">{epss_display}</span></td>
                    <td>{cvss_display}</td>
                    <td>
                        <div class="cve-description">{truncated_desc}</div>
                    </td>
                    <td>{component_rows}</td>
                </tr>
"""

        html_content += f"""
                </tbody>
            </table>
        </div>

        <div class="footer">
            <p>EPSS Prioritizer Report</p>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><small>Data sources: OSV.dev, First.org EPSS, NVD</small></p>
        </div>
    </div>

    <script>
        // --- CHART DATA INJECTED FROM PYTHON ---
        // Using JSON.parse for safer data handling
        const chartLabels = {chart_labels_json};
        const chartData = {chart_data_json};
        const chartColors = {chart_colors_json};
        // --- END OF CHART DATA ---

        // Function to render the EPSS distribution chart
        function renderEpssChart() {{
            console.log("Attempting to render chart...");
            console.log("Labels:", chartLabels);
            console.log("Data:", chartData);
            console.log("Colors:", chartColors);

            const ctxElement = document.getElementById('epssChart');
            if (!ctxElement) {{
                console.error("Chart canvas element with ID 'epssChart' not found.");
                return;
            }}
            const ctx = ctxElement.getContext('2d');
            if (!ctx) {{
                console.error("Unable to get 2D context for the chart canvas.");
                return;
            }}

            // Destroy existing chart instance if it exists (prevents duplication errors on reload)
            if (window.epssChartInstance) {{
                window.epssChartInstance.destroy();
            }}

            try {{
                // Create the chart instance and store it globally
                window.epssChartInstance = new Chart(ctx, {{
                    type: 'bar',
                    data: {{
                        labels: chartLabels,
                        datasets: [{{
                            label: 'Number of CVEs',
                            data: chartData,
                            backgroundColor: chartColors,
                            borderColor: chartColors,
                            borderWidth: 1
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {{
                            y: {{
                                beginAtZero: true,
                                ticks: {{
                                    stepSize: 1,
                                    precision: 0 // Ensure integer ticks on Y axis
                                }},
                                title: {{
                                    display: true,
                                    text: 'Number of CVEs'
                                }}
                            }}
                        }},
                        plugins: {{
                            legend: {{
                                display: false
                            }},
                            tooltip: {{
                                callbacks: {{
                                    label: function(context) {{
                                        let label = context.dataset.label || '';
                                        if (label) {{
                                            label += ': ';
                                        }}
                                        if (context.parsed.y !== null) {{
                                            label += context.parsed.y;
                                        }}
                                        return label;
                                    }}
                                }}
                            }}
                        }}
                    }}
                }});
                console.log("Chart rendered successfully.");
            }} catch (error) {{
                console.error("Error creating the chart:", error);
            }}
        }}

        // --- IMPROVED SCRIPT EXECUTION ---
        // Use Chart.js's built-in 'afterInit' event as a reliable trigger point
        // Or fallback to DOMContentLoaded/Window Load events
        console.log("Chart.js version loaded:", Chart.version); // Debug log

        // Method 1: Listen for Chart.js to be fully ready (if supported by the version)
        // Chart.register({{ id: 'afterInitPlugin', afterInit: renderEpssChart }});

        // Method 2: Standard event listeners with fallback
        function initChart() {{
            console.log("Initializing chart...");
            if (typeof Chart !== 'undefined' && Chart.defaults) {{
                renderEpssChart();
            }} else {{
                console.warn("Chart.js not ready, retrying in 100ms...");
                setTimeout(initChart, 100); // Retry after a short delay
            }}
        }}

        // Ensure the DOM is fully loaded before initializing
        if (document.readyState === 'loading') {{
            document.addEventListener('DOMContentLoaded', initChart);
        }} else {{
            // DOM is already loaded
            initChart();
        }}

        // Also try on window load as a final fallback
        window.addEventListener('load', initChart);
        // --- END OF IMPROVED SCRIPT EXECUTION ---
    </script>
</body>
</html>
"""
        with open(output_file, 'w') as f:
            f.write(html_content)
        print(f"Enhanced HTML report generated: {output_file}")


    def _generate_json_report(self, sorted_cve_data: List[Dict], output_file: str):
        """Generate JSON report."""
        output_data = {
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_cves': len(sorted_cve_data),
                'high_epss_count': sum(1 for item in sorted_cve_data if (item.get('epss_score') or 0) >= 0.5),
                'medium_epss_count': sum(1 for item in sorted_cve_data if 0.1 <= (item.get('epss_score') or 0) < 0.5),
                'low_epss_count': sum(1 for item in sorted_cve_data if (item.get('epss_score') or -1) < 0.1)
            },
            'cves': sorted_cve_data
        }
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        print(f"Enhanced JSON report generated: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='EPSS Prioritizer: Ranks SBOM CVEs by Exploit Probability',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --sbom my_sbom.spdx.json
  %(prog)s --sbom my_sbom.spdx.json --output-format markdown --output my_priorities.md
        """
    )
    parser.add_argument('--sbom', type=str, required=True, help='Path to the SPDX SBOM file (JSON format)')
    parser.add_argument('--output', type=str, default='epss_report.html', help='Output report file path')
    parser.add_argument('--output-format', choices=['html', 'markdown', 'json'], default='html', help='Output format (default: html)')
    
    args = parser.parse_args()

    if not os.path.isfile(args.sbom):
        print(f"Error: SBOM file '{args.sbom}' not found.", file=sys.stderr)
        sys.exit(1)

    prioritizer = EPPSPrioritizer()
    sorted_cve_data = prioritizer.prioritize_cves(args.sbom)

    if not sorted_cve_data:
        print("No CVEs were found or prioritized.")
        sys.exit(0)

    prioritizer.generate_report(sorted_cve_data, args.output, format=args.output_format)


if __name__ == '__main__':
    main()
