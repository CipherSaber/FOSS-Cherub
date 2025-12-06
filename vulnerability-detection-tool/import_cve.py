#!/usr/bin/env python3
# import_cve.py - Import CVE and CWE data into PostgreSQL (FIXED)

import requests
import zipfile
import gzip
import json
import xml.etree.ElementTree as ET
from pathlib import Path
import psycopg2
from psycopg2.extras import execute_batch
from datetime import datetime
import sys

# Configuration
DB_CONFIG = {
    'host': 'foss-cherub-db',
    'port': 5432,
    'database': 'foss_cherub',
    'user': 'postgres',
    'password': 'foss_cherub_2024'
}

# Data Sources
NVD_CVE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
YEARS = range(2002, 2026)  # CVE years to import

class CVEImporter:
    def __init__(self, db_config):
        self.conn = psycopg2.connect(**db_config)
        self.cursor = self.conn.cursor()

    def download_file(self, url, filename):
        """Download file from URL"""
        print(f"Downloading {filename}...")
        try:
            response = requests.get(url, stream=True, timeout=300)
            response.raise_for_status()

            with open(filename, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print(f"✓ Downloaded {filename}")
            return True
        except Exception as e:
            print(f"✗ Failed to download {filename}: {e}")
            return False

    def import_cwe_data(self):
        """Import CWE data from MITRE"""
        print("\n" + "="*70)
        print("Importing CWE Data")
        print("="*70)

        zip_file = "cwec_latest.xml.zip"
        if not self.download_file(CWE_URL, zip_file):
            return

        # Extract XML
        with zipfile.ZipFile(zip_file, 'r') as zip_ref:
            xml_files = [f for f in zip_ref.namelist() if f.endswith('.xml')]
            if xml_files:
                zip_ref.extract(xml_files[0], '.')
                xml_file = xml_files[0]

        print(f"Parsing {xml_file}...")
        tree = ET.parse(xml_file)
        root = tree.getroot()

        # Get namespace
        ns = {'': 'http://cwe.mitre.org/cwe-7'}

        cwe_data = []
        for weakness in root.findall('.//Weakness', ns):
            cwe_id = f"CWE-{weakness.get('ID')}"
            name = weakness.get('Name', '')

            description_elem = weakness.find('.//Description', ns)
            description = description_elem.text if description_elem is not None else ''

            # Extract mitigations
            mitigations = []
            for mitigation in weakness.findall('.//Mitigation', ns):
                desc_elem = mitigation.find('.//Description', ns)
                if desc_elem is not None and desc_elem.text:
                    mitigations.append({'description': desc_elem.text})

            # Match our simplified schema
            cwe_data.append((
                cwe_id,
                name,
                description,
                '',  # typical_severity (will be empty, we have 7 pre-populated)
                json.dumps(mitigations) if mitigations else None
            ))

        # Insert into database using our actual schema
        print(f"Inserting {len(cwe_data)} CWEs...")
        query = """
            INSERT INTO cwe (cwe_id, name, description, typical_severity, potential_mitigations)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (cwe_id) DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                potential_mitigations = EXCLUDED.potential_mitigations
        """

        execute_batch(self.cursor, query, cwe_data, page_size=100)
        self.conn.commit()
        print(f"✓ Imported {len(cwe_data)} CWEs")

    def import_cve_data(self, year):
        """Import CVE data for a specific year"""
        print(f"\nImporting CVE data for {year}...")

        gz_file = f"nvdcve-1.1-{year}.json.gz"
        json_file = f"nvdcve-1.1-{year}.json"

        url = NVD_CVE_URL.format(year=year)
        if not self.download_file(url, gz_file):
            return

        # Decompress
        with gzip.open(gz_file, 'rb') as f_in:
            with open(json_file, 'wb') as f_out:
                f_out.write(f_in.read())

        # Parse JSON
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        cve_items = data.get('CVE_Items', [])
        print(f"Processing {len(cve_items)} CVEs...")

        cve_data = []
        for item in cve_items:
            cve_id = item['cve']['CVE_data_meta']['ID']

            # Get description
            descriptions = item['cve'].get('description', {}).get('description_data', [])
            description = descriptions[0].get('value', '') if descriptions else ''

            # Get CWE IDs
            cwe_ids = []
            for problem_type in item['cve'].get('problemtype', {}).get('problemtype_data', []):
                for desc in problem_type.get('description', []):
                    cwe_id = desc.get('value', '')
                    if cwe_id.startswith('CWE-'):
                        cwe_ids.append(cwe_id)

            # Get CVSS data
            cvss_data = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {})

            # Get dates
            published = item.get('publishedDate', '')
            modified = item.get('lastModifiedDate', '')

            # Match our simplified schema
            cve_data.append((
                cve_id,
                description,
                cvss_data.get('baseScore', 0.0),
                cvss_data.get('baseSeverity', ''),
                cvss_data.get('vectorString', ''),
                published,
                cwe_ids  # PostgreSQL array
            ))

        # Insert into database
        query = """
            INSERT INTO cve (cve_id, description, cvss_base_score, cvss_base_severity,
                           cvss_vector_string, published_date, cwe_ids)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (cve_id) DO UPDATE SET
                description = EXCLUDED.description,
                cvss_base_score = EXCLUDED.cvss_base_score,
                cvss_base_severity = EXCLUDED.cvss_base_severity
        """

        execute_batch(self.cursor, query, cve_data, page_size=100)
        self.conn.commit()
        print(f"✓ Imported {len(cve_data)} CVEs for {year}")

    def run_full_import(self):
        """Run full import of CWE and CVE data"""
        print("="*70)
        print("FOSS-CHERUB CVE/CWE Data Import")
        print("="*70)

        # Import CWE data first
        try:
            self.import_cwe_data()
        except Exception as e:
            print(f"✗ CWE import failed: {e}")
            import traceback
            traceback.print_exc()

        # Import CVE data by year
        print("\n" + "="*70)
        print("Importing CVE Data")
        print("="*70)

        for year in YEARS:
            try:
                self.import_cve_data(year)
            except Exception as e:
                print(f"✗ Failed to import CVE data for {year}: {e}")
                continue

        # Print statistics
        print("\n" + "="*70)
        print("Import Statistics")
        print("="*70)

        self.cursor.execute("SELECT COUNT(*) FROM cwe")
        cwe_count = self.cursor.fetchone()[0]
        print(f"Total CWEs: {cwe_count:,}")

        self.cursor.execute("SELECT COUNT(*) FROM cve")
        cve_count = self.cursor.fetchone()[0]
        print(f"Total CVEs: {cve_count:,}")

        self.cursor.execute("SELECT cvss_base_severity, COUNT(*) FROM cve GROUP BY cvss_base_severity")
        print("\nCVEs by Severity:")
        for severity, count in self.cursor.fetchall():
            print(f"  {severity or 'Unknown':10s}: {count:,}")

        print("\n✅ Import Complete!")

    def close(self):
        self.cursor.close()
        self.conn.close()

if __name__ == "__main__":
    print("\n⚠️  Note: This will download several GB of data and may take hours.")
    response = input("Continue? (yes/no): ")

    if response.lower() != 'yes':
        print("Import cancelled.")
        sys.exit(0)

    importer = CVEImporter(DB_CONFIG)
    try:
        importer.run_full_import()
    except KeyboardInterrupt:
        print("\n\nImport interrupted by user.")
    except Exception as e:
        print(f"\n\nImport failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        importer.close()
