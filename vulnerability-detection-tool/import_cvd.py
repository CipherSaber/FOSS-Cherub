#!/usr/bin/env python3
# import_cve_nvd_api.py - Import CVEs using NVD API 2.0

import requests
import psycopg2
from psycopg2.extras import execute_batch
import json
import time
from datetime import datetime, timedelta
import sys

# ========== CONFIGURATION ==========
API_KEY = "0bda2a47-955a-429c-952a-238e9066f175"  # ← PUT YOUR API KEY HERE

DB_CONFIG = {
    'host': 'foss-cherub-db',
    'port': 5432,
    'database': 'foss_cherub',
    'user': 'postgres',
    'password': 'foss_cherub_2024'
}

# NVD API 2.0 Endpoint
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate limits (with API key: 50 requests/30 seconds)
REQUESTS_PER_30_SEC = 50
DELAY_BETWEEN_REQUESTS = 0.6  # 0.6 seconds = 50 requests per 30 seconds

class NVDImporter:
    def __init__(self, api_key, db_config):
        self.api_key = api_key
        self.conn = psycopg2.connect(**db_config)
        self.cursor = self.conn.cursor()
        self.request_count = 0
        self.start_time = time.time()

    def rate_limit(self):
        """Handle rate limiting"""
        self.request_count += 1

        # If we hit 50 requests, wait for 30 seconds
        if self.request_count >= REQUESTS_PER_30_SEC:
            elapsed = time.time() - self.start_time
            if elapsed < 30:
                wait_time = 30 - elapsed
                print(f"  Rate limit: waiting {wait_time:.1f} seconds...")
                time.sleep(wait_time)
            self.request_count = 0
            self.start_time = time.time()
        else:
            time.sleep(DELAY_BETWEEN_REQUESTS)

    def fetch_cves(self, start_index=0, results_per_page=2000):
        """Fetch CVEs from NVD API"""
        headers = {'apiKey': self.api_key} if self.api_key != "YOUR_API_KEY_HERE" else {}

        params = {
            'startIndex': start_index,
            'resultsPerPage': results_per_page
        }

        try:
            response = requests.get(NVD_API_URL, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Error fetching CVEs: {e}")
            return None

    def parse_cve(self, cve_item):
        """Parse CVE item from API response"""
        cve = cve_item.get('cve', {})
        cve_id = cve.get('id', '')

        # Description
        descriptions = cve.get('descriptions', [])
        description = ''
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break

        # CVSS scores (prefer v3.1, fallback to v3.0)
        cvss_score = 0.0
        cvss_severity = ''
        cvss_vector = ''

        metrics = cve.get('metrics', {})

        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            cvss_data = metrics['cvssMetricV31'][0]['cvssData']
            cvss_score = cvss_data.get('baseScore', 0.0)
            cvss_severity = cvss_data.get('baseSeverity', '')
            cvss_vector = cvss_data.get('vectorString', '')
        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            cvss_data = metrics['cvssMetricV30'][0]['cvssData']
            cvss_score = cvss_data.get('baseScore', 0.0)
            cvss_severity = cvss_data.get('baseSeverity', '')
            cvss_vector = cvss_data.get('vectorString', '')

        # CWE IDs
        cwe_ids = []
        weaknesses = cve.get('weaknesses', [])
        for weakness in weaknesses:
            for desc in weakness.get('description', []):
                cwe_value = desc.get('value', '')
                if cwe_value.startswith('CWE-') and cwe_value not in cwe_ids:
                    cwe_ids.append(cwe_value)

        # Published date
        published = cve.get('published', '')

        return {
            'cve_id': cve_id,
            'description': description,
            'cvss_score': cvss_score,
            'cvss_severity': cvss_severity,
            'cvss_vector': cvss_vector,
            'published_date': published,
            'cwe_ids': cwe_ids
        }

    def import_cves(self, max_results=None):
        """Import CVEs from NVD API"""
        print("="*70)
        print("NVD API 2.0 CVE Import")
        print("="*70)

        if self.api_key == "YOUR_API_KEY_HERE":
            print("⚠️  WARNING: Using API without key (slow rate limit)")
            print("   Get a free API key at: https://nvd.nist.gov/developers/request-an-api-key")
            print()

        start_index = 0
        results_per_page = 2000
        total_imported = 0

        while True:
            print(f"\nFetching CVEs {start_index} to {start_index + results_per_page}...")

            data = self.fetch_cves(start_index, results_per_page)
            if not data:
                break

            vulnerabilities = data.get('vulnerabilities', [])
            if not vulnerabilities:
                print("No more CVEs to fetch.")
                break

            print(f"Processing {len(vulnerabilities)} CVEs...")

            cve_batch = []
            for vuln in vulnerabilities:
                try:
                    cve_data = self.parse_cve(vuln)
                    cve_batch.append((
                        cve_data['cve_id'],
                        cve_data['description'],
                        cve_data['cvss_score'],
                        cve_data['cvss_severity'],
                        cve_data['cvss_vector'],
                        cve_data['published_date'],
                        cve_data['cwe_ids']
                    ))
                except Exception as e:
                    print(f"  Error parsing CVE: {e}")
                    continue

            # Insert batch into database
            query = """
                INSERT INTO cve (cve_id, description, cvss_base_score, cvss_base_severity,
                               cvss_vector_string, published_date, cwe_ids)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (cve_id) DO UPDATE SET
                    description = EXCLUDED.description,
                    cvss_base_score = EXCLUDED.cvss_base_score,
                    cvss_base_severity = EXCLUDED.cvss_base_severity,
                    cvss_vector_string = EXCLUDED.cvss_vector_string,
                    published_date = EXCLUDED.published_date,
                    cwe_ids = EXCLUDED.cwe_ids
            """

            execute_batch(self.cursor, query, cve_batch, page_size=100)
            self.conn.commit()

            total_imported += len(cve_batch)
            print(f"✓ Imported {len(cve_batch)} CVEs (Total: {total_imported:,})")

            # Check if we should continue
            total_results = data.get('totalResults', 0)
            start_index += results_per_page

            if start_index >= total_results:
                print(f"\nReached end of results (Total: {total_results:,})")
                break

            if max_results and total_imported >= max_results:
                print(f"\nReached max results limit ({max_results:,})")
                break

            # Rate limiting
            self.rate_limit()

        return total_imported

    def get_statistics(self):
        """Print import statistics"""
        print("\n" + "="*70)
        print("Import Statistics")
        print("="*70)

        self.cursor.execute("SELECT COUNT(*) FROM cve")
        total = self.cursor.fetchone()[0]
        print(f"Total CVEs in database: {total:,}")

        self.cursor.execute("""
            SELECT cvss_base_severity, COUNT(*) 
            FROM cve 
            WHERE cvss_base_severity IS NOT NULL AND cvss_base_severity != ''
            GROUP BY cvss_base_severity 
            ORDER BY 
                CASE cvss_base_severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                END
        """)

        print("\nCVEs by Severity:")
        for severity, count in self.cursor.fetchall():
            print(f"  {severity:10s}: {count:,}")

        self.cursor.execute("""
            SELECT COUNT(DISTINCT unnest(cwe_ids)) FROM cve WHERE cwe_ids IS NOT NULL
        """)
        unique_cwes = self.cursor.fetchone()[0]
        print(f"\nUnique CWEs referenced: {unique_cwes:,}")

    def close(self):
        self.cursor.close()
        self.conn.close()

def main():
    print("\n" + "="*70)
    print("NVD API 2.0 CVE Importer for FOSS-CHERUB")
    print("="*70)

    if API_KEY == "YOUR_API_KEY_HERE":
        print("\n⚠️  No API key configured!")
        print("\n📝 To get an API key:")
        print("   1. Visit: https://nvd.nist.gov/developers/request-an-api-key")
        print("   2. Fill out the form (instant approval)")
        print("   3. Copy your API key")
        print("   4. Edit this file and paste it in API_KEY variable")
        print("\n💡 You can continue without a key, but it will be MUCH slower.")
        print()
        response = input("Continue anyway? (yes/no): ")
        if response.lower() != 'yes':
            print("Cancelled. Get your API key and try again!")
            sys.exit(0)

    print("\n⚠️  Note: Full import takes 30-60 minutes even with API key.")
    print("   Imports ~250,000 CVEs from NVD database.")
    response = input("\nContinue? (yes/no): ")

    if response.lower() != 'yes':
        print("Import cancelled.")
        sys.exit(0)

    importer = NVDImporter(API_KEY, DB_CONFIG)

    try:
        print("\nStarting import...")
        start_time = time.time()

        # Import all CVEs (remove max_results to import everything)
        total = importer.import_cves(max_results=None)  # Set to 10000 for testing

        elapsed = time.time() - start_time
        print(f"\n✅ Import completed in {elapsed/60:.1f} minutes")
        print(f"   Imported {total:,} CVEs")

        importer.get_statistics()

    except KeyboardInterrupt:
        print("\n\nImport interrupted by user.")
    except Exception as e:
        print(f"\n\nImport failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        importer.close()

if __name__ == "__main__":
    main()
