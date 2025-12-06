# cwe_classifier.py - AI-Powered CWE Classification

import requests
import pandas as pd
from typing import Optional

API_ENDPOINT = "http://localhost:8080"

def classify_cwe_with_ai(vulnerability: str, code_snippet: str = "", severity: str = "MEDIUM") -> str:
    """Use AI to classify vulnerability to CWE"""
    try:
        response = requests.post(
            f"{API_ENDPOINT}/classify_cwe",
            json={
                "vulnerability": vulnerability,
                "code_snippet": code_snippet,
                "severity": severity
            },
            timeout=30
        )

        if response.ok:
            result = response.json()
            cwe_id = result.get('cwe_id', 'N/A')
            if cwe_id and cwe_id.startswith('CWE-'):
                return cwe_id

        return infer_cwe_from_pattern(vulnerability)
    except:
        return infer_cwe_from_pattern(vulnerability)


def infer_cwe_from_pattern(vulnerability_text: str) -> str:
    """Fallback: Pattern matching for CWE inference"""
    text_lower = vulnerability_text.lower()

    patterns = {
        'sql': 'CWE-89', 'injection': 'CWE-89', 'xss': 'CWE-79',
        'cross-site': 'CWE-79', 'command': 'CWE-78', 'shell': 'CWE-78',
        'path traversal': 'CWE-22', '../': 'CWE-22', 'deseriali': 'CWE-502',
        'buffer overflow': 'CWE-120', 'hardcoded': 'CWE-798',
        'weak crypto': 'CWE-327', 'eval': 'CWE-95', 'xxe': 'CWE-611',
        'ssrf': 'CWE-918', 'race condition': 'CWE-362',
        'integer overflow': 'CWE-190', 'null pointer': 'CWE-476',
        'use after free': 'CWE-416', 'csrf': 'CWE-352',
        'file upload': 'CWE-434', 'authentication': 'CWE-287'
    }

    for pattern, cwe in patterns.items():
        if pattern in text_lower:
            return cwe

    return 'N/A'


def enrich_findings_with_cwe(findings_df: pd.DataFrame, verbose: bool = True) -> pd.DataFrame:
    """Enrich findings with AI-classified CWEs"""
    if findings_df.empty:
        return findings_df

    needs_classification = findings_df['CWE'].isin(['N/A', '', 'nan', None])
    count = needs_classification.sum()

    if count == 0:
        return findings_df

    if verbose:
        print(f"🤖 AI: Classifying {count} findings...")

    for idx in findings_df[needs_classification].index:
        try:
            vulnerability = findings_df.at[idx, 'Vulnerability']
            severity = findings_df.at[idx, 'Severity']
            cwe = classify_cwe_with_ai(vulnerability, severity=severity)

            if cwe != 'N/A':
                findings_df.at[idx, 'CWE'] = cwe
                if verbose:
                    print(f"  ✓ {vulnerability[:50]}... → {cwe}")
        except:
            continue

    return findings_df


# Batch processing version for large scans
def enrich_findings_batch(findings_df: pd.DataFrame, batch_size: int = 10) -> pd.DataFrame:
    """Batch process CWE classification for efficiency"""
    if findings_df.empty:
        return findings_df

    needs_classification = findings_df[findings_df['CWE'].isin(['N/A', '', 'nan', None])]

    if len(needs_classification) == 0:
        return findings_df

    print(f"🤖 Batch classifying {len(needs_classification)} findings...")

    # Process in batches
    for i in range(0, len(needs_classification), batch_size):
        batch = needs_classification.iloc[i:i+batch_size]

        try:
            # Prepare batch request
            batch_data = [
                {
                    "vulnerability": row['Vulnerability'],
                    "severity": row['Severity']
                }
                for _, row in batch.iterrows()
            ]

            # Send batch request
            response = requests.post(
                f"{API_ENDPOINT}/classify_cwe_batch",
                json={"findings": batch_data},
                timeout=60
            )

            if response.ok:
                results = response.json().get('classifications', [])
                for (idx, _), cwe in zip(batch.iterrows(), results):
                    if cwe and cwe != 'N/A':
                        findings_df.at[idx, 'CWE'] = cwe
        except:
            # Fallback to individual classification
            for idx, row in batch.iterrows():
                cwe = infer_cwe_from_pattern(row['Vulnerability'])
                if cwe != 'N/A':
                    findings_df.at[idx, 'CWE'] = cwe

    return findings_df
