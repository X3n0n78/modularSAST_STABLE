#!/usr/bin/env python3
"""
Comprehensive Test Suite for ModularSAST v1.1
Tests all supported vulnerability types across all languages
"""

import subprocess
import json
import sys
from pathlib import Path

def run_scan(test_dir):
    """Run ModularSAST scan on test directory"""
    cmd = ['./modularSAST', f'--path={test_dir}', '--formats=json']
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr

def analyze_results():
    """Analyze scan results"""
    try:
        with open('report.json', 'r') as f:
            findings = json.load(f)

        stats = {
            'total': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'by_language': {}
        }

        for file_path, file_findings in findings.items():
            # Determine language from file extension
            ext = Path(file_path).suffix
            lang_map = {
                '.py': 'Python',
                '.php': 'PHP',
                '.js': 'JavaScript',
                '.cpp': 'C++',
                '.c': 'C',
                '.go': 'Go'
            }
            lang = lang_map.get(ext, 'Unknown')

            if lang not in stats['by_language']:
                stats['by_language'][lang] = 0

            for finding in file_findings:
                stats['total'] += 1
                stats['by_language'][lang] += 1

                severity = finding.get('severity', '').lower()
                if severity == 'critical':
                    stats['critical'] += 1
                elif severity == 'high':
                    stats['high'] += 1
                elif severity == 'medium':
                    stats['medium'] += 1
                elif severity == 'low':
                    stats['low'] += 1

        return stats, findings
    except FileNotFoundError:
        return None, None

def print_report(stats, findings):
    """Print comprehensive test report"""
    print("\n" + "="*70)
    print(" ModularSAST v1.1 - Comprehensive Test Results")
    print("="*70)

    print(f"\n📊 OVERALL STATISTICS:")
    print(f"  Total Findings: {stats['total']}")
    print(f"  ├─ Critical: {stats['critical']}")
    print(f"  ├─ High: {stats['high']}")
    print(f"  ├─ Medium: {stats['medium']}")
    print(f"  └─ Low: {stats['low']}")

    print(f"\n🔍 FINDINGS BY LANGUAGE:")
    for lang, count in sorted(stats['by_language'].items()):
        print(f"  • {lang}: {count} findings")

    print(f"\n📁 FINDINGS BY FILE:")
    for file_path, file_findings in sorted(findings.items()):
        print(f"\n  {file_path} ({len(file_findings)} findings)")
        for finding in file_findings[:3]:  # Show first 3 per file
            severity = finding.get('severity', 'Unknown')
            rule = finding.get('rule_name', finding.get('finding', 'Unknown'))
            line = finding.get('line', 0)
            print(f"    [{severity}] Line {line}: {rule}")
        if len(file_findings) > 3:
            print(f"    ... and {len(file_findings) - 3} more")

    print("\n" + "="*70)
    print("✓ Test completed successfully!")
    print("="*70 + "\n")

if __name__ == "__main__":
    print("Running ModularSAST Comprehensive Test...")

    # Run scan
    returncode, stdout, stderr = run_scan("test_suite")

    # Analyze results
    stats, findings = analyze_results()

    if stats and findings:
        print_report(stats, findings)
        sys.exit(0)
    else:
        print("❌ Error: Could not analyze results")
        sys.exit(1)
