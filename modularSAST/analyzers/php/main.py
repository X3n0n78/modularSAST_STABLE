#!/usr/bin/env python3
"""
ModularSAST PHP Analyzer
Pattern-based security analyzer for PHP code
"""

import sys
import json
import re
import yaml


class PHPAnalyzer:
    def __init__(self, rule_file, target_file):
        self.rule_file = rule_file
        self.target_file = target_file
        self.findings = []
        self.rules = []
        self.sources = []

    def load_rules(self):
        """Load rules from YAML file"""
        try:
            with open(self.rule_file, 'r', encoding='utf-8') as f:
                yaml_content = yaml.safe_load(f)
                self.rules = yaml_content.get('rules', [])
                self.sources = yaml_content.get('sources', [])
        except Exception as e:
            print(json.dumps([{"error": f"Error loading rules: {e}"}]), file=sys.stderr)

    def check_suppression(self, lines, line_num, pattern):
        """Check for suppression comments"""
        if line_num < 1 or line_num > len(lines):
            return False

        # Check current line and previous line for suppression
        for idx in [line_num - 1, line_num - 2]:
            if idx < 0 or idx >= len(lines):
                continue

            line = lines[idx]
            # Match // nosast or /* nosast */
            if re.search(r'(?://|/\*)\s*nosast(?::\s*(\S+))?', line, re.IGNORECASE):
                match = re.search(r'(?://|/\*)\s*nosast(?::\s*(\S+))?', line, re.IGNORECASE)
                if match.group(1):
                    if pattern in match.group(1) or match.group(1) == 'all':
                        return True
                else:
                    return True

        return False

    def calculate_confidence(self, pattern, has_variable, is_suppressed):
        """Calculate confidence score (0-100)"""
        if is_suppressed:
            return 0

        base_confidence = 60

        # High-risk functions get higher confidence
        high_risk = ['eval', 'exec', 'system', 'passthru', 'shell_exec',
                     'unserialize', 'assert']
        if any(risk in pattern for risk in high_risk):
            base_confidence = 85

        # If user variable is involved, increase confidence
        if has_variable:
            base_confidence += 15

        return min(100, base_confidence)

    def analyze(self):
        """Analyze PHP file for security vulnerabilities"""
        try:
            with open(self.target_file, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')

            for rule in self.rules:
                pattern = rule.get('pattern', '')
                if not pattern:
                    continue

                # Build regex pattern
                # Look for the dangerous function with potential user input
                regex_pattern = re.escape(pattern) + r'\s*\('

                for line_num, line in enumerate(lines, 1):
                    if re.search(regex_pattern, line, re.IGNORECASE):
                        # Check if suppressed
                        is_suppressed = self.check_suppression(lines, line_num, pattern)

                        # Check if user-controlled variable is present
                        has_variable = any(var in line for var in
                            ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE',
                             '$_SERVER', '$_FILES', '$_ENV'])

                        confidence = self.calculate_confidence(pattern, has_variable, is_suppressed)

                        if confidence > 0:
                            self.findings.append({
                                "file": self.target_file,
                                "line": line_num,
                                "finding": pattern,
                                "snippet": line.strip(),
                                "confidence": confidence,
                                "rule_name": rule.get('name', pattern)
                            })

        except Exception as e:
            print(json.dumps([{"error": f"Error analyzing file: {e}"}]), file=sys.stderr)

    def output_findings(self):
        """Output findings as JSON"""
        print(json.dumps(self.findings, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(json.dumps([{"error": "Usage: python3 main.py <rule_file> <target_file>"}]))
        sys.exit(1)

    rule_file = sys.argv[1]
    target_file = sys.argv[2]

    analyzer = PHPAnalyzer(rule_file, target_file)
    analyzer.load_rules()
    analyzer.analyze()
    analyzer.output_findings()
