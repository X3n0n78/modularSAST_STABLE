#!/usr/bin/env node
/**
 * ModularSAST JavaScript/TypeScript Analyzer
 * AST-based security analyzer for JavaScript and TypeScript code
 */

const fs = require('fs');
const path = require('path');

// Simple AST parser (minimal implementation without external dependencies)
class JSAnalyzer {
    constructor(ruleFile, targetFile) {
        this.ruleFile = ruleFile;
        this.targetFile = targetFile;
        this.findings = [];
        this.rules = [];
        this.taintedVars = new Set();
        this.sources = [];
    }

    loadRules() {
        try {
            const yamlContent = fs.readFileSync(this.ruleFile, 'utf8');
            const lines = yamlContent.split('\n');
            let currentRule = null;
            let inSources = false;
            let inRules = false;

            for (const line of lines) {
                const trimmed = line.trim();

                if (trimmed.startsWith('sources:')) {
                    inSources = true;
                    inRules = false;
                    continue;
                }

                if (trimmed.startsWith('rules:')) {
                    inRules = true;
                    inSources = false;
                    continue;
                }

                if (inSources && trimmed.startsWith('- ')) {
                    this.sources.push(trimmed.substring(2));
                }

                if (inRules) {
                    if (trimmed.startsWith('- name:')) {
                        if (currentRule) {
                            this.rules.push(currentRule);
                        }
                        currentRule = { name: trimmed.split(':')[1].trim().replace(/"/g, '') };
                    } else if (currentRule) {
                        if (trimmed.startsWith('pattern:')) {
                            currentRule.pattern = trimmed.split(':')[1].trim().replace(/"/g, '');
                        } else if (trimmed.startsWith('severity:')) {
                            currentRule.severity = trimmed.split(':')[1].trim().replace(/"/g, '');
                        } else if (trimmed.startsWith('message:')) {
                            currentRule.message = line.split('message:')[1].trim().replace(/^"/, '').replace(/"$/, '');
                        }
                    }
                }
            }

            if (currentRule) {
                this.rules.push(currentRule);
            }
        } catch (err) {
            console.error(`Error loading rules: ${err.message}`);
        }
    }

    analyze() {
        try {
            const code = fs.readFileSync(this.targetFile, 'utf8');
            const lines = code.split('\n');

            for (let lineNum = 0; lineNum < lines.length; lineNum++) {
                const line = lines[lineNum];

                // Track tainted variables from sources
                for (const source of this.sources) {
                    if (line.includes(source)) {
                        // Extract variable name (simple heuristic)
                        const match = line.match(/(?:const|let|var)\s+(\w+)\s*=/);
                        if (match) {
                            this.taintedVars.add(match[1]);
                        }
                    }
                }

                // Check patterns from rules
                for (const rule of this.rules) {
                    if (line.includes(rule.pattern)) {
                        // Check if it's a taint-based sink
                        let isTainted = false;
                        for (const taintedVar of this.taintedVars) {
                            if (line.includes(taintedVar)) {
                                isTainted = true;
                                break;
                            }
                        }

                        // Pattern-based detection (always report)
                        const shouldReport = this.isPatternBased(rule.pattern) || isTainted;

                        if (shouldReport) {
                            this.findings.push({
                                file: this.targetFile,
                                line: lineNum + 1,
                                finding: rule.pattern,
                                severity: rule.severity || 'Medium',
                                message: rule.message || `Dangerous pattern '${rule.pattern}' detected.`,
                                snippet: line.trim(),
                                rule_name: rule.name
                            });
                        }
                    }
                }
            }
        } catch (err) {
            console.error(`Error analyzing file: ${err.message}`);
        }
    }

    isPatternBased(pattern) {
        // Patterns that should always be reported (not taint-based)
        const alwaysReport = [
            'innerHTML',
            'outerHTML',
            'document.write',
            'eval(',
            'Function(',
            'setTimeout(',
            'setInterval(',
            'crypto.createHash(\'md5\')',
            'crypto.createHash(\'sha1\')',
            'execSync',
            'crypto.pseudoRandomBytes'
        ];
        return alwaysReport.some(p => pattern.includes(p));
    }

    outputFindings() {
        console.log(JSON.stringify(this.findings, null, 2));
    }
}

// Main execution
if (process.argv.length < 4) {
    console.error('Usage: node main.js <rule_file> <target_file>');
    process.exit(1);
}

const ruleFile = process.argv[2];
const targetFile = process.argv[3];

const analyzer = new JSAnalyzer(ruleFile, targetFile);
analyzer.loadRules();
analyzer.analyze();
analyzer.outputFindings();
