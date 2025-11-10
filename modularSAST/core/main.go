package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	Version = "1.1.0"
	Author  = "Kristof Stier"
	GitHub  = "https://github.com/X3n0n78"
)

// --- Struktúrák ---
type Finding struct {
	File       string `json:"file"`
	Line       int    `json:"line"`
	Finding    string `json:"finding"` // Ez a 'pattern' VAGY a 'rule_name'
	Severity   string `json:"severity"`
	Message    string `json:"message"`
	Snippet    string `json:"snippet"`
	RuleName   string `json:"rule_name"`
	Confidence int    `json:"confidence"` // 0-100 confidence score
}
type Rule struct {
	Name     string `yaml:"name"`
	Pattern  string `yaml:"pattern"`
	Severity string `yaml:"severity"`
	Message  string `yaml:"message"`
}
type RuleSet struct {
	Rules []Rule `yaml:"rules"`
}

// Config represents the configuration file structure
type Config struct {
	TargetPath        string   `yaml:"target_path"`
	ExcludePatterns   []string `yaml:"exclude_patterns"`
	ReportFormats     []string `yaml:"report_formats"`
	SeverityThreshold string   `yaml:"severity_threshold"`
	MaxFindings       int      `yaml:"max_findings"`
	FailOnSeverity    string   `yaml:"fail_on_severity"`
	EnableCache       bool     `yaml:"enable_cache"`
	SaveBaseline      bool     `yaml:"save_baseline"`
	BaselineFile      string   `yaml:"baseline_file"`
}
type SarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SarifRun `json:"runs"`
}
type SarifRun struct {
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
}
type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}
type SarifDriver struct {
	Name string `json:"name"`
}
type SarifResult struct {
	RuleID    string          `json:"ruleId"`
	Message   SarifMessage    `json:"message"`
	Level     string          `json:"level"`
	Locations []SarifLocation `json:"locations"`
}
type SarifMessage struct {
	Text string `json:"text"`
}
type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}
type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
	Region           SarifRegion           `json:"region"`
}
type SarifArtifactLocation struct {
	URI string `json:"uri"`
}
type SarifRegion struct {
	StartLine int `json:"startLine"`
}

// --- ASCII Banner ---
func printBanner() {
	banner := `
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   ███╗   ███╗ ██████╗ ██████╗ ██╗   ██╗██╗      █████╗ ██████╗          ║
║   ████╗ ████║██╔═══██╗██╔══██╗██║   ██║██║     ██╔══██╗██╔══██╗         ║
║   ██╔████╔██║██║   ██║██║  ██║██║   ██║██║     ███████║██████╔╝         ║
║   ██║╚██╔╝██║██║   ██║██║  ██║██║   ██║██║     ██╔══██║██╔══██╗         ║
║   ██║ ╚═╝ ██║╚██████╔╝██████╔╝╚██████╔╝███████╗██║  ██║██║  ██║         ║
║   ╚═╝     ╚═╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝         ║
║                                                                           ║
║               ███████╗ █████╗ ███████╗████████╗                          ║
║               ██╔════╝██╔══██╗██╔════╝╚══██╔══╝                          ║
║               ███████╗███████║███████╗   ██║                             ║
║               ╚════██║██╔══██║╚════██║   ██║                             ║
║               ███████║██║  ██║███████║   ██║                             ║
║               ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝                             ║
║                                                                           ║
║                  Modular Static Application Security Testing             ║
║                                                                           ║
╟───────────────────────────────────────────────────────────────────────────╢
║  Version    : %-58s  ║
║  Author     : %-58s  ║
║  GitHub     : %-58s  ║
╟───────────────────────────────────────────────────────────────────────────╢
║  Languages  : Python │ C/C++ │ Go │ JavaScript/TypeScript │ PHP         ║
║  Rules      : 135+ security patterns across all languages                ║
║  Features   : Taint Analysis │ Confidence Scoring │ CI/CD Ready          ║
╚═══════════════════════════════════════════════════════════════════════════╝
`
	fmt.Printf(banner, Version, Author, GitHub)
	fmt.Println()
}

// --- loadConfig loads configuration from YAML file ---
func loadConfig(configPath string) (*Config, error) {
	// Default config
	config := &Config{
		TargetPath:        ".",
		ExcludePatterns:   []string{"*/vendor/*", "*/node_modules/*", "*/.git/*"},
		ReportFormats:     []string{"html", "sarif"},
		SeverityThreshold: "Low",
		MaxFindings:       10000,
		FailOnSeverity:    "",
		EnableCache:       false,
		SaveBaseline:      false,
		BaselineFile:      ".sast-baseline.json",
	}

	// If no config file exists, return defaults
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return config, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("error reading configuration file: %w", err)
	}

	err = yaml.Unmarshal(data, config)
	if err != nil {
		return nil, fmt.Errorf("error parsing configuration YAML: %w", err)
	}

	return config, nil
}

// --- shouldExclude checks if a file should be excluded ---
func shouldExclude(path string, patterns []string) bool {
	for _, pattern := range patterns {
		matched, err := filepath.Match(pattern, path)
		if err == nil && matched {
			return true
		}
		// Alkönyvtár-alapú minta kezelés (pl. */node_modules/*)
		if strings.Contains(path, strings.Trim(pattern, "*")) {
			return true
		}
	}
	return false
}

// --- loadRules returns TWO MAPS ---
// 1. pattern -> Rule (for AST analyzers)
// 2. name -> Rule (for Regex analyzer)
func loadRules(ruleFile string) (map[string]Rule, map[string]Rule, error) {
	patternMap := make(map[string]Rule)
	nameMap := make(map[string]Rule)

	data, err := os.ReadFile(ruleFile)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading rule file (%s): %w", ruleFile, err)
	}
	var ruleSet RuleSet
	err = yaml.Unmarshal(data, &ruleSet)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing YAML (%s): %w", ruleFile, err)
	}
	for _, rule := range ruleSet.Rules {
		if rule.Pattern != "" {
			patternMap[rule.Pattern] = rule // Key = 'pattern'
		}
		if rule.Name != "" {
			nameMap[rule.Name] = rule // Key = 'name'
		}
	}
	if len(patternMap) == 0 && len(nameMap) == 0 {
		return nil, nil, fmt.Errorf("no loadable 'rule' found in rule file: %s", ruleFile)
	}
	return patternMap, nameMap, nil
}

// --- Analyzer Runners ---
func scanPyFile(wg *sync.WaitGroup, pythonAnalyzerPath, pythonRuleFile, path string, resultsChan chan<- string) {
	defer wg.Done()
	log.Printf("→ Scanning Python file: %s\n", path)
	cmd := exec.Command("python3", pythonAnalyzerPath, pythonRuleFile, path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("✗ Error running Python analyzer (%s): %v\n", path, err)
		resultsChan <- fmt.Sprintf("[{\"file\": \"%s\", \"finding\": \"ANALYZER ERROR\", \"message\": \"%v\"}]", path, err)
	} else {
		resultsChan <- string(output)
	}
}
func scanCppFile(wg *sync.WaitGroup, cppAnalyzerPath string, path string, rulePatterns []string, resultsChan chan<- string) {
	defer wg.Done()
	log.Printf("→ Scanning C/C++ file: %s\n", path)
	args := []string{path}
	args = append(args, rulePatterns...)
	cmd := exec.Command(cppAnalyzerPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("✗ Error running C++ analyzer (%s): %v\n", path, err)
		resultsChan <- fmt.Sprintf("[{\"file\": \"%s\", \"finding\": \"ANALYZER ERROR\", \"message\": \"%v\"}]", path, err)
	} else {
		resultsChan <- string(output)
	}
}
func scanGoFile(wg *sync.WaitGroup, goAnalyzerPath string, path string, rulePatterns []string, resultsChan chan<- string) {
	defer wg.Done()
	log.Printf("→ Scanning Go file: %s\n", path)
	args := []string{path}
	args = append(args, rulePatterns...)
	cmd := exec.Command(goAnalyzerPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("✗ Error running Go analyzer (%s): %v\n", path, err)
		resultsChan <- fmt.Sprintf("[{\"file\": \"%s\", \"finding\": \"ANALYZER ERROR\", \"message\": \"%v\"}]", path, err)
	} else {
		resultsChan <- string(output)
	}
}
func scanJSFile(wg *sync.WaitGroup, jsAnalyzerPath, jsRuleFile, path string, resultsChan chan<- string) {
	defer wg.Done()
	log.Printf("→ Scanning JavaScript file: %s\n", path)
	cmd := exec.Command("node", jsAnalyzerPath, jsRuleFile, path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("✗ Error running JavaScript analyzer (%s): %v\n", path, err)
		resultsChan <- fmt.Sprintf("[{\"file\": \"%s\", \"finding\": \"ANALYZER ERROR\", \"message\": \"%v\"}]", path, err)
	} else {
		resultsChan <- string(output)
	}
}
func scanPHPFile(wg *sync.WaitGroup, phpAnalyzerPath, phpRuleFile, path string, resultsChan chan<- string) {
	defer wg.Done()
	log.Printf("→ Scanning PHP file: %s\n", path)
	cmd := exec.Command("python3", phpAnalyzerPath, phpRuleFile, path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("✗ Error running PHP analyzer (%s): %v\n", path, err)
		resultsChan <- fmt.Sprintf("[{\"file\": \"%s\", \"finding\": \"ANALYZER ERROR\", \"message\": \"%v\"}]", path, err)
	} else {
		resultsChan <- string(output)
	}
}
func scanRegexFile(wg *sync.WaitGroup, regexAnalyzerPath, regexRuleFile, path string, resultsChan chan<- string) {
	defer wg.Done()
	log.Printf("→ Scanning with regex analyzer: %s\n", path)
	cmd := exec.Command("python3", regexAnalyzerPath, regexRuleFile, path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("✗ Error running Regex analyzer (%s): %v\n", path, err)
		resultsChan <- fmt.Sprintf("[{\"file\": \"%s\", \"finding\": \"ANALYZER ERROR\", \"message\": \"%v\"}]", path, err)
	} else {
		resultsChan <- string(output)
	}
}

// --- Report Generators ---
func generateHTMLReport(findingsMap map[string][]Finding, scanPath string) error {
	filename := "sast_report.html"
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create HTML report file: %w", err)
	}
	defer file.Close()
	header := `
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>ModularSAST Report</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; background-color: #f4f7f6; color: #333; }
.container { max-width: 1000px; margin: 20px auto; padding: 20px; background-color: #ffffff; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
h1 { color: #2c3e50; border-bottom: 2px solid #e0e0e0; padding-bottom: 10px; }
.summary { font-size: 1.2em; margin-bottom: 20px; }
.file-group { margin-bottom: 30px; border: 1px solid #ccc; border-radius: 8px; }
.file-header { background-color: #2c3e50; color: #ffffff; padding: 15px; border-radius: 8px 8px 0 0; font-size: 1.2em; font-family: monospace; }
.finding { border-bottom: 1px solid #eee; } .finding:last-child { border-bottom: none; }
.finding-header { padding: 15px; background-color: #f9f9f9; } .finding-header strong { font-size: 1.1em; }
.finding-body { padding: 15px; } .finding-body pre { background-color: #f4f4f4; border: 1px solid #ddd; color: #333; padding: 10px; border-radius: 4px; overflow-x: auto; }
.severity-High { border-left: 5px solid #e74c3c; } .severity-Critical { border-left: 5px solid #c0392b; }
.sev-Critical { color: #c0392b; } .sev-High { color: #e74c3c; }
</style></head><body><div class="container">`
	file.WriteString(header)
	severityScore := map[string]int{"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "": 5}
	totalFindings := 0
	for _, findings := range findingsMap {
		totalFindings += len(findings)
	}
	summary := fmt.Sprintf(`<h1>ModularSAST Report</h1><div class="summary"><strong>Scan directory:</strong> %s<br><strong>Report time:</strong> %s<br><strong>Total findings:</strong> %d</div>`, scanPath, time.Now().Format("2006-01-02 15:04:05"), totalFindings)
	file.WriteString(summary)
	sortedFilenames := make([]string, 0, len(findingsMap))
	for filename := range findingsMap {
		sortedFilenames = append(sortedFilenames, filename)
	}
	sort.Strings(sortedFilenames)
	for _, filename := range sortedFilenames {
		findingsForThisFile := findingsMap[filename]
		sort.Slice(findingsForThisFile, func(i, j int) bool {
			scoreI := severityScore[findingsForThisFile[i].Severity]
			scoreJ := severityScore[findingsForThisFile[j].Severity]
			if scoreI != scoreJ {
				return scoreI < scoreJ
			}
			return findingsForThisFile[i].Line < findingsForThisFile[j].Line
		})
		fileHeader := fmt.Sprintf(`<div class="file-group"><div class="file-header">%s (%d findings)</div>`, filename, len(findingsForThisFile))
		file.WriteString(fileHeader)
		for _, f := range findingsForThisFile {
			if f.Severity == "" {
				f.Severity = "High"
			}
			if f.Message == "" {
				f.Message = "No detailed message available."
			}
			if f.Snippet == "" {
				f.Snippet = "N/A"
			}
			if f.RuleName == "" {
				f.RuleName = f.Finding
			}
			findingHTML := fmt.Sprintf(`<div class="finding severity-%s"><div class="finding-header"><strong class="sev-%s">[%s: %s]</strong> - Line %d</div><div class="finding-body"><p><strong>Rule:</strong> %s</p><p><strong>Message:</strong> %s</p><pre><code>%s</code></pre></div></div>`, f.Severity, f.Severity, f.Severity, f.Finding, f.Line, f.RuleName, f.Message, f.Snippet)
			file.WriteString(findingHTML)
		}
		file.WriteString("</div>")
	}
	file.WriteString("</div></body></html>")
	log.Printf("✓ HTML report successfully generated: %s\n", filename)
	return nil
}

func generateSarifReport(findingsMap map[string][]Finding) error {
	tool := SarifTool{Driver: SarifDriver{Name: "ModularSAST"}}
	severityMap := map[string]string{"Critical": "error", "High": "warning", "Medium": "note", "Low": "note", "": "warning"}
	sarifResults := []SarifResult{}
	for _, findingsInFile := range findingsMap {
		for _, f := range findingsInFile {
			ruleID := f.RuleName
			if ruleID == "" {
				ruleID = f.Finding
			}
			result := SarifResult{
				RuleID: ruleID, Message: SarifMessage{Text: f.Message}, Level: severityMap[f.Severity],
				Locations: []SarifLocation{{PhysicalLocation: SarifPhysicalLocation{
					ArtifactLocation: SarifArtifactLocation{URI: f.File},
					Region:           SarifRegion{StartLine: f.Line},
				}}},
			}
			sarifResults = append(sarifResults, result)
		}
	}
	sarifLog := SarifLog{Schema: "https://json.schemastore.org/sarif-2.1.0-rtm.2.json", Version: "2.1.0", Runs: []SarifRun{{Tool: tool, Results: sarifResults}}}
	data, err := json.MarshalIndent(sarifLog, "", "  ")
	if err != nil {
		return fmt.Errorf("error generating SARIF JSON: %w", err)
	}
	err = os.WriteFile("report.sarif.json", data, 0644)
	if err != nil {
		return fmt.Errorf("error writing SARIF file: %w", err)
	}
	log.Printf("✓ SARIF report successfully generated: report.sarif.json\n")
	return nil
}

func generateJSONReport(findingsMap map[string][]Finding) error {
	data, err := json.MarshalIndent(findingsMap, "", "  ")
	if err != nil {
		return fmt.Errorf("error generating JSON report: %w", err)
	}
	err = os.WriteFile("report.json", data, 0644)
	if err != nil {
		return fmt.Errorf("error writing JSON file: %w", err)
	}
	log.Printf("✓ JSON report successfully generated: report.json\n")
	return nil
}

func generateCSVReport(findingsMap map[string][]Finding) error {
	file, err := os.Create("report.csv")
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	// Header
	file.WriteString("File,Line,Severity,Rule Name,Finding,Message\n")

	// Sort files for consistent output
	sortedFiles := make([]string, 0, len(findingsMap))
	for filename := range findingsMap {
		sortedFiles = append(sortedFiles, filename)
	}
	sort.Strings(sortedFiles)

	for _, filename := range sortedFiles {
		findings := findingsMap[filename]
		for _, f := range findings {
			// Escape CSV fields
			message := strings.ReplaceAll(f.Message, "\"", "\"\"")
			line := fmt.Sprintf("\"%s\",%d,\"%s\",\"%s\",\"%s\",\"%s\"\n",
				f.File, f.Line, f.Severity, f.RuleName, f.Finding, message)
			file.WriteString(line)
		}
	}

	log.Printf("✓ CSV report successfully generated: report.csv\n")
	return nil
}

func generateMarkdownReport(findingsMap map[string][]Finding, scanPath string) error {
	file, err := os.Create("report.md")
	if err != nil {
		return fmt.Errorf("failed to create Markdown file: %w", err)
	}
	defer file.Close()

	// Header
	file.WriteString("# ModularSAST Security Report\n\n")
	file.WriteString(fmt.Sprintf("**Scan Path:** %s\n\n", scanPath))
	file.WriteString(fmt.Sprintf("**Generated:** %s\n\n", time.Now().Format("2006-01-02 15:04:05")))

	// Summary
	totalFindings := 0
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, findings := range findingsMap {
		totalFindings += len(findings)
		for _, f := range findings {
			switch f.Severity {
			case "Critical":
				criticalCount++
			case "High":
				highCount++
			case "Medium":
				mediumCount++
			case "Low":
				lowCount++
			}
		}
	}

	file.WriteString("## Summary\n\n")
	file.WriteString(fmt.Sprintf("- **Total Findings:** %d\n", totalFindings))
	file.WriteString(fmt.Sprintf("- **Critical:** %d\n", criticalCount))
	file.WriteString(fmt.Sprintf("- **High:** %d\n", highCount))
	file.WriteString(fmt.Sprintf("- **Medium:** %d\n", mediumCount))
	file.WriteString(fmt.Sprintf("- **Low:** %d\n\n", lowCount))

	// Findings by file
	file.WriteString("## Findings by File\n\n")

	sortedFiles := make([]string, 0, len(findingsMap))
	for filename := range findingsMap {
		sortedFiles = append(sortedFiles, filename)
	}
	sort.Strings(sortedFiles)

	for _, filename := range sortedFiles {
		findings := findingsMap[filename]
		file.WriteString(fmt.Sprintf("### %s\n\n", filename))

		for _, f := range findings {
			severityIcon := "⚠️"
			switch f.Severity {
			case "Critical":
				severityIcon = "🔴"
			case "High":
				severityIcon = "🟠"
			case "Medium":
				severityIcon = "🟡"
			case "Low":
				severityIcon = "🔵"
			}

			file.WriteString(fmt.Sprintf("%s **[%s]** %s (Line %d)\n\n", severityIcon, f.Severity, f.RuleName, f.Line))
			file.WriteString(fmt.Sprintf("- **Finding:** %s\n", f.Finding))
			file.WriteString(fmt.Sprintf("- **Message:** %s\n", f.Message))
			if f.Snippet != "" && f.Snippet != "N/A" {
				file.WriteString(fmt.Sprintf("- **Code:**\n```\n%s\n```\n", f.Snippet))
			}
			file.WriteString("\n---\n\n")
		}
	}

	log.Printf("✓ Markdown report successfully generated: report.md\n")
	return nil
}

// --- getSeverityScore returns numeric score for severity comparison ---
func getSeverityScore(severity string) int {
	scores := map[string]int{"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
	if score, ok := scores[severity]; ok {
		return score
	}
	return 5
}

// --- meetsSeverityThreshold checks if finding meets threshold ---
func meetsSeverityThreshold(findingSeverity, threshold string) bool {
	return getSeverityScore(findingSeverity) <= getSeverityScore(threshold)
}

// --- Main Function ---
func main() {
	// Print banner
	printBanner()

	// 1. Arguments and Config
	scanPath := flag.String("path", "", "Path to the directory to scan (overrides config)")
	configPath := flag.String("config", ".modularsast.yaml", "Path to the configuration file")
	failOnSeverity := flag.String("fail-on", "", "Exit with code 1 if findings at or above this severity level (Critical, High, Medium, Low)")
	outputFormats := flag.String("formats", "", "Output formats separated by commas (html, sarif, json, csv, markdown)")
	flag.Parse()

	// Load config
	config, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("✗ Critical error loading configuration: %v", err)
	}

	// Flags override config
	if *scanPath != "" {
		config.TargetPath = *scanPath
	}
	if *failOnSeverity != "" {
		config.FailOnSeverity = *failOnSeverity
	}
	if *outputFormats != "" {
		config.ReportFormats = strings.Split(*outputFormats, ",")
	}

	log.Printf("▶ Starting analysis at: %s\n", config.TargetPath)

	// 2. Paths and Rules
	analyzerBasePath, _ := filepath.Abs("analyzers")
	rulesBasePath, _ := filepath.Abs("rules")

	pythonAnalyzerPath := filepath.Join(analyzerBasePath, "python", "main.py")
	pythonRuleFile := filepath.Join(rulesBasePath, "python.yaml")

	cppAnalyzerPath := filepath.Join(analyzerBasePath, "cpp", "cpp_analyzer")
	cppRuleFile := filepath.Join(rulesBasePath, "cpp.yaml")

	goAnalyzerPath := filepath.Join(analyzerBasePath, "go", "go_analyzer")
	goRuleFile := filepath.Join(rulesBasePath, "go.yaml")

	jsAnalyzerPath := filepath.Join(analyzerBasePath, "javascript", "main.js")
	jsRuleFile := filepath.Join(rulesBasePath, "javascript.yaml")

	phpAnalyzerPath := filepath.Join(analyzerBasePath, "php", "main.py")
	phpRuleFile := filepath.Join(rulesBasePath, "php.yaml")

	regexAnalyzerPath := filepath.Join(analyzerBasePath, "regex", "main.py")
	regexRuleFile := filepath.Join(rulesBasePath, "regex.yaml")

	// --- Load Rules (All 6 Analyzers) ---
	// AST/Pattern analyzers use 'pattern' -> Rule maps
	pythonPatternMap, _, err := loadRules(pythonRuleFile)
	if err != nil {
		log.Fatalf("✗ Critical error (Python rules): %v", err)
	}

	cppPatternMap, _, err := loadRules(cppRuleFile)
	if err != nil {
		log.Fatalf("✗ Critical error (C++ rules): %v", err)
	}

	goPatternMap, _, err := loadRules(goRuleFile)
	if err != nil {
		log.Fatalf("✗ Critical error (Go rules): %v", err)
	}

	jsPatternMap, _, err := loadRules(jsRuleFile)
	if err != nil {
		log.Fatalf("✗ Critical error (JavaScript rules): %v", err)
	}

	phpPatternMap, _, err := loadRules(phpRuleFile)
	if err != nil {
		log.Fatalf("✗ Critical error (PHP rules): %v", err)
	}

	// The Regex analyzer uses 'name' -> Rule map
	_, regexNameMap, err := loadRules(regexRuleFile)
	if err != nil {
		log.Fatalf("✗ Critical error (Regex rules): %v", err)
	}

	// Pattern lists for analyzers
	cppRulePatterns := make([]string, 0, len(cppPatternMap))
	for pattern := range cppPatternMap {
		cppRulePatterns = append(cppRulePatterns, pattern)
	}

	goRulePatterns := make([]string, 0, len(goPatternMap))
	for pattern := range goPatternMap {
		goRulePatterns = append(goRulePatterns, pattern)
	}

	// 3. Concurrency and Result Enrichment
	var scannerWg sync.WaitGroup
	var resultsWg sync.WaitGroup
	resultsChan := make(chan string, 100)
	allFindingsMap := make(map[string][]Finding)
	var mapMutex sync.Mutex

	resultsWg.Add(1)
	go func() {
		defer resultsWg.Done()
		for jsonString := range resultsChan {
			var findingsInArray []Finding
			if err := json.Unmarshal([]byte(jsonString), &findingsInArray); err != nil {
				log.Printf("✗ JSON parsing error: %v (Skipping: %s)", err, jsonString)
				continue
			}

			// Enrichment and Grouping
			for i, finding := range findingsInArray {
				var rule Rule
				var ok bool

				// --- ENRICHMENT LOGIC ---
				// Decision based on 'finding.Finding' field content

				// 1. Try pattern-based maps (Python, C++, Go, JS, PHP)
				if r, ok_py := pythonPatternMap[finding.Finding]; ok_py {
					rule, ok = r, true
				} else if r, ok_cpp := cppPatternMap[finding.Finding]; ok_cpp {
					rule, ok = r, true
				} else if r, ok_go := goPatternMap[finding.Finding]; ok_go {
					rule, ok = r, true
				} else if r, ok_js := jsPatternMap[finding.Finding]; ok_js {
					rule, ok = r, true
				} else if r, ok_php := phpPatternMap[finding.Finding]; ok_php {
					rule, ok = r, true
				} else if r, ok_rx := regexNameMap[finding.Finding]; ok_rx {
					// 2. Try name-based map (Regex)
					rule, ok = r, true
				}
				// --- END ENRICHMENT ---

				if ok {
					findingsInArray[i].RuleName = rule.Name
					findingsInArray[i].Severity = rule.Severity
					findingsInArray[i].Message = rule.Message
				} else {
					findingsInArray[i].RuleName = "UnknownRule"
					findingsInArray[i].Severity = "Medium"
					findingsInArray[i].Message = "Finding reported by analyzer but not found in central rule map."
				}

				mapMutex.Lock()
				allFindingsMap[findingsInArray[i].File] = append(allFindingsMap[findingsInArray[i].File], findingsInArray[i])
				mapMutex.Unlock()
			}
		}
	}()

	// 4. Directory Traversal
	err = filepath.WalkDir(config.TargetPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Exclude directories
			if shouldExclude(path, config.ExcludePatterns) {
				log.Printf("⊗ Skipped (exclude pattern): %s\n", path)
				return fs.SkipDir
			}
			return nil
		}

		// Exclude files
		if shouldExclude(path, config.ExcludePatterns) {
			log.Printf("⊗ Skipped (exclude pattern): %s\n", path)
			return nil
		}

		// --- Specialized Analyzers ---
		if strings.HasSuffix(path, ".py") {
			scannerWg.Add(1)
			go scanPyFile(&scannerWg, pythonAnalyzerPath, pythonRuleFile, path, resultsChan)
		} else if strings.HasSuffix(path, ".cpp") || strings.HasSuffix(path, ".c") || strings.HasSuffix(path, ".h") {
			scannerWg.Add(1)
			go scanCppFile(&scannerWg, cppAnalyzerPath, path, cppRulePatterns, resultsChan)
		} else if strings.HasSuffix(path, ".go") {
			scannerWg.Add(1)
			go scanGoFile(&scannerWg, goAnalyzerPath, path, goRulePatterns, resultsChan)
		} else if strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".ts") || strings.HasSuffix(path, ".jsx") || strings.HasSuffix(path, ".tsx") {
			scannerWg.Add(1)
			go scanJSFile(&scannerWg, jsAnalyzerPath, jsRuleFile, path, resultsChan)
		} else if strings.HasSuffix(path, ".php") {
			scannerWg.Add(1)
			go scanPHPFile(&scannerWg, phpAnalyzerPath, phpRuleFile, path, resultsChan)
		}

		// --- GENERIC (REGEX) Analyzer ---
		scannerWg.Add(1)
		go scanRegexFile(&scannerWg, regexAnalyzerPath, regexRuleFile, path, resultsChan)

		return nil
	})

	if err != nil {
		log.Fatalf("✗ Error traversing directory: %v", err)
	}

	// 5. Completion and Report Generation
	scannerWg.Wait()
	close(resultsChan)
	resultsWg.Wait()

	// Filter by severity threshold and max findings
	filteredFindings := make(map[string][]Finding)
	totalFindings := 0
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for file, findings := range allFindingsMap {
		for _, finding := range findings {
			// Apply severity threshold
			if !meetsSeverityThreshold(finding.Severity, config.SeverityThreshold) {
				continue
			}

			// Check max findings limit
			if config.MaxFindings > 0 && totalFindings >= config.MaxFindings {
				break
			}

			filteredFindings[file] = append(filteredFindings[file], finding)
			totalFindings++

			// Count by severity
			switch finding.Severity {
			case "Critical":
				criticalCount++
			case "High":
				highCount++
			case "Medium":
				mediumCount++
			case "Low":
				lowCount++
			}
		}
	}

	// Generate reports based on configured formats
	for _, format := range config.ReportFormats {
		switch format {
		case "html":
			if err := generateHTMLReport(filteredFindings, config.TargetPath); err != nil {
				log.Printf("✗ Error generating HTML report: %v", err)
			}
		case "sarif":
			if err := generateSarifReport(filteredFindings); err != nil {
				log.Printf("✗ Error generating SARIF report: %v", err)
			}
		case "json":
			if err := generateJSONReport(filteredFindings); err != nil {
				log.Printf("✗ Error generating JSON report: %v", err)
			}
		case "csv":
			if err := generateCSVReport(filteredFindings); err != nil {
				log.Printf("✗ Error generating CSV report: %v", err)
			}
		case "markdown":
			if err := generateMarkdownReport(filteredFindings, config.TargetPath); err != nil {
				log.Printf("✗ Error generating Markdown report: %v", err)
			}
		}
	}

	log.Println("✓ Analysis completed.")
	fmt.Printf("\n═══════════════════════════════════════════════════════════\n")
	fmt.Printf("  SCAN SUMMARY\n")
	fmt.Printf("═══════════════════════════════════════════════════════════\n")
	fmt.Printf("  Total Findings: %d\n", totalFindings)
	fmt.Printf("  ├─ Critical: %d\n", criticalCount)
	fmt.Printf("  ├─ High: %d\n", highCount)
	fmt.Printf("  ├─ Medium: %d\n", mediumCount)
	fmt.Printf("  └─ Low: %d\n", lowCount)
	fmt.Printf("═══════════════════════════════════════════════════════════\n\n")

	// Fail-on severity check
	shouldFail := false
	if config.FailOnSeverity != "" {
		for _, findings := range filteredFindings {
			for _, finding := range findings {
				if meetsSeverityThreshold(finding.Severity, config.FailOnSeverity) {
					shouldFail = true
					break
				}
			}
			if shouldFail {
				break
			}
		}
	}

	if shouldFail {
		fmt.Printf("✗ ERROR: Findings at '%s' severity or higher detected. Exiting with code 1.\n\n", config.FailOnSeverity)
		os.Exit(1)
	}

	os.Exit(0)
}
