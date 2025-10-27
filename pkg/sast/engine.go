package sast

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ghostn3xus/reconsec/pkg/report"
)

type Rule struct {
	ID string `json:"id"`
	Language string `json:"language"`
	Description string `json:"description"`
	Pattern string `json:"pattern"`
	Severity string `json:"severity"`
	CWE string `json:"cwe,omitempty"`
	Example string `json:"example,omitempty"`
}

func LoadRules(path string) ([]Rule, error) {
	f, err := os.Open(path)
	if err != nil { return nil, err }
	defer f.Close()
	var rules []Rule
	if err := json.NewDecoder(f).Decode(&rules); err != nil { return nil, err }
	return rules, nil
}

func ScanPathWithRules(root string, rules []Rule) ([]report.Finding, error) {
	var findings []report.Finding
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() { return nil }
		ext := strings.ToLower(filepath.Ext(path))
		lang := extToLang(ext)
		if lang == "" { return nil }
		f, err := os.Open(path); if err != nil { return nil }
		defer f.Close()
		sc := bufio.NewScanner(f); lineNo := 0
		for sc.Scan() {
			lineNo++
			line := sc.Text()
			for _, r := range rules {
				if r.Language != lang && r.Language != "all" { continue }
				re, err := regexp.Compile(r.Pattern)
				if err != nil { continue }
				if re.MatchString(line) {
					severity := report.SeverityLow
					if strings.ToUpper(r.Severity) == "HIGH" { severity = report.SeverityHigh }
					if strings.ToUpper(r.Severity) == "MEDIUM" { severity = report.SeverityMedium }
					findings = append(findings, report.Finding{
						Type: string(severity) + "-SAST",
						CWE: r.CWE,
						Severity: severity,
						Confidence: report.ConfidenceMedium,
						File: path,
						Line: lineNo,
						Notes: r.Description,
						Snippet: line,
					})
				}
			}
		}
		return nil
	})
	return findings, nil
}

func extToLang(ext string) string {
	switch ext {
	case ".js", ".ts": return "js"
	case ".py": return "python"
	case ".php": return "php"
	case ".java": return "java"
	case ".go": return "go"
	case ".cs": return "csharp"
	case ".rb": return "ruby"
	case ".c", ".cpp", ".h", ".hpp": return "c"
	default: return ""
	}
}
