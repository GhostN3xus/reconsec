package sast

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ghostn3xus/reconsec/pkg/report"
)

type Rule struct {
	ID          string `json:"id"`
	Language    string `json:"language"`
	Description string `json:"description"`
	Pattern     string `json:"pattern"`
	Severity    string `json:"severity"`
	CWE         string `json:"cwe,omitempty"`
	Example     string `json:"example,omitempty"`
}

func LoadRules(path string) ([]Rule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var rules []Rule
	if err := json.NewDecoder(f).Decode(&rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func ScanPathWithRules(root string, rules []Rule) ([]report.Finding, error) {
	var findings []report.Finding

	compiledRules, err := compileRules(rules)
	if err != nil {
		return findings, err
	}

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		lang := extToLang(ext)
		if lang == "" {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}

		scanner := bufio.NewScanner(f)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			line := scanner.Text()

			for _, r := range compiledRules {
				if r.Language != lang && r.Language != "all" {
					continue
				}

				if !r.re.MatchString(line) {
					continue
				}

				severity := report.SeverityLow
				switch strings.ToUpper(r.Severity) {
				case "HIGH":
					severity = report.SeverityHigh
				case "MEDIUM":
					severity = report.SeverityMedium
				}

				findings = append(findings, report.Finding{
					Type:       string(severity) + "-SAST",
					CWE:        r.CWE,
					Severity:   severity,
					Confidence: report.ConfidenceMedium,
					File:       path,
					Line:       lineNo,
					Notes:      r.Description,
					Snippet:    line,
				})
			}
		}

		f.Close()

		if err := scanner.Err(); err != nil {
			return err
		}

		return nil
	})

	if walkErr != nil {
		return findings, walkErr
	}

	return findings, nil
}

type compiledRule struct {
	Rule
	re *regexp.Regexp
}

func compileRules(rules []Rule) ([]compiledRule, error) {
	compiled := make([]compiledRule, 0, len(rules))
	var invalid []string

	for _, r := range rules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			invalid = append(invalid, r.ID)
			continue
		}

		compiled = append(compiled, compiledRule{Rule: r, re: re})
	}

	if len(compiled) == 0 {
		if len(invalid) > 0 {
			return nil, fmt.Errorf("no valid rules - invalid patterns for: %s", strings.Join(invalid, ", "))
		}

		return nil, fmt.Errorf("no rules provided")
	}

	if len(invalid) > 0 {
		return compiled, fmt.Errorf("invalid patterns for: %s", strings.Join(invalid, ", "))
	}

	return compiled, nil
}

func extToLang(ext string) string {
	switch ext {
	case ".js", ".ts":
		return "js"
	case ".py":
		return "python"
	case ".php":
		return "php"
	case ".java":
		return "java"
	case ".go":
		return "go"
	case ".cs":
		return "csharp"
	case ".rb":
		return "ruby"
	case ".c", ".cpp", ".h", ".hpp":
		return "c"
	default:
		return ""
	}
}
