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

func loadIgnorePatterns(root string) ([]string, error) {
	var patterns []string
	ignorePath := filepath.Join(root, ".reconsec-ignore")
	if _, err := os.Stat(ignorePath); os.IsNotExist(err) {
		return patterns, nil // Nenhum arquivo de ignore, não faz nada
	}

	file, err := os.Open(ignorePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			patterns = append(patterns, line)
		}
	}
	return patterns, scanner.Err()
}

func isIgnored(path string, patterns []string) bool {
	for _, p := range patterns {
		if matched, _ := filepath.Match(p, filepath.Base(path)); matched {
			return true
		}
		if matched, _ := filepath.Match(p, path); matched {
			return true
		}
	}
	return false
}

func ScanPathWithRules(root string, rules []Rule) ([]report.Finding, error) {
	var findings []report.Finding

	compiledRules, err := compileRules(rules)
	if err != nil {
		return findings, err
	}

	ignorePatterns, err := loadIgnorePatterns(root)
	if err != nil {
		return findings, fmt.Errorf("could not load ignore patterns: %w", err)
	}

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Ignorar diretórios e arquivos
		if isIgnored(path, ignorePatterns) {
			if d.IsDir() {
				return filepath.SkipDir // Pula o diretório inteiro
			}
			return nil // Pula o arquivo
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
			return nil // Pode ser um erro de permissão, continua para o próximo
		}
		defer f.Close()

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

		if err := scanner.Err(); err != nil {
			// Logar o erro, mas não parar a varredura inteira
			fmt.Fprintf(os.Stderr, "error scanning file %s: %v\n", path, err)
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
