package active

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ghostn3xus/reconsec/pkg/report"
)

const successIndicator = "VULNERABLE"

type ActiveOptions struct {
	URL            string
	PayloadsPath   string
	SandboxEnabled bool
	TimeoutSec     int
	Rate           int
}

type PayloadTemplate struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Template string `json:"template"`
	Notes    string `json:"notes,omitempty"`
}

// LoadPayloads carrega templates de payload de um arquivo ou diretório.
func LoadPayloads(path string) ([]PayloadTemplate, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("payload path required")
	}

	var allPayloads []PayloadTemplate

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("could not access path %s: %w", path, err)
	}

	if info.IsDir() {
		// Se for um diretório, carrega todos os arquivos .json
		files, err := os.ReadDir(path)
		if err != nil {
			return nil, fmt.Errorf("could not read directory %s: %w", path, err)
		}

		for _, file := range files {
			if !file.IsDir() && strings.HasSuffix(strings.ToLower(file.Name()), ".json") {
				filePath := filepath.Join(path, file.Name())
				payloads, err := loadPayloadsFromFile(filePath)
				if err != nil {
					// Loga o erro, mas continua com os outros arquivos
					fmt.Fprintf(os.Stderr, "warning: could not load payload file %s: %v\n", filePath, err)
					continue
				}
				allPayloads = append(allPayloads, payloads...)
			}
		}
	} else {
		// Se for um arquivo, carrega-o diretamente
		payloads, err := loadPayloadsFromFile(path)
		if err != nil {
			return nil, err
		}
		allPayloads = append(allPayloads, payloads...)
	}

	if len(allPayloads) == 0 {
		return nil, fmt.Errorf("no payload templates found in %s", path)
	}

	return allPayloads, nil
}

// loadPayloadsFromFile carrega payloads de um único arquivo JSON.
func loadPayloadsFromFile(filePath string) ([]PayloadTemplate, error) {
	f, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var arr []PayloadTemplate
	if err := json.Unmarshal(f, &arr); err != nil {
		return nil, err
	}

	return arr, nil
}


func RunActiveScan(opts ActiveOptions) ([]report.Finding, error) {
	var findings []report.Finding
	if strings.TrimSpace(opts.URL) == "" {
		return findings, fmt.Errorf("target URL required")
	}

	if !opts.SandboxEnabled {
		return findings, fmt.Errorf("sandbox required to run active scans")
	}

	if opts.TimeoutSec <= 0 {
		opts.TimeoutSec = 30
	}

	if opts.Rate <= 0 {
		opts.Rate = 1
	}

	payloads, err := LoadPayloads(opts.PayloadsPath)
	if err != nil {
		return findings, err
	}

	marker := "__RECONSEC_ACTIVE_MARKER__" + time.Now().Format("150405")
	sleepInterval := time.Second / time.Duration(opts.Rate)
	timeout := time.Duration(opts.TimeoutSec) * time.Second

	for _, p := range payloads {
		payload := strings.ReplaceAll(p.Template, "{{INJECT}}", marker)

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		cmd := exec.CommandContext(ctx, "bash", "scripts/run_payload_in_sandbox.sh", opts.URL, payload)

		output, err := cmd.CombinedOutput()
		cancel()

		outputStr := string(output)

		if err != nil {
			note := err.Error()
			if errors.Is(err, context.DeadlineExceeded) {
				note = "payload execution timed out"
			}

			findings = append(findings, report.Finding{
				Type:       "ActiveExecError",
				Severity:   report.SeverityLow,
				Confidence: report.ConfidenceLow,
				URL:        opts.URL,
				Notes:      fmt.Sprintf("%s (%s)", note, p.Name),
			})

			continue
		}

		if strings.Contains(outputStr, successIndicator) {
			findings = append(findings, report.Finding{
				Type:       "VulnerabilityFound",
				Severity:   report.SeverityHigh,
				Confidence: report.ConfidenceHigh,
				URL:        opts.URL,
				Notes:      fmt.Sprintf("Payload '%s' triggered a success indicator.", p.Name),
				Snippet:    outputStr,
			})
		} else {
			findings = append(findings, report.Finding{
				Type:       "ActiveAttempt",
				Severity:   report.SeverityLow,
				Confidence: report.ConfidenceLow,
				URL:        opts.URL,
				Notes:      "Executed payload in sandbox: " + p.Name,
			})
		}

		if sleepInterval > 0 {
			time.Sleep(sleepInterval)
		}
	}

	return findings, nil
}
