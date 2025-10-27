package active

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/ghostn3xus/reconsec/pkg/report"
)

type ActiveOptions struct {
	URL             string
	PayloadsPath    string
	SandboxEnabled  bool
	ConfirmAuthText string
	TimeoutSec      int
	Rate            int
}

type PayloadTemplate struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Template string `json:"template"`
	Notes    string `json:"notes,omitempty"`
}

func LoadPayloads(path string) ([]PayloadTemplate, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("payload path required")
	}

	f, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var arr []PayloadTemplate
	if err := json.Unmarshal(f, &arr); err != nil {
		return nil, err
	}

	if len(arr) == 0 {
		return nil, fmt.Errorf("no payload templates found in %s", path)
	}

	return arr, nil
}

func RunActiveScan(opts ActiveOptions) ([]report.Finding, error) {
	var findings []report.Finding
	if strings.TrimSpace(opts.URL) == "" {
		return findings, fmt.Errorf("target URL required")
	}

	if strings.TrimSpace(opts.ConfirmAuthText) == "" {
		return findings, fmt.Errorf("explicit authorization required")
	}

	if !opts.SandboxEnabled {
		return findings, fmt.Errorf("sandbox required")
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
		err := cmd.Run()
		cancel()

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

		findings = append(findings, report.Finding{
			Type:       "ActiveAttempt",
			Severity:   report.SeverityLow,
			Confidence: report.ConfidenceLow,
			URL:        opts.URL,
			Notes:      "Executed payload in sandbox: " + p.Name,
		})

		if sleepInterval > 0 {
			time.Sleep(sleepInterval)
		}
	}

	return findings, nil
}
