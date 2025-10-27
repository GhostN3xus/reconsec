package active

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/ghostn3xus/reconsec/pkg/report"
)

type ActiveOptions struct {
	URL string
	PayloadsPath string
	SandboxEnabled bool
	ConfirmAuthText string
	TimeoutSec int
	Rate int
}

type PayloadTemplate struct {
	Name string `json:"name"`
	Category string `json:"category"`
	Template string `json:"template"`
	Notes string `json:"notes,omitempty"`
}

func LoadPayloads(path string) ([]PayloadTemplate, error) {
	f, err := os.ReadFile(path)
	if err != nil { return nil, err }
	var arr []PayloadTemplate
	if err := json.Unmarshal(f, &arr); err != nil { return nil, err }
	return arr, nil
}

func RunActiveScan(opts ActiveOptions) ([]report.Finding, error) {
	var findings []report.Finding
	if strings.TrimSpace(opts.ConfirmAuthText) == "" {
		return findings, fmt.Errorf("explicit authorization required")
	}
	if !opts.SandboxEnabled {
		return findings, fmt.Errorf("sandbox required")
	}
	payloads, err := LoadPayloads(opts.PayloadsPath)
	if err != nil { return findings, err }
	marker := "__RECONSEC_ACTIVE_MARKER__" + time.Now().Format("150405")
	for _, p := range payloads {
		payload := strings.ReplaceAll(p.Template, "{{INJECT}}", marker)
		// call helper script (user must configure)
		cmd := exec.Command("bash", "scripts/run_payload_in_sandbox.sh", opts.URL, payload)
		if err := cmd.Run(); err != nil {
			findings = append(findings, report.Finding{ Type: "ActiveExecError", Severity: report.SeverityLow, Confidence: report.ConfidenceLow, URL: opts.URL, Notes: err.Error() })
			continue
		}
		findings = append(findings, report.Finding{ Type: "ActiveAttempt", Severity: report.SeverityLow, Confidence: report.ConfidenceLow, URL: opts.URL, Notes: "Executed payload in sandbox: " + p.Name })
		time.Sleep(time.Duration(1000/opts.Rate) * time.Millisecond)
	}
	return findings, nil
}
