package scanner

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ghostn3xus/reconsec/pkg/report"
	"github.com/ghostn3xus/reconsec/pkg/utils"
)

type TestOptions struct {
	URL         string
	Only        string // xss|sqli|rce|all
	Mode        string // passive|active
	ConfirmText string
	TimeoutSec  int
	Rate        int
}

func RunTests(opt TestOptions) ([]report.Finding, error) {
	if opt.URL == "" { return nil, fmt.Errorf("url required") }
	if opt.Mode == "active" && strings.TrimSpace(opt.ConfirmText)=="" {
		return nil, fmt.Errorf("active mode requires --confirm-authorized text")
	}
	token := "__RECONSEC_"+time.Now().Format("150405")+"__"
	target, err := url.Parse(opt.URL); if err != nil { return nil, err }

	q := target.Query()
	q.Set("reconsec_test", token)
	target.RawQuery = q.Encode()

	cl := utils.HTTPClient(opt.TimeoutSec)
	resp, err := cl.Get(target.String())
	if err != nil { return nil, err }
	defer resp.Body.Close()

	findings := []report.Finding{}
	sev := report.SeverityLow
	if resp.StatusCode >= 500 { sev = report.SeverityHigh } else if resp.StatusCode >= 400 { sev = report.SeverityMedium }
	findings = append(findings, report.Finding{
		Type:"StatusCode", Severity: sev, Confidence: report.ConfidenceMedium, URL: target.String(),
		Notes: fmt.Sprintf("Observed status %d for tokenized request", resp.StatusCode),
	})

	if opt.Mode == "active" {
		findings = append(findings, report.Finding{
			Type:"ActiveTestInfo", Severity: report.SeverityLow, Confidence: report.ConfidenceLow, URL: opt.URL,
			Notes: "Active mode requested but not executed in this safe build; requires explicit authorized payload set.",
		})
	}
	return findings, nil
}
