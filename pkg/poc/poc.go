package poc

import (
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ghostn3xus/reconsec/pkg/report"
	"github.com/ghostn3xus/reconsec/pkg/utils"
)

type PoCOptions struct {
	URL      string
	Param    string
	Token    string
	Timeout  int
	Only     string
	MaxReads int64
}

func SafeProbe(opt PoCOptions) (report.Finding, error) {
	var finding report.Finding
	if strings.TrimSpace(opt.URL) == "" {
		return finding, fmt.Errorf("url required")
	}

	if opt.MaxReads <= 0 {
		opt.MaxReads = 256000
	}

	if opt.Timeout <= 0 {
		opt.Timeout = 10
	}

	if opt.Token == "" {
		opt.Token = "__RECONSEC_PROBE__"
	}
	u, err := url.Parse(opt.URL)
	if err != nil {
		return finding, err
	}
	q := u.Query()
	if opt.Param == "" {
		opt.Param = "reconsec_probe"
	}
	q.Set(opt.Param, opt.Token)
	u.RawQuery = q.Encode()
	client := utils.HTTPClient(opt.Timeout)
	resp, err := client.Get(u.String())
	if err != nil {
		return finding, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, opt.MaxReads))
	if err != nil {
		return finding, err
	}
	bodyStr := string(body)
	respLen := len(body)
	reflected := strings.Contains(bodyStr, opt.Token)
	lenUtf8 := utf8.RuneCountInString(bodyStr)
	sev := report.SeverityLow
	if resp.StatusCode >= 500 {
		sev = report.SeverityHigh
	} else if resp.StatusCode >= 400 {
		sev = report.SeverityMedium
	}
	notes := fmt.Sprintf("Status=%d; len=%d; runes=%d; reflected=%v", resp.StatusCode, respLen, lenUtf8, reflected)
	finding = report.Finding{
		Type:       "SafeProbe",
		Severity:   sev,
		Confidence: report.ConfidenceMedium,
		URL:        u.String(),
		Notes:      notes,
		Time:       time.Now(),
	}
	if reflected {
		finding.Confidence = report.ConfidenceHigh
		finding.Notes = "Token reflected; " + finding.Notes
	}
	return finding, nil
}
