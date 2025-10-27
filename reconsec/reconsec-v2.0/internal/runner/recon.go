package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ghostn3xus/reconsec/internal/cli"
	"github.com/ghostn3xus/reconsec/pkg/recon"
	"github.com/ghostn3xus/reconsec/pkg/report"
	"github.com/ghostn3xus/reconsec/pkg/utils"
)

func RunRecon(c *cli.ReconCmd) (report.PassiveRecon, error) {
	if c.URL == "" {
		return report.PassiveRecon{}, fmt.Errorf("url is required")
	}
	res := recon.Passive(recon.Options{
		URL: c.URL, Depth: c.Depth, TimeoutSec: c.Timeout, Rate: c.Rate, Verbose: c.Verbose,
	})
	if c.OutFile != "" {
		if err := writeJSON(c.OutFile, res); err != nil {
			return res, err
		}
	}
	if c.OutTXT {
		_, _ = report.SaveReconText(res, "")
	}
	if c.OutHTML && c.OutFile != "" {
		_ = report.RenderReconHTML(res, c.OutFile)
	}
	return res, nil
}

func writeJSON(path string, v any) error {
	f, err := os.Create(path); if err != nil { return err }
	defer f.Close()
	enc := json.NewEncoder(f); enc.SetIndent("", "  "); return enc.Encode(v)
}

type FullResult struct {
	Target    string
	Recon     report.PassiveRecon
	SCA       report.SCAResult
	Findings  []report.Finding
	Summary   report.Summary
	GeneratedAt time.Time
}

func RunFull(c *cli.FullCmd) (FullResult, error) {
	r := FullResult{ Target: c.URL, GeneratedAt: time.Now() }
	if c.URL == "" { return r, fmt.Errorf("url required") }

	r.Recon = recon.Passive(recon.Options{ URL: c.URL, Depth: 1, TimeoutSec: c.Timeout, Rate: c.Rate, Verbose: c.Verbose })
	r.SCA = report.RunSCALocal(c.Code)
	r.Findings = append(r.Findings, report.RunSASTLite(c.Code)...)

	for _, f := range r.Findings {
		switch f.Severity {
		case report.SeverityHigh: r.Summary.High++
		case report.SeverityMedium: r.Summary.Medium++
		case report.SeverityLow: r.Summary.Low++
		}
	}

	if c.OutFile != "" { _ = writeJSON(c.OutFile, r) }
	if c.Report != "" { _ = report.RenderFullHTML(r, c.Report) }
	_, _ = report.SaveReconText(r.Recon, "")
	fmt.Println("Full pipeline done for", utils.SanitizeFilename(c.URL))
	return r, nil
}
