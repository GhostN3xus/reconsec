package report

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// SaveReconText writes readable text summary named after host
func SaveReconText(recon PassiveRecon, outFile string) (string, error) {
	host := sanitizeFilename(recon.Target)
	if outFile == "" {
		outFile = fmt.Sprintf("%s-%s.txt", host, time.Now().Format("20060102-150405"))
	} else {
		if info, err := os.Stat(outFile); err == nil && info.IsDir() {
			outFile = filepath.Join(outFile, fmt.Sprintf("%s-%s.txt", host, time.Now().Format("20060102-150405")))
		}
	}
	f, err := os.Create(outFile); if err != nil { return "", err }
	defer f.Close()

	w := func(format string, a ...interface{}) { fmt.Fprintf(f, format+"\n", a...) }

	w("Recon Report for: %s", recon.Target)
	w("Fetched at: %s", recon.FetchedAt.Format(time.RFC3339))
	w("")
	w("=== Headers ===")
	if len(recon.Headers) == 0 { w("  (none)") } else {
		keys := make([]string, 0, len(recon.Headers)); for k := range recon.Headers { keys = append(keys, k) }
		sort.Strings(keys)
		for _, k := range keys { w("  %s: %s", k, recon.Headers[k]) }
	}
	w("")
	if recon.Robots != "" {
		w("=== robots.txt ===")
		for _, line := range strings.Split(recon.Robots, "\n") { w("  %s", strings.TrimRight(line, "\r")) }
		w("")
	}
	if len(recon.Sitemaps) > 0 {
		w("=== Sitemaps ===")
		for _, s := range recon.Sitemaps { w("  %s", s) }
		w("")
	}
	w("=== URLs ===")
	if len(recon.URLs) == 0 { w("  (none)") } else { for _, u := range recon.URLs { w("  %s", u) } }
	w("")
	w("=== JS Endpoints ===")
	if len(recon.JSURLs) == 0 { w("  (none)") } else { for _, u := range recon.JSURLs { w("  %s", u) } }
	w("")
	w("=== Forms ===")
	if len(recon.Forms) == 0 { w("  (none)") } else { for _, u := range recon.Forms { w("  %s", u) } }
	w("")
	if len(recon.TechHints) > 0 {
		w("=== Tech Hints ===")
		for _, t := range recon.TechHints { w("  %s", t) }
		w("")
	}
	return outFile, nil
}

func sanitizeFilename(raw string) string {
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		raw = strings.TrimPrefix(raw, "http://")
		raw = strings.TrimPrefix(raw, "https://")
	}
	raw = strings.TrimSuffix(raw, "/")
	out := make([]rune, 0, len(raw))
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r=='.' || r=='-' || r=='_' {
			out = append(out, r)
		} else { out = append(out, '_') }
	}
	if len(out)==0 { return "target" }
	return string(out)
}

type htmlData struct {
	Target     string
	GeneratedAt string
	Summary    Summary
	Recon      PassiveRecon
	Findings   []Finding
}

func RenderReconHTML(re PassiveRecon, out string) error {
	data := htmlData{
		Target: re.Target, GeneratedAt: time.Now().Format(time.RFC3339),
		Summary: Summary{}, Recon: re, Findings: []Finding{},
	}
	return renderHTML(out, data)
}

type FullResultLike struct {
	Target string
	Recon PassiveRecon
	Findings []Finding
	Summary Summary
	GeneratedAt time.Time
}

func RenderFullHTML(fr any, out string) error {
	switch v := fr.(type) {
	case FullResultLike:
		data := htmlData{
			Target: v.Target, GeneratedAt: v.GeneratedAt.Format(time.RFC3339),
			Summary: v.Summary, Recon: v.Recon, Findings: v.Findings,
		}
		return renderHTML(out, data)
	default:
		// best-effort: minimal
		data := htmlData{ Target: "unknown", GeneratedAt: time.Now().Format(time.RFC3339) }
		return renderHTML(out, data)
	}
}

func renderHTML(out string, data htmlData) error {
	tpl, err := template.ParseFiles("web/report.tmpl")
	if err != nil { return err }
	f, err := os.Create(out); if err != nil { return err }
	defer f.Close()
	return tpl.Execute(f, data)
}
