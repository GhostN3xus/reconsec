package report

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func SASTLite(root string) []Finding {
	var out []Finding
	rules := []struct{
		re *regexp.Regexp
		f Finding
	}{
		{regexp.MustCompile(`\beval\s*\(`), Finding{Type:"RCE", CWE:"CWE-95", Severity:SeverityHigh, Confidence:ConfidenceHigh, Notes:"eval usage"}},
		{regexp.MustCompile(`child_process\.(exec|spawn|execSync)`), Finding{Type:"RCE", CWE:"CWE-78", Severity:SeverityHigh, Confidence:ConfidenceMedium, Notes:"child_process"}},
		{regexp.MustCompile(`\.(query|execute)\s*\(`), Finding{Type:"SQLi", CWE:"CWE-89", Severity:SeverityHigh, Confidence:ConfidenceMedium, Notes:"DB call"}},
		{regexp.MustCompile(`\b(include|require)(_once)?\s*\(`), Finding{Type:"LFI", CWE:"CWE-98", Severity:SeverityHigh, Confidence:ConfidenceHigh, Notes:"include/require"}},
	}
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() { return nil }
		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".js",".ts",".py",".php",".rb",".go",".java",".cs",".c",".cpp",".h":
		default: return nil
		}
		f, err := os.Open(path); if err != nil { return nil }
		defer f.Close()
		sc := bufio.NewScanner(f); line := 0
		for sc.Scan() {
			line++
			ln := sc.Text()
			for _, r := range rules {
				if r.re.MatchString(ln) {
					ff := r.f; ff.File = path; ff.Line = line; ff.Snippet = strings.TrimSpace(ln)
					out = append(out, ff)
				}
			}
		}
		return nil
	})
	return out
}
