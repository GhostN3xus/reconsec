package sast

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCompileRulesRejectsInvalidPatterns(t *testing.T) {
	_, err := compileRules([]Rule{{ID: "bad", Pattern: "["}})
	if err == nil {
		t.Fatalf("expected compile error")
	}
}

func TestScanPathWithRules(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "sample.go")
	if err := os.WriteFile(target, []byte("package main\nfunc main() { println(\"hi\") }\n"), 0600); err != nil {
		t.Fatalf("write sample: %v", err)
	}

	rules := []Rule{{
		ID:          "print",
		Language:    "go",
		Description: "use of println",
		Pattern:     "println\\(",
		Severity:    "medium",
	}}

	findings, err := ScanPathWithRules(dir, rules)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].File != target {
		t.Fatalf("unexpected file: %s", findings[0].File)
	}
}
