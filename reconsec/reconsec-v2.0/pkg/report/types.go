package report

import "time"

type Severity string
type Confidence string

const (
	SeverityHigh   Severity = "HIGH"
	SeverityMedium Severity = "MEDIUM"
	SeverityLow    Severity = "LOW"

	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

type Finding struct {
	Type       string     `json:"type"`
	CWE        string     `json:"cwe,omitempty"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	File       string     `json:"file,omitempty"`
	Line       int        `json:"line,omitempty"`
	URL        string     `json:"url,omitempty"`
	Notes      string     `json:"notes,omitempty"`
	Snippet    string     `json:"snippet,omitempty"`
}

type PassiveRecon struct {
	Target     string            `json:"target"`
	Headers    map[string]string `json:"headers,omitempty"`
	Robots     string            `json:"robots_txt,omitempty"`
	Sitemaps   []string          `json:"sitemaps,omitempty"`
	URLs       []string          `json:"urls,omitempty"`
	JSURLs     []string          `json:"js_urls,omitempty"`
	Forms      []string          `json:"forms,omitempty"`
	FetchedAt  time.Time         `json:"fetched_at"`
	TechHints  []string          `json:"tech_hints,omitempty"`
	StatusSeen map[int]int       `json:"status_seen,omitempty"`
}

type SCAItem struct {
	Manager string `json:"manager"` // npm,pip,go,maven,composer
	Name    string `json:"name"`
	Version string `json:"version"`
	File    string `json:"file"`
}

type SCAResult struct {
	Dependencies []SCAItem `json:"dependencies"`
}

type Summary struct {
	High int `json:"high"`
	Medium int `json:"medium"`
	Low int `json:"low"`
}
