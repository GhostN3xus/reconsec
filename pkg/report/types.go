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
	Time       time.Time  `json:"time,omitempty"`
}
