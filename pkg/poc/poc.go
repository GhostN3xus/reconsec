package poc

import (
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/ghostn3xus/reconsec/pkg/ml"
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

// isCommonVulnParam verifica se um nome de parâmetro é comumente associado a vulnerabilidades.
func isCommonVulnParam(param string) bool {
	commonParams := []string{"page", "file", "redirect", "url", "debug", "id", "user", "name", "cmd"}
	for _, p := range commonParams {
		if strings.Contains(strings.ToLower(param), p) {
			return true
		}
	}
	return false
}

// analyzeReflectionContext analisa onde o token foi refletido e ajusta a severidade.
func analyzeReflectionContext(body, token string, currentSeverity report.Severity) (string, report.Severity) {
	if !strings.Contains(body, token) {
		return "not reflected", currentSeverity
	}

	// Verifica a reflexão em um contexto de script (XSS de alto impacto)
	if strings.Contains(body, "<script>") && strings.Contains(body, "</script>") {
		scriptContent := body[strings.Index(body, "<script>")+8 : strings.Index(body, "</script>")]
		if strings.Contains(scriptContent, token) {
			return "reflected in script tag", report.SeverityHigh
		}
	}

	// Verifica a reflexão em um atributo HTML
	if strings.Contains(body, fmt.Sprintf(`="%s"`, token)) || strings.Contains(body, fmt.Sprintf(`='%s'`, token)) {
		return "reflected in HTML attribute", report.SeverityMedium
	}

	return "reflected in body", report.SeverityLow
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

	// Determina a severidade inicial com base no código de status
	sev := report.SeverityLow
	if resp.StatusCode >= 500 {
		sev = report.SeverityHigh
	} else if resp.StatusCode >= 400 {
		sev = report.SeverityMedium
	}

	// Analisa o contexto da reflexão para ajustar a severidade
	reflectionContext, sev := analyzeReflectionContext(bodyStr, opt.Token, sev)
	reflected := reflectionContext != "not reflected"

	// Integração com ML
	model, _ := ml.LoadModel("") // Carrega o modelo padrão
	features := map[string]float64{
		"param_name_entropy": ml.CalculateEntropy(opt.Param),
		"param_name_len":     float64(len(opt.Param)),
		"is_common_name":     0,
	}
	if isCommonVulnParam(opt.Param) {
		features["is_common_name"] = 1
	}
	interestScore := model.Score(features)

	notes := fmt.Sprintf("Status=%d; len=%d; reflected=%s; interest_score=%.2f",
		resp.StatusCode, respLen, reflectionContext, interestScore)

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
	}

	return finding, nil
}
