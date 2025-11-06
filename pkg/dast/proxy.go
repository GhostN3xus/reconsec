package dast

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ghostn3xus/reconsec/pkg/report"
)

type Proxy struct {
	Addr       string
	LogPath    string
	MaxBody    int64
	TimeoutSec int
	logger     *log.Logger
	file       *os.File
}

func NewProxy(addr, logPath string) (*Proxy, error) {
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, err
	}
	p := &Proxy{Addr: addr, LogPath: logPath, MaxBody: 200000, TimeoutSec: 15, file: f}
	p.logger = log.New(io.MultiWriter(os.Stdout, f), "[recon-proxy] ", log.LstdFlags)
	return p, nil
}

func (p *Proxy) Close() error {
	if p.file != nil {
		return p.file.Close()
	}
	return nil
}

func (p *Proxy) Start() error {
	server := &http.Server{Addr: p.Addr, Handler: http.HandlerFunc(p.handleHTTP), ReadTimeout: time.Duration(p.TimeoutSec) * time.Second, WriteTimeout: time.Duration(p.TimeoutSec) * time.Second}
	p.logger.Printf("starting proxy on %s, logging to %s\n", p.Addr, p.LogPath)
	return server.ListenAndServe()
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		p.handleTunneling(w, req)
		return
	}
	p.logRequest(req) // Manter o registro para depuração
	transport := http.DefaultTransport
	resp, err := transport.RoundTrip(req)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		p.logger.Printf("roundtrip error: %v", err)
		return
	}
	defer resp.Body.Close()

	// Analisar a resposta e registrar os achados
	p.analyzeAndReport(resp)

	p.logResponse(resp) // Manter o registro para depuração
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, io.LimitReader(resp.Body, p.MaxBody)); err != nil {
		p.logger.Printf("body copy error: %v", err)
	}
}

func (p *Proxy) analyzeAndReport(resp *http.Response) {
	findings := p.analyzeHeaders(resp)
	if len(findings) > 0 {
		p.logger.Println("=== DAST Findings ===")
		enc := json.NewEncoder(p.logger.Writer())
		enc.SetIndent("", "  ")
		for _, f := range findings {
			_ = enc.Encode(f)
		}
		p.logger.Println("===================")
	}
}

func (p *Proxy) analyzeHeaders(resp *http.Response) []report.Finding {
	var findings []report.Finding

	// Verificações de cabeçalhos de segurança ausentes
	missingHeaders := []struct {
		Name     string
		Severity report.Severity
		CWE      string
	}{
		{"Content-Security-Policy", report.SeverityMedium, "CWE-693"},
		{"Strict-Transport-Security", report.SeverityMedium, "CWE-319"},
		{"X-Content-Type-Options", report.SeverityLow, "CWE-693"},
		{"X-Frame-Options", report.SeverityLow, "CWE-1021"},
	}

	for _, h := range missingHeaders {
		if resp.Header.Get(h.Name) == "" {
			findings = append(findings, report.Finding{
				Type:       "MissingSecurityHeader",
				Severity:   h.Severity,
				Confidence: report.ConfidenceHigh,
				URL:        resp.Request.URL.String(),
				Notes:      fmt.Sprintf("Missing security header: %s", h.Name),
				CWE:        h.CWE,
			})
		}
	}

	return findings
}

func (p *Proxy) handleTunneling(w http.ResponseWriter, req *http.Request) {
	destConn, err := net.DialTimeout("tcp", req.Host, time.Duration(p.TimeoutSec)*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
	p.logger.Printf("tunnel established to %s\n", req.Host)
}

func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}

func (p *Proxy) logRequest(req *http.Request) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("REQ %s %s %s\n", req.Method, req.URL.String(), req.Proto))
	for k, vv := range req.Header {
		for _, v := range vv {
			sb.WriteString(fmt.Sprintf("%s: %s\n", k, v))
		}
	}
	if req.Body != nil && req.ContentLength != 0 {
		body, _ := io.ReadAll(io.LimitReader(req.Body, p.MaxBody))
		sb.WriteString("BODY:\n")
		sb.Write(body)
		sb.WriteString("\n--END-BODY--\n")
		req.Body = io.NopCloser(strings.NewReader(string(body)))
	}
	sb.WriteString("\n")
	p.logger.Print(sb.String())
}

func (p *Proxy) logResponse(resp *http.Response) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("RESP %s %s\n", resp.Proto, resp.Status))
	for k, vv := range resp.Header {
		for _, v := range vv {
			sb.WriteString(fmt.Sprintf("%s: %s\n", k, v))
		}
	}
	if resp.Body != nil {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, p.MaxBody))
		sb.WriteString("BODY:\n")
		sb.Write(body)
		sb.WriteString("\n--END-BODY--\n")
		resp.Body = io.NopCloser(strings.NewReader(string(body)))
	}
	sb.WriteString("\n")
	p.logger.Print(sb.String())
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
