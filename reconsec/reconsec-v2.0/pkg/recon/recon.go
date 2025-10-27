package recon

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/ghostn3xus/reconsec/pkg/report"
	"github.com/ghostn3xus/reconsec/pkg/utils"
)

type Options struct {
	URL        string
	Depth      int
	TimeoutSec int
	Rate       int
	Verbose    bool
}

func Passive(opt Options) report.PassiveRecon {
	if opt.Depth < 1 { opt.Depth = 1 }
	if opt.Depth > 2 { opt.Depth = 2 }
	out := report.PassiveRecon{
		Target: opt.URL, Headers: map[string]string{}, StatusSeen: map[int]int{}, FetchedAt: time.Now(),
	}
	base := baseURL(opt.URL)
	body, hdr, code := fetch(opt, base)
	for k, v := range hdr { out.Headers[k] = strings.Join(v, "; ") }
	if code != 0 { out.StatusSeen[code]++ }

	if txt, _, sc := fetchBody(opt, base+"/robots.txt"); txt != "" {
		out.Robots = txt
		out.StatusSeen[sc]++
		for _, ln := range strings.Split(txt, "\n") {
			ln = strings.TrimSpace(ln)
			if strings.HasPrefix(strings.ToLower(ln), "sitemap:") {
				su := strings.TrimSpace(strings.TrimPrefix(ln, "Sitemap:"))
				if su != "" { out.Sitemaps = append(out.Sitemaps, su) }
			}
		}
	}
	if sm, _, sc := fetchBody(opt, base+"/sitemap.xml"); sm != "" {
		out.StatusSeen[sc]++
		type urlset struct{ URLs []struct{ Loc string `xml:"loc"` } `xml:"url"` }
		var us urlset; _ = xml.Unmarshal([]byte(sm), &us)
		for _, it := range us.URLs { out.URLs = append(out.URLs, it.Loc) }
	}

	out.URLs = append(out.URLs, extractLinks(body, base)...)
	out.JSURLs = append(out.JSURLs, extractJSURLs(body, base)...)
	out.Forms  = append(out.Forms, extractForms(body, base)...)

	for k, v := range out.Headers {
		lk := strings.ToLower(k + ":" + v)
		if strings.Contains(lk, "cloudflare") { out.TechHints = append(out.TechHints, "cloudflare") }
		if strings.Contains(lk, "nginx") { out.TechHints = append(out.TechHints, "nginx") }
		if strings.Contains(lk, "apache") { out.TechHints = append(out.TechHints, "apache") }
		if strings.Contains(lk, "asp.net") { out.TechHints = append(out.TechHints, "asp.net") }
	}
	return out
}

func baseURL(u string) string {
	pu, err := url.Parse(u); if err != nil { return u }
	return pu.Scheme + "://" + pu.Host
}

func fetch(opt Options, u string) (string, http.Header, int) {
	cl := utils.HTTPClient(opt.TimeoutSec)
	resp, err := cl.Get(u)
	if err != nil { return "", http.Header{}, 0 }
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2_000_000))
	return string(b), resp.Header, resp.StatusCode
}

func fetchBody(opt Options, u string) (string, http.Header, int) {
	cl := utils.HTTPClient(opt.TimeoutSec)
	resp, err := cl.Get(u)
	if err != nil { return "", http.Header{}, 0 }
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2_000_000))
	return string(b), resp.Header, resp.StatusCode
}

func extractLinks(body, base string) []string {
	var out []string
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil { return out }
	doc.Find("a[href]").Each(func(_ int, s *goquery.Selection){
		h, _ := s.Attr("href")
		h = strings.TrimSpace(h)
		if strings.HasPrefix(h, "/") { out = append(out, base+h) }
		if strings.HasPrefix(h, "http") { out = append(out, h) }
	})
	return dedup(out)
}

func extractJSURLs(body, base string) []string {
	var out []string
	re := regexp.MustCompile(`(?i)(fetch|axios|XMLHttpRequest)\s*\(\s*['"]([^'"]+)['"]`)
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		u := m[2]
		if strings.HasPrefix(u, "/") { out = append(out, base+u) }
		if strings.HasPrefix(u, "http") { out = append(out, u) }
	}
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err == nil {
		doc.Find("script[src]").Each(func(_ int, s *goquery.Selection){
			src, _ := s.Attr("src")
			if strings.HasPrefix(src, "/") { out = append(out, base+src) }
			if strings.HasPrefix(src, "http") { out = append(out, src) }
		})
	}
	return dedup(out)
}

func extractForms(body, base string) []string {
	var out []string
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil { return out }
	doc.Find("form").Each(func(_ int, s *goquery.Selection){
		if act, ok := s.Attr("action"); ok {
			act = strings.TrimSpace(act)
			if strings.HasPrefix(act, "/") { out = append(out, base+act) }
			if strings.HasPrefix(act, "http") { out = append(out, act) }
		}
	})
	return dedup(out)
}

func dedup(in []string) []string {
	seen := map[string]bool{}; var out []string
	for _, s := range in {
		if !seen[s] { seen[s] = true; out = append(out, s) }
	}
	return out
}
