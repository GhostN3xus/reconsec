package discovery

import (
	"net/http"
	"net/url"
	"sync"

	"github.com/ghostn3xus/reconsec/pkg/utils"
)

// DirScanOptions holds the options for a directory scan.
type DirScanOptions struct {
	BaseURL     string
	Wordlist    []string
	Threads     int
	SuccessCodes []int
}

// ScanResult holds the result of a single path scan.
type ScanResult struct {
	URL        string
	StatusCode int
}

// RunDirScan performs a directory and file discovery scan.
func RunDirScan(opts DirScanOptions) []ScanResult {
	if opts.Threads <= 0 {
		opts.Threads = 10
	}
	if len(opts.SuccessCodes) == 0 {
		opts.SuccessCodes = []int{200, 204, 301, 302, 307, 401, 403}
	}

	results := make(chan ScanResult)
	var wg sync.WaitGroup
	paths := make(chan string, opts.Threads)
	client := utils.HTTPClient(10)

	for i := 0; i < opts.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range paths {
				targetURL, err := url.JoinPath(opts.BaseURL, path)
				if err != nil {
					continue // Ignora caminhos inválidos
				}

				req, err := http.NewRequest("GET", targetURL, nil)
				if err != nil {
					continue
				}
				req.Header.Set("User-Agent", "ReconSec-DirScan/1.0")

				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				defer resp.Body.Close()

				for _, code := range opts.SuccessCodes {
					if resp.StatusCode == code {
						results <- ScanResult{URL: targetURL, StatusCode: resp.StatusCode}
						break
					}
				}
			}
		}()
	}

	for _, p := range opts.Wordlist {
		paths <- p
	}
	close(paths)

	scanResults := []ScanResult{}
	done := make(chan struct{})
	go func() {
		for r := range results {
			scanResults = append(scanResults, r)
		}
		close(done)
	}()

	wg.Wait()
	close(results)
	<-done

	return scanResults
}

// DefaultDirWordlist returns a small, default list of directories/files to check.
func DefaultDirWordlist() []string {
	return []string{
		"admin", "login", "dashboard", "api", "test", "dev", "backup",
		"config", "secret", "users", "wp-admin", "wp-login.php",
		".git/config", ".env", "robots.txt", "sitemap.xml",
	}
}
