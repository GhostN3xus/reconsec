package recon

import (
	"fmt"
	"net"
	"sync"
)

// SubdomainOptions holds the options for a subdomain scan.
type SubdomainOptions struct {
	Domain    string
	Wordlist  []string
	Threads   int
}

// RunSubdomainScan performs a subdomain enumeration.
func RunSubdomainScan(opts SubdomainOptions) []string {
	if opts.Threads <= 0 {
		opts.Threads = 10
	}

	found := make(chan string)
	var wg sync.WaitGroup
	subdomains := make(chan string, opts.Threads)

	for i := 0; i < opts.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for subdomain := range subdomains {
				target := fmt.Sprintf("%s.%s", subdomain, opts.Domain)
				if _, err := net.LookupHost(target); err == nil {
					found <- target
				}
			}
		}()
	}

	for _, s := range opts.Wordlist {
		subdomains <- s
	}
	close(subdomains)

	results := []string{}
	done := make(chan struct{})
	go func() {
		for f := range found {
			results = append(results, f)
		}
		close(done)
	}()

	wg.Wait()
	close(found)
	<-done

	return results
}

// DefaultWordlist returns a small, default list of subdomains to check.
func DefaultWordlist() []string {
	return []string{
		"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2", "admin",
		"dev", "test", "web", "demo", "vpn", "m", "shop", "api", "prod", "staging",
	}
}
