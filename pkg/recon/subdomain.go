package recon

import (
	"fmt"
	"net"
	"strings"
	"sync"
)

// SubdomainOptions holds the options for a subdomain scan.
type SubdomainOptions struct {
	Domain   string
	Wordlist []string
	Threads  int
}

// RunSubdomainScan performs a two-phase subdomain enumeration.
func RunSubdomainScan(opts SubdomainOptions) []string {
	if opts.Threads <= 0 {
		opts.Threads = 10
	}

	// --- Fase 1: Enumeração por Lista de Palavras ---
	fmt.Println("Fase 1: Iniciando enumeração por lista de palavras...")
	initialResults := resolveDomains(opts.Domain, opts.Wordlist, opts.Threads)
	fmt.Printf("Fase 1: Encontrados %d subdomínios.\n", len(initialResults))

	// --- Fase 2: Enumeração por Permutação ---
	fmt.Println("Fase 2: Gerando e testando permutações...")
	permutationCandidates := generatePermutations(initialResults, opts.Domain)
	permutationResults := resolveDomains(opts.Domain, permutationCandidates, opts.Threads)
	fmt.Printf("Fase 2: Encontrados %d novos subdomínios por permutação.\n", len(permutationResults))

	// Combina e remove duplicatas
	allFound := make(map[string]struct{})
	for _, r := range initialResults {
		allFound[r] = struct{}{}
	}
	for _, r := range permutationResults {
		allFound[r] = struct{}{}
	}

	finalResults := []string{}
	for r := range allFound {
		finalResults = append(finalResults, r)
	}

	return finalResults
}

// resolveDomains é uma função auxiliar para resolver uma lista de nomes de domínio.
func resolveDomains(baseDomain string, candidates []string, threads int) []string {
	found := make(chan string)
	var wg sync.WaitGroup
	domainChan := make(chan string, threads)

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range domainChan {
				target := fmt.Sprintf("%s.%s", c, baseDomain)
				if _, err := net.LookupHost(target); err == nil {
					found <- target
				}
			}
		}()
	}

	for _, c := range candidates {
		domainChan <- c
	}
	close(domainChan)

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

// generatePermutations cria novas palavras de subdomínio a partir dos resultados iniciais.
func generatePermutations(foundSubdomains []string, baseDomain string) []string {
	permutations := make(map[string]struct{})

	// Palavras comuns para substituição e adição
	words := []string{"dev", "stage", "prod", "test", "uat", "qa", "web", "api", "db", "devops", "admin"}

	for _, sub := range foundSubdomains {
		// Remove o domínio base para trabalhar apenas com o subdomínio
		sub = strings.TrimSuffix(sub, "."+baseDomain)
		parts := strings.Split(sub, ".")

		if len(parts) > 1 {
			// Ex: dev.api.example.com -> parts = ["dev", "api"]
			// 1. Substituir a primeira parte: "dev" -> "stage", "prod", etc.
			//    Resulta em: stage.api, prod.api
			for _, word := range words {
				if parts[0] != word {
					permutations[word+"."+strings.Join(parts[1:], ".")] = struct{}{}
				}
			}
		}

		// 2. Adicionar prefixos: "api" -> "dev-api", "test-api", etc.
		for _, word := range words {
			permutations[word+"-"+sub] = struct{}{}
		}
	}

	var resultList []string
	for p := range permutations {
		resultList = append(resultList, p)
	}
	return resultList
}


// DefaultWordlist returns a small, default list of subdomains to check.
func DefaultWordlist() []string {
	return []string{
		"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2", "admin",
		"dev", "test", "web", "demo", "vpn", "m", "shop", "api", "prod", "staging",
	}
}
