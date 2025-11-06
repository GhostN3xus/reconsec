package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/ghostn3xus/reconsec/pkg/active"
	"github.com/ghostn3xus/reconsec/pkg/dast"
	"github.com/ghostn3xus/reconsec/pkg/discovery"
	"github.com/ghostn3xus/reconsec/pkg/poc"
	"github.com/ghostn3xus/reconsec/pkg/recon"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "reconsec",
	Short: "ReconSec is a focused reconnaissance and dynamic analysis tool.",
	Long: `A versatile CLI tool for reconnaissance (subdomains, directories),
and dynamic analysis.`,
}

func init() {
	// version
	rootCmd.AddCommand(versionCmd)

	// recon
	reconCmd.Flags().String("wordlist", "", "Path to a custom wordlist file for subdomain enumeration")
	reconCmd.Flags().Int("threads", 10, "Number of threads to use for subdomain enumeration")
	rootCmd.AddCommand(reconCmd)

	// dirscan
	dirscanCmd.Flags().String("wordlist", "", "Path to a custom wordlist file for directory scanning")
	dirscanCmd.Flags().Int("threads", 10, "Number of threads to use for directory scanning")
	rootCmd.AddCommand(dirscanCmd)

	// activescan
	activescanCmd.Flags().String("url", "", "Target URL for the active scan")
	activescanCmd.Flags().String("payloads", "payloads/", "Path to the directory containing payload files")
	activescanCmd.Flags().Bool("sandbox", false, "Must be true to enable the sandbox and run the scan")
	activescanCmd.MarkFlagRequired("url")
	rootCmd.AddCommand(activescanCmd)

	// proxy
	proxyCmd.Flags().String("addr", ":8081", "Address for the proxy to listen on")
	proxyCmd.Flags().String("log", "/tmp/recon-proxy.log", "Path to the proxy log file")
	rootCmd.AddCommand(proxyCmd)

	// test
	testCmd.Flags().String("param", "reconsec_probe", "The parameter name to use for the probe")
	rootCmd.AddCommand(testCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of ReconSec",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("reconsec final -", time.Now().Format(time.RFC3339))
	},
}

var reconCmd = &cobra.Command{
	Use:   "recon [domain]",
	Short: "Enumerate subdomains for a given domain",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		domain := args[0]
		wordlistPath, _ := cmd.Flags().GetString("wordlist")
		threads, _ := cmd.Flags().GetInt("threads")

		wordlist := loadWordlist(wordlistPath, recon.DefaultWordlist)
		opts := recon.SubdomainOptions{
			Domain:   domain,
			Wordlist: wordlist,
			Threads:  threads,
		}

		results := recon.RunSubdomainScan(opts)
		fmt.Println("Found subdomains:")
		for _, r := range results {
			fmt.Println(r)
		}
	},
}

var dirscanCmd = &cobra.Command{
	Use:   "dirscan [url]",
	Short: "Scan a web server for accessible directories and files",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		baseURL := args[0]
		wordlistPath, _ := cmd.Flags().GetString("wordlist")
		threads, _ := cmd.Flags().GetInt("threads")

		wordlist := loadWordlist(wordlistPath, discovery.DefaultDirWordlist)
		opts := discovery.DirScanOptions{
			BaseURL:  baseURL,
			Wordlist: wordlist,
			Threads:  threads,
		}

		results := discovery.RunDirScan(opts)
		fmt.Println("Found paths:")
		for _, r := range results {
			fmt.Printf("[%d] %s\n", r.StatusCode, r.URL)
		}
	},
}

var activescanCmd = &cobra.Command{
	Use:   "activescan",
	Short: "Run an active scan with approved payloads",
	Run: func(cmd *cobra.Command, args []string) {
		url, _ := cmd.Flags().GetString("url")
		payloads, _ := cmd.Flags().GetString("payloads")
		sandbox, _ := cmd.Flags().GetBool("sandbox")

		opts := active.ActiveOptions{
			URL:            url,
			PayloadsPath:   payloads,
			SandboxEnabled: sandbox,
			TimeoutSec:     20,
			Rate:           4,
		}

		res, err := active.RunActiveScan(opts)
		if err != nil {
			log.Fatal(err)
		}
		printJSON(res)
	},
}

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Start a simple HTTP/HTTPS logging proxy",
	Run: func(cmd *cobra.Command, args []string) {
		addr, _ := cmd.Flags().GetString("addr")
		logPath, _ := cmd.Flags().GetString("log")

		p, err := dast.NewProxy(addr, logPath)
		if err != nil {
			log.Fatal(err)
		}
		defer p.Close()

		if err := p.Start(); err != nil {
			log.Fatal(err)
		}
	},
}

var testCmd = &cobra.Command{
	Use:   "test [url]",
	Short: "Run a safe proof-of-concept probe for parameter reflection",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		url := args[0]
		param, _ := cmd.Flags().GetString("param")

		opts := poc.PoCOptions{
			URL:      url,
			Param:    param,
			Token:    "__RECONSEC_TEST__",
			Timeout:  10,
			MaxReads: 200000,
		}

		f, err := poc.SafeProbe(opts)
		if err != nil {
			log.Fatal(err)
		}
		printJSON(f)
	},
}

func loadWordlist(path string, defaultFunc func() []string) []string {
	if path == "" {
		return defaultFunc()
	}

	var wordlist []string
	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("Failed to open wordlist file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		wordlist = append(wordlist, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("Failed to read wordlist file: %v", err)
	}
	return wordlist
}

func printJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		log.Fatal(err)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
