package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/ghostn3xus/reconsec/internal/cli"
	"github.com/ghostn3xus/reconsec/internal/runner"
	"github.com/ghostn3xus/reconsec/pkg/active"
	"github.com/ghostn3xus/reconsec/pkg/dast"
	"github.com/ghostn3xus/reconsec/pkg/poc"
	"github.com/ghostn3xus/reconsec/pkg/report"
	"github.com/ghostn3xus/reconsec/pkg/scanner"
	"github.com/ghostn3xus/reconsec/pkg/sast"
)

func main() {
	if len(os.Args) < 2 {
		usage(); return
	}
	switch os.Args[1] {
	case "version":
		fmt.Println("reconsec final -", time.Now().Format(time.RFC3339))
	case "recon":
		// placeholder - use internal runner in full implementation
		fmt.Println("recon command (use subcommands in full build)")
	case "activescan":
		// basic arg parse (for demo)
		urlArg := ""
		payloadsPath := "payloads/approved.json"
		sandbox := false
		confirm := ""
		for i, a := range os.Args {
			if a == "-url" && i+1 < len(os.Args) { urlArg = os.Args[i+1] }
			if a == "-payloads" && i+1 < len(os.Args) { payloadsPath = os.Args[i+1] }
			if a == "--sandbox" && i+1 < len(os.Args) && os.Args[i+1] == "true" { sandbox = true }
			if a == "--confirm-authorized" && i+1 < len(os.Args) { confirm = os.Args[i+1] }
		}
		opts := active.ActiveOptions{ URL: urlArg, PayloadsPath: payloadsPath, SandboxEnabled: sandbox, ConfirmAuthText: confirm, TimeoutSec: 20, Rate: 4 }
		res, err := active.RunActiveScan(opts)
		if err != nil { log.Fatal(err) }
		enc := json.NewEncoder(os.Stdout); enc.SetIndent("", "  "); _ = enc.Encode(res)
	case "proxy":
		// start proxy (demo)
		addr := ":8081"; logPath := "/tmp/recon-proxy.log"
		p, err := dast.NewProxy(addr, logPath)
		if err != nil { log.Fatal(err) }
		defer p.Close()
		if err := p.Start(); err != nil { log.Fatal(err) }
	case "sast-scan":
		// args: path to code
		root := "."
		rulesPath := "pkg/sast/rules.json"
		if len(os.Args) > 2 { root = os.Args[2] }
		rules, err := sast.LoadRules(rulesPath)
		if err != nil { log.Fatal(err) }
		findings, err := sast.ScanPathWithRules(root, rules)
		if err != nil { log.Fatal(err) }
		enc := json.NewEncoder(os.Stdout); enc.SetIndent("", "  "); _ = enc.Encode(findings)
	case "test":
		// simple safe probe demo
		if len(os.Args) < 3 { fmt.Println("usage: reconsec test <url>"); return }
		url := os.Args[2]
		f, err := poc.SafeProbe(poc.PoCOptions{ URL: url, Param: "reconsec_probe", Token: "__RECONSEC_TEST__", Timeout: 10, MaxReads: 200000 })
		if err != nil { log.Fatal(err) }
		enc := json.NewEncoder(os.Stdout); enc.SetIndent("", "  "); _ = enc.Encode(f)
	default:
		usage()
	}
}

func usage() {
	fmt.Println("reconsec final - comandos: version, activescan, proxy, sast-scan, test")
}
