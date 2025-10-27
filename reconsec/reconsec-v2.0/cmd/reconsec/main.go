package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/ghostn3xus/reconsec/internal/cli"
	"github.com/ghostn3xus/reconsec/internal/runner"
	"github.com/ghostn3xus/reconsec/pkg/report"
	"github.com/ghostn3xus/reconsec/pkg/scanner"
)

func main() {
	if len(os.Args) < 2 {
		usage(); return
	}
	switch os.Args[1] {
	case "recon":
		rc := cli.NewReconCmd(); rc.Parse(os.Args[2:])
		if rc.URL == "" { log.Fatal("use: reconsec recon -url https://target") }
		res, err := runner.RunRecon(rc); if err != nil { log.Fatal(err) }
		emitIfNoOut(res, rc.OutFile)
	case "sca":
		sc := cli.NewSCACmd(); sc.Parse(os.Args[2:])
		res := report.RunSCALocal(sc.Path)
		emit(sc.OutFile, res)
	case "scan":
		sc := cli.NewScanCmd(); sc.Parse(os.Args[2:])
		res := report.RunSASTLite(sc.Path)
		emit(sc.OutFile, res)
	case "test":
		tc := cli.NewTestCmd(); tc.Parse(os.Args[2:])
		findings, err := scanner.RunTests(scanner.TestOptions{
			URL: tc.URL, Only: tc.Only, Mode: tc.Mode, ConfirmText: tc.ConfirmAuth, TimeoutSec: tc.Timeout, Rate: tc.Rate,
		})
		if err != nil { log.Fatal(err) }
		emit(tc.OutFile, findings)
	case "full":
		fc := cli.NewFullCmd(); fc.Parse(os.Args[2:])
		res, err := runner.RunFull(fc); if err != nil { log.Fatal(err) }
		emit(fc.OutFile, res)
	case "version":
		fmt.Println("reconsec v2.0 -", time.Now().Format(time.RFC3339))
	default:
		usage()
	}
}

func usage() {
	fmt.Println("reconsec — Recon & AppSec Suite (safe by default)")
	fmt.Println("usage: reconsec <recon|sca|scan|test|full> [flags]")
	fmt.Println("try: reconsec recon -url https://example.com -out recon.json --txt")
}

func emit(out string, v any) {
	if out == "" {
		enc := json.NewEncoder(os.Stdout); enc.SetIndent("", "  "); _ = enc.Encode(v); return
	}
	f, err := os.Create(out); if err != nil { log.Fatal(err) }
	defer f.Close()
	enc := json.NewEncoder(f); enc.SetIndent("", "  "); _ = enc.Encode(v)
	fmt.Println("Wrote", out)
}
func emitIfNoOut(v any, out string) {
	if out == "" {
		enc := json.NewEncoder(os.Stdout); enc.SetIndent("", "  "); _ = enc.Encode(v)
	}
}
