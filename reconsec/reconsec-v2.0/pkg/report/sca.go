package report

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

func ScanDependencies(root string) SCAResult {
	var res SCAResult
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil { return nil }
		if info.IsDir() { return nil }
		name := strings.ToLower(filepath.Base(path))
		switch name {
		case "package.json":
			res.Dependencies = append(res.Dependencies, parsePackageJSON(path)...)
		case "requirements.txt":
			res.Dependencies = append(res.Dependencies, parseRequirements(path)...)
		case "go.mod":
			res.Dependencies = append(res.Dependencies, parseGoMod(path)...)
		case "composer.lock":
			res.Dependencies = append(res.Dependencies, parseComposerLock(path)...)
		}
		return nil
	})
	return res
}

func parsePackageJSON(path string) []SCAItem {
	var out []SCAItem
	f, err := os.Open(path); if err != nil { return out }
	defer f.Close()
	var obj map[string]any
	if err := json.NewDecoder(f).Decode(&obj); err != nil { return out }
	if deps, ok := obj["dependencies"].(map[string]any); ok {
		for k, v := range deps { out = append(out, SCAItem{ Manager:"npm", Name:k, Version: toStr(v), File: path }) }
	}
	if dev, ok := obj["devDependencies"].(map[string]any); ok {
		for k, v := range dev { out = append(out, SCAItem{ Manager:"npm", Name:k, Version: toStr(v), File: path }) }
	}
	return out
}
func toStr(v any) string { if s, ok := v.(string); ok { return s }; return "" }

func parseRequirements(path string) []SCAItem {
	var out []SCAItem
	f, err := os.Open(path); if err != nil { return out }
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ln := strings.TrimSpace(sc.Text())
		if ln=="" || strings.HasPrefix(ln, "#") { continue }
		name := ln; ver := ""
		if strings.Contains(ln, "==") {
			parts := strings.SplitN(ln, "==", 2); name = parts[0]; ver = parts[1]
		}
		out = append(out, SCAItem{ Manager:"pip", Name:name, Version:ver, File:path })
	}
	return out
}

func parseGoMod(path string) []SCAItem {
	var out []SCAItem
	f, err := os.Open(path); if err != nil { return out }
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ln := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(ln, "require ") { continue }
		fields := strings.Fields(ln)
		if len(fields)>=2 && strings.Contains(fields[0], "/") {
			out = append(out, SCAItem{ Manager:"go", Name:fields[0], Version:fields[1], File:path })
		}
	}
	return out
}

type composerLock struct {
	Packages []struct{ Name, Version string } `json:"packages"`
}
func parseComposerLock(path string) []SCAItem {
	var out []SCAItem
	f, err := os.Open(path); if err != nil { return out }
	defer f.Close()
	var lock composerLock
	if err := json.NewDecoder(f).Decode(&lock); err != nil { return out }
	for _, p := range lock.Packages {
		out = append(out, SCAItem{ Manager:"composer", Name:p.Name, Version:p.Version, File:path })
	}
	return out
}
