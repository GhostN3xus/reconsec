package cli

import "flag"

type TestCmd struct {
	Base
	URL         string
	Only        string // xss|sqli|rce|all
	Mode        string // passive|active
	ConfirmAuth string // textual confirmation for active mode
}

func NewTestCmd() *TestCmd { return &TestCmd{} }

func (c *TestCmd) Parse(args []string) {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	addCommonFlags(fs, &c.Base)
	fs.StringVar(&c.URL, "url", "", "target URL")
	fs.StringVar(&c.Only, "only", "all", "only: xss|sqli|rce|all")
	fs.StringVar(&c.Mode, "mode", "passive", "mode: passive|active")
	fs.StringVar(&c.ConfirmAuth, "confirm-authorized", "", "explicit authorization text (required for active mode)")
	_ = fs.Parse(args)
}

func (c *TestCmd) AuthorizedActive() bool {
	return c.Mode == "active" && c.ConfirmAuth != ""
}
