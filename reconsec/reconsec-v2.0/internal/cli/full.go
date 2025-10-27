package cli

import "flag"

type FullCmd struct {
	Base
	URL    string
	Code   string
	Report string // report html path if set
	ConfirmAuth string
}

func NewFullCmd() *FullCmd { return &FullCmd{} }

func (c *FullCmd) Parse(args []string) {
	fs := flag.NewFlagSet("full", flag.ExitOnError)
	addCommonFlags(fs, &c.Base)
	fs.StringVar(&c.URL, "url", "", "target URL")
	fs.StringVar(&c.Code, "code", ".", "local code path for SAST/SCA")
	fs.StringVar(&c.Report, "report", "", "if set and ends with .html, will render HTML report")
	fs.StringVar(&c.ConfirmAuth, "confirm-authorized", "", "explicit authorization text (required if active tests enabled by config)")
	_ = fs.Parse(args)
}
