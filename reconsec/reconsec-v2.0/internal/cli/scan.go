package cli

import "flag"

type ScanCmd struct {
	Base
	Path string
}

func NewScanCmd() *ScanCmd { return &ScanCmd{} }

func (c *ScanCmd) Parse(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	addCommonFlags(fs, &c.Base)
	fs.StringVar(&c.Path, "path", ".", "path to source code")
	_ = fs.Parse(args)
}
