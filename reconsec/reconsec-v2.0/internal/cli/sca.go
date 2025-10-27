package cli

import "flag"

type SCACmd struct {
	Base
	Path string
}

func NewSCACmd() *SCACmd { return &SCACmd{} }

func (c *SCACmd) Parse(args []string) {
	fs := flag.NewFlagSet("sca", flag.ExitOnError)
	addCommonFlags(fs, &c.Base)
	fs.StringVar(&c.Path, "path", ".", "path to project (local)")
	_ = fs.Parse(args)
}
