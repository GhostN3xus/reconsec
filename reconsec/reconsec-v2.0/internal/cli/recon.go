package cli

import "flag"

type ReconCmd struct {
	Base
	URL   string
	Depth int
}

func NewReconCmd() *ReconCmd { return &ReconCmd{} }

func (c *ReconCmd) Parse(args []string) {
	fs := flag.NewFlagSet("recon", flag.ExitOnError)
	addCommonFlags(fs, &c.Base)
	fs.StringVar(&c.URL, "url", "", "target URL (https://example.com)")
	fs.IntVar(&c.Depth, "depth", 1, "crawl depth (1..2)")
	_ = fs.Parse(args)
}
