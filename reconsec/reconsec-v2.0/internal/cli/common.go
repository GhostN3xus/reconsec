package cli

import "flag"

type Base struct {
	OutFile   string
	OutHTML   bool
	OutTXT    bool
	Verbose   bool
	Timeout   int
	Rate      int
}

func addCommonFlags(fs *flag.FlagSet, b *Base) {
	fs.StringVar(&b.OutFile, "out", "", "output file (json or html if --html)")
	fs.BoolVar(&b.OutHTML, "html", false, "render HTML report")
	fs.BoolVar(&b.OutTXT, "txt", false, "also write a .txt summary")
	fs.BoolVar(&b.Verbose, "verbose", false, "verbose output")
	fs.IntVar(&b.Timeout, "timeout", 15, "HTTP timeout seconds")
	fs.IntVar(&b.Rate, "rate", 4, "requests per second limit (best-effort)")
}
