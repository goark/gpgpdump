package main

import (
	"os"

	"github.com/spiegel-im-spiegel/gocli"
	"github.com/spiegel-im-spiegel/gpgpdump/facade"
)

const (
	// Name of application
	Name string = "gpgpdump"
	// Version of application
	Version string = "0.1.0"
)

func main() {
	ui := gocli.NewUI()
	if rtn, err := facade.Run(os.Args[1:], Name, Version, ui); rtn != facade.ExitCodeOK {
		if err != nil {
			ui.OutputErrln(err)
		}
		os.Exit(rtn)
	}
	os.Exit(facade.ExitCodeOK)
}
