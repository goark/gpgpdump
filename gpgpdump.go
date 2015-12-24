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

func setupFacade(ui *gocli.UI) *facade.Facade {
	return facade.NewFacade(Name, Version, ui)
}

func main() {
	ui := gocli.NewUI()
	fcd := setupFacade(ui)
	if rtn, err := fcd.Run(os.Args[1:]); rtn != facade.ExitCodeOK {
		if err != nil {
			ui.OutputErrln(err)
		}
		os.Exit(rtn)
	}
	os.Exit(facade.ExitCodeOK)
}
