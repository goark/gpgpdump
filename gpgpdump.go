package main

import (
	"os"
	"path"
	"strings"

	"github.com/spiegel-im-spiegel/gocli"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/facade"
)

var (
	// Name of application
	Name = "gpgpdump"
	// Version of application
	Version = "v0.1.0"
	// GoVersion of go version
	GoVersion = ""
)

func setupFacade(ui *gocli.UI) *facade.Facade {
	return facade.NewFacade(Name, Version, GoVersion, ui)
}

func main() {
	Name = path.Base(strings.Replace(os.Args[0], "\\", "/", -1))
	ui := gocli.NewUI()
	fcd := setupFacade(ui)
	if rtn, err := fcd.Run(os.Args[1:]); rtn != facade.ExitSuccess {
		if err != nil {
			ui.OutputErrln(err)
		}
		os.Exit(rtn)
	}
	os.Exit(facade.ExitSuccess)
}
