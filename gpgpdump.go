package main

import (
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/spiegel-im-spiegel/gocli"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/facade"
)

var (
	// Name of application
	Name = "gpgpdump"
	// Version of application
	Version = "v0.1.2"
)

func setupFacade(ui *gocli.UI) *facade.Facade {
	return facade.NewFacade(Name, Version, runtime.Version(), ui)
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

/* Copyright 2016 Spiegel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
