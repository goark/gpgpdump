package facade

import (
	"bytes"
	"testing"

	"github.com/spiegel-im-spiegel/gocli"
)

func TestVersionMin(t *testing.T) {
	result := "gpgpdump\nCopyright 2016,2017 Spiegel (based on pgpdump by kazu-yamamoto)\nLicensed under Apache License, Version 2.0\n"

	outBuf := new(bytes.Buffer)
	outErrBuf := new(bytes.Buffer)
	ui := gocli.NewUI(gocli.Writer(outBuf), gocli.ErrorWriter(outErrBuf))
	args := []string{"-v"}

	clearFlags()
	exit := Execute(ui, args)
	if exit != ExitNormal {
		t.Errorf("Execute(version) = \"%v\", want \"%v\".", exit, ExitNormal)
	}
	str := outBuf.String()
	if str != "" {
		t.Errorf("Execute(version) = \"%v\", want \"%v\".", str, "")
	}
	str = outErrBuf.String()
	if str != result {
		t.Errorf("Execute(version) = \"%v\", want \"%v\".", str, result)
	}
}

func TestVersionNum(t *testing.T) {
	Version = "TestVersion"
	result := "gpgpdump vTestVersion\nCopyright 2016,2017 Spiegel (based on pgpdump by kazu-yamamoto)\nLicensed under Apache License, Version 2.0\n"

	outBuf := new(bytes.Buffer)
	outErrBuf := new(bytes.Buffer)
	ui := gocli.NewUI(gocli.Writer(outBuf), gocli.ErrorWriter(outErrBuf))
	args := []string{"-v"}

	clearFlags()
	exit := Execute(ui, args)
	if exit != ExitNormal {
		t.Errorf("Execute(version) = \"%v\", want \"%v\".", exit, ExitNormal)
	}
	str := outBuf.String()
	if str != "" {
		t.Errorf("Execute(version) = \"%v\", want \"%v\".", str, "")
	}
	str = outErrBuf.String()
	if str != result {
		t.Errorf("Execute(version) = \"%v\", want \"%v\".", str, result)
	}
}

/* Copyright 2017 Spiegel
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
