package facade

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spiegel-im-spiegel/gocli"
)

func TestArmorNormal(t *testing.T) {
	inData := bytes.NewBufferString(ascdata1)
	outBuf := new(bytes.Buffer)
	outErrBuf := new(bytes.Buffer)
	ui := gocli.NewUI(gocli.Reader(inData), gocli.Writer(outBuf), gocli.ErrorWriter(outErrBuf))
	args := []string{"-a"}

	clearFlags()
	exit := Execute(ui, args)
	if exit != ExitNormal {
		t.Errorf("Execute(armor) = \"%v\", want \"%v\".", exit, ExitNormal)
	}
	str := outErrBuf.String()
	if str != "" {
		t.Errorf("Execute(armor) = \"%v\", want \"%v\".", str, "")
	}
	str = strings.Trim(outBuf.String(), "\n")
	res := strings.Trim(resdataFromAscdata1, "\n")
	if str != res {
		t.Errorf("Execute(armor) = \"%v\", want \"%v\".", str, res)
	}
}

func TestArmorErr(t *testing.T) {
	inData := bytes.NewReader(bindata1)
	outBuf := new(bytes.Buffer)
	outErrBuf := new(bytes.Buffer)
	ui := gocli.NewUI(gocli.Reader(inData), gocli.Writer(outBuf), gocli.ErrorWriter(outErrBuf))
	args := []string{"-a"}

	clearFlags()
	exit := Execute(ui, args)
	if exit != ExitAbnormal {
		t.Errorf("Execute(armor) = \"%v\", want \"%v\".", exit, ExitAbnormal)
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
