package facade

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/spiegel-im-spiegel/gocli/exitcode"
	"github.com/spiegel-im-spiegel/gocli/rwi"
)

func TestArmorNormal(t *testing.T) {
	inData := bytes.NewBufferString(ascdata1)
	outBuf := new(bytes.Buffer)
	outErrBuf := new(bytes.Buffer)
	ui := rwi.New(rwi.WithReader(inData), rwi.WithWriter(outBuf), rwi.WithErrorWriter(outErrBuf))
	args := []string{"-a", "-u"}

	exit := Execute(ui, args)
	if exit != exitcode.Normal {
		t.Errorf("Execute(armor) = \"%v\", want \"%v\".", exit, exitcode.Normal)
	}
	str := outErrBuf.String()
	if str != "" {
		t.Errorf("Execute(armor) = \"%v\", want \"%v\".", str, "")
	}
	str = outBuf.String()
	if str != resdataFromAscdata1 {
		t.Errorf("Execute(armor) = \"%v\", want \"%v\".", str, resdataFromAscdata1)
	}
}

func TestArmorErr(t *testing.T) {
	inData := bytes.NewReader(bindata1)
	outBuf := new(bytes.Buffer)
	outErrBuf := new(bytes.Buffer)
	ui := rwi.New(rwi.WithReader(inData), rwi.WithWriter(outBuf), rwi.WithErrorWriter(outErrBuf))
	args := []string{"-a", "--debug"}

	exit := Execute(ui, args)
	if exit != exitcode.Abnormal {
		t.Errorf("Execute(armor) = \"%v\", want \"%v\".", exit, exitcode.Abnormal)
	} else {
		fmt.Printf("Info: %+v", outErrBuf.String())
	}
}

/* Copyright 2017-2019 Spiegel
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
