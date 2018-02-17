package facade

import (
	"bytes"
	"testing"

	"github.com/spiegel-im-spiegel/gocli/exitcode"
	"github.com/spiegel-im-spiegel/gocli/rwi"
)

func TestOptionsNormal(t *testing.T) {
	inData := bytes.NewReader(bindata1)
	outBuf := new(bytes.Buffer)
	outErrBuf := new(bytes.Buffer)
	ui := rwi.New(rwi.Reader(inData), rwi.Writer(outBuf), rwi.ErrorWriter(outErrBuf))
	args := []string{"-i", "-l", "-m", "-p", "-u", "--debug"}

	exit := Execute(ui, args)
	if exit != exitcode.Normal {
		t.Errorf("Execute(options) = \"%v\", want \"%v\".", exit, exitcode.Normal)
	}
}

func TestOptionsAbnormal(t *testing.T) {
	inData := bytes.NewReader(bindata1)
	outBuf := new(bytes.Buffer)
	outErrBuf := new(bytes.Buffer)
	ui := rwi.New(rwi.Reader(inData), rwi.Writer(outBuf), rwi.ErrorWriter(outErrBuf))
	args := []string{"-d"}

	exit := Execute(ui, args)
	if exit != exitcode.Abnormal {
		t.Errorf("Execute(options) = \"%v\", want \"%v\".", exit, exitcode.Abnormal)
	}
}

/* Copyright 2017,2018 Spiegel
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
