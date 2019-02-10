package facade

import (
	"bytes"
	"testing"

	"github.com/spiegel-im-spiegel/gocli/exitcode"
	"github.com/spiegel-im-spiegel/gocli/rwi"
)

var (
	binTOMLdata1            = []byte{0xa8, 0x03, 0x50, 0x47, 0x50, 0xc3, 0x04, 0x04, 0x03, 0x00, 0x01, 0xc9, 0x38, 0xe7, 0x2d, 0x2f, 0xb1, 0xf1, 0x0f, 0xc3, 0xce, 0x55, 0x5d, 0xb2, 0x8a, 0x4b, 0xe8, 0x4f, 0x43, 0x15, 0x6e, 0x7d, 0x90, 0x90, 0x53, 0x6a, 0x9a, 0xe3, 0xaa, 0x1c, 0x68, 0xd6, 0xd3, 0xfc, 0x6a, 0x4e, 0x79, 0xa8, 0xe7, 0xb1, 0xa5, 0x87, 0xea, 0xcc, 0xcc, 0x99, 0x66, 0x31, 0xad, 0xff, 0xe1, 0xa3, 0x03, 0xb6, 0x47, 0x85, 0x76, 0xbd, 0x0b}
	resTOMLdataFromBindata1 = `[[Packet]]
  name = "Marker Packet (Obsolete Literal Packet) (tag 10)"
  note = "3 bytes"

  [[Packet.Item]]
    name = "Literal data"
    note = "3 bytes"

[[Packet]]
  name = "Symmetric-Key Encrypted Session Key Packet (tag 3)"
  note = "4 bytes"

  [[Packet.Item]]
    name = "Version"
    value = "4"
    note = "current"

  [[Packet.Item]]
    name = "Symmetric Algorithm"
    value = "CAST5 (128 bit key, as per) (sym 3)"

  [[Packet.Item]]
    name = "String-to-Key (S2K) Algorithm"
    value = "Simple S2K (s2k 0)"

    [[Packet.Item.Item]]
      name = "Hash Algorithm"
      value = "MD5 (hash 1)"

[[Packet]]
  name = "Symmetrically Encrypted Data Packet (tag 9)"
  note = "56 bytes"

  [[Packet.Item]]
    name = "Encrypted data"
    value = "sym alg is specified in sym-key encrypted session key"
    note = "56 bytes"
`
)

func TestTOMLLoadByStdin(t *testing.T) {
	inData := bytes.NewReader(binTOMLdata1)
	outBuf := new(bytes.Buffer)
	outErrBuf := new(bytes.Buffer)
	ui := rwi.New(rwi.WithReader(inData), rwi.WithWriter(outBuf), rwi.WithErrorWriter(outErrBuf))
	args := []string{"-t"}

	exit := Execute(ui, args)
	if exit != exitcode.Normal {
		t.Errorf("Execute(stdin) = \"%v\", want \"%v\".", exit, exitcode.Normal)
	}
	str := outErrBuf.String()
	if str != "" {
		t.Errorf("Execute(stdin) = \"%v\", want \"%v\".", str, "")
	}
	str = outBuf.String()
	if str != resTOMLdataFromBindata1 {
		t.Errorf("Execute(stdin) = \"%v\", want \"%v\".", str, resTOMLdataFromBindata1)
	}
}

func TestTOMLLoadByNosata(t *testing.T) {
	inData := bytes.NewReader([]byte{})
	outBuf := new(bytes.Buffer)
	outErrBuf := new(bytes.Buffer)
	ui := rwi.New(rwi.WithReader(inData), rwi.WithWriter(outBuf), rwi.WithErrorWriter(outErrBuf))
	args := []string{"-t"}

	exit := Execute(ui, args)
	if exit != exitcode.Normal {
		t.Errorf("Execute(nodata) = \"%v\", want \"%v\".", exit, exitcode.Normal)
	}
	str := outErrBuf.String()
	if str != "" {
		t.Errorf("Execute(nodata) = \"%v\", want \"%v\".", str, "")
	}
	str = outBuf.String()
	if str != "" {
		t.Errorf("Execute(stdin) = \"%v\", want \"%v\".", str, "")
	}
}

func TestTOMLLoadByFile(t *testing.T) {
	outBuf := new(bytes.Buffer)
	outErrBuf := new(bytes.Buffer)
	ui := rwi.New(rwi.WithWriter(outBuf), rwi.WithErrorWriter(outErrBuf))
	args := []string{"-t", "testdata/bindata1"}

	exit := Execute(ui, args)
	if exit != exitcode.Normal {
		t.Errorf("Execute(file) = \"%v\", want \"%v\".", exit, exitcode.Normal)
	}
	str := outErrBuf.String()
	if str != "" {
		t.Errorf("Execute(file) = \"%v\", want \"%v\".", str, "")
	}
	str = outBuf.String()
	if str != resTOMLdataFromBindata1 {
		t.Errorf("Execute(file) = \"%v\", want \"%v\".", str, resTOMLdataFromBindata1)
	}
}

func TestTOMLLoadByNofile(t *testing.T) {
	outBuf := new(bytes.Buffer)
	outErrBuf := new(bytes.Buffer)
	ui := rwi.New(rwi.WithWriter(outBuf), rwi.WithErrorWriter(outErrBuf))
	args := []string{"-t", "noexist"}

	exit := Execute(ui, args)
	if exit != exitcode.Abnormal {
		t.Errorf("Execute(nofile) = \"%v\", want \"%v\".", exit, exitcode.Abnormal)
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
