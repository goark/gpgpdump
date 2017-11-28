package facade

import (
	"bytes"
	"testing"

	"github.com/spiegel-im-spiegel/gocli"
)

var (
	binTOMLdata1 = []byte{0xa8, 0x03, 0x50, 0x47, 0x50, 0xc3, 0x04, 0x04, 0x03, 0x00, 0x01, 0xc9, 0x38, 0xe7, 0x2d, 0x2f, 0xb1, 0xf1, 0x0f, 0xc3, 0xce, 0x55, 0x5d, 0xb2, 0x8a, 0x4b, 0xe8, 0x4f, 0x43, 0x15, 0x6e, 0x7d, 0x90, 0x90, 0x53, 0x6a, 0x9a, 0xe3, 0xaa, 0x1c, 0x68, 0xd6, 0xd3, 0xfc, 0x6a, 0x4e, 0x79, 0xa8, 0xe7, 0xb1, 0xa5, 0x87, 0xea, 0xcc, 0xcc, 0x99, 0x66, 0x31, 0xad, 0xff, 0xe1, 0xa3, 0x03, 0xb6, 0x47, 0x85, 0x76, 0xbd, 0x0b}
	ascTOMLdata1 = `
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v2

iF4EARMIAAYFAlTDCN8ACgkQMfv9qV+7+hg2HwEA6h2iFFuCBv3VrsSf2BREQaT1
T1ZprZqwRPOjiLJg9AwA/ArTwCPz7c2vmxlv7sRlRLUI6CdsOqhuO1KfYXrq7idI
=ZOTN
-----END PGP SIGNATURE-----
`
)

var (
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
	resTOMLdataFromAscdata1 = `[[Packet]]
  name = "Signature Packet (tag 2)"
  note = "94 bytes"

  [[Packet.Item]]
    name = "Version"
    value = "4"
    note = "current"

  [[Packet.Item]]
    name = "Signiture Type"
    value = "Signature of a canonical text document (0x01)"

  [[Packet.Item]]
    name = "Public-key Algorithm"
    value = "ECDSA public key algorithm (pub 19)"

  [[Packet.Item]]
    name = "Hash Algorithm"
    value = "SHA2-256 (hash 8)"

  [[Packet.Item]]
    name = "Hashed Subpacket"
    note = "6 bytes"

    [[Packet.Item.Item]]
      name = "Signature Creation Time (sub 2)"
      value = "2015-01-24T02:52:15Z"

  [[Packet.Item]]
    name = "Unhashed Subpacket"
    note = "10 bytes"

    [[Packet.Item.Item]]
      name = "Issuer (sub 16)"
      value = "0x31fbfda95fbbfa18"

  [[Packet.Item]]
    name = "Hash left 2 bytes"
    dump = "36 1f"

  [[Packet.Item]]
    name = "ECDSA r"
    note = "256 bits"

  [[Packet.Item]]
    name = "ECDSA s"
    note = "252 bits"
`
)

func TestTOMLLoadByStdin(t *testing.T) {
	inData := bytes.NewReader(binTOMLdata1)
	outBuf := new(bytes.Buffer)
	outErrBuf := new(bytes.Buffer)
	ui := gocli.NewUI(gocli.Reader(inData), gocli.Writer(outBuf), gocli.ErrorWriter(outErrBuf))
	args := []string{"-t"}

	clearFlags()
	exit := Execute(ui, args)
	if exit != ExitNormal {
		t.Errorf("Execute(stdin) = \"%v\", want \"%v\".", exit, ExitNormal)
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
	ui := gocli.NewUI(gocli.Reader(inData), gocli.Writer(outBuf), gocli.ErrorWriter(outErrBuf))
	args := []string{"-t"}

	clearFlags()
	exit := Execute(ui, args)
	if exit != ExitNormal {
		t.Errorf("Execute(nodata) = \"%v\", want \"%v\".", exit, ExitNormal)
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
	ui := gocli.NewUI(gocli.Writer(outBuf), gocli.ErrorWriter(outErrBuf))
	args := []string{"-t", "testdata/bindata1"}

	clearFlags()
	exit := Execute(ui, args)
	if exit != ExitNormal {
		t.Errorf("Execute(file) = \"%v\", want \"%v\".", exit, ExitNormal)
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
	ui := gocli.NewUI(gocli.Writer(outBuf), gocli.ErrorWriter(outErrBuf))
	args := []string{"-t", "noexist"}

	clearFlags()
	exit := Execute(ui, args)
	if exit != ExitAbnormal {
		t.Errorf("Execute(nofile) = \"%v\", want \"%v\".", exit, ExitAbnormal)
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
