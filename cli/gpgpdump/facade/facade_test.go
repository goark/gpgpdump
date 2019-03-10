package facade

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/spiegel-im-spiegel/gocli/exitcode"
	"github.com/spiegel-im-spiegel/gocli/rwi"
)

var (
	bindata1 = []byte{0xa8, 0x03, 0x50, 0x47, 0x50, 0xc3, 0x04, 0x04, 0x03, 0x00, 0x01, 0xc9, 0x38, 0xe7, 0x2d, 0x2f, 0xb1, 0xf1, 0x0f, 0xc3, 0xce, 0x55, 0x5d, 0xb2, 0x8a, 0x4b, 0xe8, 0x4f, 0x43, 0x15, 0x6e, 0x7d, 0x90, 0x90, 0x53, 0x6a, 0x9a, 0xe3, 0xaa, 0x1c, 0x68, 0xd6, 0xd3, 0xfc, 0x6a, 0x4e, 0x79, 0xa8, 0xe7, 0xb1, 0xa5, 0x87, 0xea, 0xcc, 0xcc, 0x99, 0x66, 0x31, 0xad, 0xff, 0xe1, 0xa3, 0x03, 0xb6, 0x47, 0x85, 0x76, 0xbd, 0x0b}
	ascdata1 = `
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v2

iF4EARMIAAYFAlTDCN8ACgkQMfv9qV+7+hg2HwEA6h2iFFuCBv3VrsSf2BREQaT1
T1ZprZqwRPOjiLJg9AwA/ArTwCPz7c2vmxlv7sRlRLUI6CdsOqhuO1KfYXrq7idI
=ZOTN
-----END PGP SIGNATURE-----
`
)

var (
	resdataFromBindata1 = `Marker Packet (Obsolete Literal Packet) (tag 10) (3 bytes)
	Literal data (3 bytes)
Symmetric-Key Encrypted Session Key Packet (tag 3) (4 bytes)
	Version: 4 (current)
	Symmetric Algorithm: CAST5 (128 bit key, as per) (sym 3)
	String-to-Key (S2K) Algorithm: Simple S2K (s2k 0)
		Hash Algorithm: MD5 (hash 1)
Symmetrically Encrypted Data Packet (tag 9) (56 bytes)
	Encrypted data: sym alg is specified in sym-key encrypted session key (56 bytes)
`
	resdataFromAscdata1 = `Signature Packet (tag 2) (94 bytes)
	Version: 4 (current)
	Signiture Type: Signature of a canonical text document (0x01)
	Public-key Algorithm: ECDSA public key algorithm (pub 19)
	Hash Algorithm: SHA2-256 (hash 8)
	Hashed Subpacket (6 bytes)
		Signature Creation Time (sub 2): 2015-01-24T02:52:15Z
	Unhashed Subpacket (10 bytes)
		Issuer (sub 16): 0x31fbfda95fbbfa18
	Hash left 2 bytes
		36 1f
	ECDSA value r (256 bits)
	ECDSA value s (252 bits)
`
)

func TestLoadByStdin(t *testing.T) {
	inData := bytes.NewReader(bindata1)
	outBuf := new(bytes.Buffer)
	outErrBuf := new(bytes.Buffer)
	ui := rwi.New(rwi.WithReader(inData), rwi.WithWriter(outBuf), rwi.WithErrorWriter(outErrBuf))
	args := []string{}

	exit := Execute(ui, args)
	if exit != exitcode.Normal {
		t.Errorf("Execute(stdin) = \"%v\", want \"%v\".", exit, exitcode.Normal)
	}
	str := outErrBuf.String()
	if str != "" {
		t.Errorf("Execute(stdin) = \"%v\", want \"%v\".", str, "")
	}
	str = outBuf.String()
	if str != resdataFromBindata1 {
		t.Errorf("Execute(stdin) = \"%v\", want \"%v\".", str, resdataFromBindata1)
	}
}

func TestLoadByNosata(t *testing.T) {
	inData := bytes.NewReader([]byte{})
	outBuf := new(bytes.Buffer)
	outErrBuf := new(bytes.Buffer)
	ui := rwi.New(rwi.WithReader(inData), rwi.WithWriter(outBuf), rwi.WithErrorWriter(outErrBuf))
	args := []string{}

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

func TestLoadByFile(t *testing.T) {
	outBuf := new(bytes.Buffer)
	outErrBuf := new(bytes.Buffer)
	ui := rwi.New(rwi.WithWriter(outBuf), rwi.WithErrorWriter(outErrBuf))
	args := []string{"testdata/bindata1"}

	exit := Execute(ui, args)
	if exit != exitcode.Normal {
		t.Errorf("Execute(file) = \"%v\", want \"%v\".", exit, exitcode.Normal)
	}
	str := outErrBuf.String()
	if str != "" {
		t.Errorf("Execute(file) = \"%v\", want \"%v\".", str, "")
	}
	str = outBuf.String()
	if str != resdataFromBindata1 {
		t.Errorf("Execute(file) = \"%v\", want \"%v\".", str, resdataFromBindata1)
	}
}

func TestLoadByNofile(t *testing.T) {
	outBuf := new(bytes.Buffer)
	outErrBuf := new(bytes.Buffer)
	ui := rwi.New(rwi.WithWriter(outBuf), rwi.WithErrorWriter(outErrBuf))
	args := []string{"--debug", "noexist"}

	exit := Execute(ui, args)
	if exit != exitcode.Abnormal {
		t.Errorf("Execute(nofile) = \"%v\", want \"%v\".", exit, exitcode.Abnormal)
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
