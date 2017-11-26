package packet

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/spiegel-im-spiegel/gpgpdump/options"
)

const (
	sample0 = ""
	sample2 = `
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v2

iF4EARMIAAYFAlTDCN8ACgkQMfv9qV+7+hg2HwEA6h2iFFuCBv3VrsSf2BREQaT1
T1ZprZqwRPOjiLJg9AwA/ArTwCPz7c2vmxlv7sRlRLUI6CdsOqhuO1KfYXrq7idI
=ZOTN
-----END PGP SIGNATURE-----
`
	sample3 = `
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Hello world
-----BEGIN PGP SIGNATURE-----

iHUEAREIAB0WIQQbUgLbSj7HdvHgrRi02juufiC4HAUCWhkOcwAKCRC02juufiC4
HDXOAP937RgFSwmBTQI3pf2EvSj+iPvZo6PLj0x/jz5YcYoodwD/YbCFjV7ydjgp
6bvdPeReurhUI5a2lUGRvU7h+D3KbDY=
=/RVh
-----END PGP SIGNATURE-----
`
)

var sample4 = []byte{0xa8, 0x03, 0x50, 0x47, 0x50, 0xc3, 0x04, 0x04, 0x03, 0x00, 0x01, 0xc9, 0x38, 0xe7, 0x2d, 0x2f, 0xb1, 0xf1, 0x0f, 0xc3, 0xce, 0x55, 0x5d, 0xb2, 0x8a, 0x4b, 0xe8, 0x4f, 0x43, 0x15, 0x6e, 0x7d, 0x90, 0x90, 0x53, 0x6a, 0x9a, 0xe3, 0xaa, 0x1c, 0x68, 0xd6, 0xd3, 0xfc, 0x6a, 0x4e, 0x79, 0xa8, 0xe7, 0xb1, 0xa5, 0x87, 0xea, 0xcc, 0xcc, 0x99, 0x66, 0x31, 0xad, 0xff, 0xe1, 0xa3, 0x03, 0xb6, 0x47, 0x85, 0x76, 0xbd, 0x0b}

const (
	result1 = "{}\n"
	result2 = `{
  "Packet": [
    {
      "name": "Signature Packet (tag 2)",
      "dump": "04 01 13 08 00 06 05 02 54 c3 08 df 00 0a 09 10 31 fb fd a9 5f bb fa 18 36 1f 01 00 ea 1d a2 14 5b 82 06 fd d5 ae c4 9f d8 14 44 41 a4 f5 4f 56 69 ad 9a b0 44 f3 a3 88 b2 60 f4 0c 00 fc 0a d3 c0 23 f3 ed cd af 9b 19 6f ee c4 65 44 b5 08 e8 27 6c 3a a8 6e 3b 52 9f 61 7a ea ee 27 48",
      "note": "94 bytes",
      "Item": [
        {
          "name": "Version",
          "value": "4",
          "dump": "04",
          "note": "new"
        },
        {
          "name": "Signiture Type",
          "value": "Signature of a canonical text document (0x01)",
          "dump": "01"
        },
        {
          "name": "Public-key Algorithm",
          "value": "ECDSA public key algorithm (pub 19)",
          "dump": "13"
        },
        {
          "name": "Hash Algorithm",
          "value": "SHA256 (hash 8)",
          "dump": "08"
        },
        {
          "name": "Hashed Subpacket",
          "dump": "05 02 54 c3 08 df",
          "note": "6 bytes",
          "Item": [
            {
              "name": "Signature Creation Time (sub 2)",
              "value": "2015-01-24T02:52:15Z",
              "dump": "54 c3 08 df"
            }
          ]
        },
        {
          "name": "Unhashed Subpacket",
          "dump": "09 10 31 fb fd a9 5f bb fa 18",
          "note": "10 bytes",
          "Item": [
            {
              "name": "Issuer (sub 16)",
              "value": "0x31fbfda95fbbfa18"
            }
          ]
        },
        {
          "name": "Hash left 2 bytes",
          "dump": "36 1f"
        },
        {
          "name": "ECDSA r",
          "note": "256 bits"
        },
        {
          "name": "ECDSA s",
          "note": "252 bits"
        }
      ]
    }
  ]
}
`
	result3 = `{
  "Packet": [
    {
      "name": "Signature Packet (tag 2)",
      "dump": "04 01 11 08 00 1d 16 21 04 1b 52 02 db 4a 3e c7 76 f1 e0 ad 18 b4 da 3b ae 7e 20 b8 1c 05 02 5a 19 0e 73 00 0a 09 10 b4 da 3b ae 7e 20 b8 1c 35 ce 00 ff 77 ed 18 05 4b 09 81 4d 02 37 a5 fd 84 bd 28 fe 88 fb d9 a3 a3 cb 8f 4c 7f 8f 3e 58 71 8a 28 77 00 ff 61 b0 85 8d 5e f2 76 38 29 e9 bb dd 3d e4 5e ba b8 54 23 96 b6 95 41 91 bd 4e e1 f8 3d ca 6c 36",
      "note": "117 bytes",
      "Item": [
        {
          "name": "Version",
          "value": "4",
          "dump": "04",
          "note": "new"
        },
        {
          "name": "Signiture Type",
          "value": "Signature of a canonical text document (0x01)",
          "dump": "01"
        },
        {
          "name": "Public-key Algorithm",
          "value": "DSA (Digital Signature Algorithm) (pub 17)",
          "dump": "11"
        },
        {
          "name": "Hash Algorithm",
          "value": "SHA256 (hash 8)",
          "dump": "08"
        },
        {
          "name": "Hashed Subpacket",
          "dump": "16 21 04 1b 52 02 db 4a 3e c7 76 f1 e0 ad 18 b4 da 3b ae 7e 20 b8 1c 05 02 5a 19 0e 73",
          "note": "29 bytes",
          "Item": [
            {
              "name": "Issuer Fingerprint (sub 33)",
              "dump": "04 1b 52 02 db 4a 3e c7 76 f1 e0 ad 18 b4 da 3b ae 7e 20 b8 1c",
              "note": "21 bytes",
              "Item": [
                {
                  "name": "Version",
                  "value": "4",
                  "note": "need 20 octets length"
                },
                {
                  "name": "Fingerprint",
                  "dump": "1b 52 02 db 4a 3e c7 76 f1 e0 ad 18 b4 da 3b ae 7e 20 b8 1c",
                  "note": "20 bytes"
                }
              ]
            },
            {
              "name": "Signature Creation Time (sub 2)",
              "value": "2017-11-25T06:32:19Z",
              "dump": "5a 19 0e 73"
            }
          ]
        },
        {
          "name": "Unhashed Subpacket",
          "dump": "09 10 b4 da 3b ae 7e 20 b8 1c",
          "note": "10 bytes",
          "Item": [
            {
              "name": "Issuer (sub 16)",
              "value": "0xb4da3bae7e20b81c"
            }
          ]
        },
        {
          "name": "Hash left 2 bytes",
          "dump": "35 ce"
        },
        {
          "name": "DSA r",
          "note": "255 bits"
        },
        {
          "name": "DSA s",
          "note": "255 bits"
        }
      ]
    }
  ]
}
`
	result4 = `{
  "Packet": [
    {
      "name": "Marker Packet (Obsolete Literal Packet) (tag 10)",
      "note": "3 bytes",
      "Item": [
        {
          "name": "Literal data",
          "note": "3 bytes"
        }
      ]
    },
    {
      "name": "Symmetric-Key Encrypted Session Key Packet (tag 3)",
      "note": "4 bytes",
      "Item": [
        {
          "name": "Version",
          "value": "4",
          "note": "new"
        },
        {
          "name": "Symmetric Algorithm",
          "value": "CAST5 (sym 3)"
        },
        {
          "name": "String-to-Key (S2K) Algorithm",
          "value": "Simple S2K (s2k 0)",
          "Item": [
            {
              "name": "Hash Algorithm",
              "value": "MD5 (hash 1)"
            }
          ]
        }
      ]
    },
    {
      "name": "Symmetrically Encrypted Data Packet (tag 9)",
      "note": "56 bytes",
      "Item": [
        {
          "name": "Encrypted data",
          "note": "sym alg is specified in sym-key encrypted session key"
        }
      ]
    }
  ]
}
`
)

func TestParseNilOption(t *testing.T) {
	_, err := NewParser(bytes.NewBufferString(sample2), nil)
	if err != nil {
		t.Errorf("NewParser()  = \"%v\", want nil error.", err)
	}
}

func TestParseNilData(t *testing.T) {
	opts := options.New(
		options.Set(options.ArmorOpt, true),
		options.Set(options.DebugOpt, true),
	)
	_, err := NewParser(nil, opts)
	if err == nil {
		t.Error("NewParser()  = nil error, not want nil error.")
	} else {
		fmt.Println("info:", err)
	}
}

func TestParseEmptyData(t *testing.T) {
	opts := options.New(
		options.Set(options.ArmorOpt, true),
		options.Set(options.DebugOpt, true),
	)
	_, err := NewParser(bytes.NewBufferString(sample0), opts)
	if err == nil {
		t.Error("NewParser()  = nil error, not want nil error.")
	} else {
		fmt.Println("info:", err)
	}
}

func TestParse(t *testing.T) {
	opts := options.New(
		options.Set(options.ArmorOpt, true),
		options.Set(options.DebugOpt, true),
		options.Set(options.UTCOpt, true),
	)
	parser, err := NewParser(bytes.NewBufferString(sample2), opts)
	if err != nil {
		t.Errorf("NewParser()  = %v, want nil error.", err)
		return
	}
	info, err := parser.Parse()
	if err != nil {
		t.Errorf("Parse()  = %v, want nil error.", err)
		return
	}
	json, err := info.JSON()
	if err != nil {
		t.Errorf("Parse()  = %v, want nil error.", err)
		return
	}
	buf := new(bytes.Buffer)
	io.Copy(buf, json)
	str := buf.String()
	if str != result2 {
		t.Errorf("Parse()  = \"%v\", want \"%v\".", str, result2)
	}
}

func TestParseClearSignText(t *testing.T) {
	opts := options.New(
		options.Set(options.ArmorOpt, true),
		options.Set(options.DebugOpt, true),
		options.Set(options.UTCOpt, true),
	)
	parser, err := NewParser(bytes.NewBufferString(sample3), opts)
	if err != nil {
		t.Errorf("NewParser()  = %v, want nil error.", err)
		return
	}
	info, err := parser.Parse()
	if err != nil {
		t.Errorf("Parse()  = %v, want nil error.", err)
		return
	}
	json, err := info.JSON()
	if err != nil {
		t.Errorf("Parse()  = %v, want nil error.", err)
		return
	}
	buf := new(bytes.Buffer)
	io.Copy(buf, json)
	str := buf.String()
	if str != result3 {
		t.Errorf("Parse()  = \"%v\", want \"%v\".", str, result3)
	}
}

func TestParseBindata(t *testing.T) {
	opts := options.New(
		options.Set(options.UTCOpt, true),
	)
	parser, err := NewParser(bytes.NewBuffer(sample4), opts)
	if err != nil {
		t.Errorf("NewParser()  = %v, want nil error.", err)
		return
	}
	info, err := parser.Parse()
	if err != nil {
		t.Errorf("Parse()  = %v, want nil error.", err)
		return
	}
	json, err := info.JSON()
	if err != nil {
		t.Errorf("Parse()  = %v, want nil error.", err)
		return
	}
	buf := new(bytes.Buffer)
	io.Copy(buf, json)
	str := buf.String()
	if str != result4 {
		t.Errorf("Parse()  = \"%v\", want \"%v\".", str, result4)
	}
}

func TestNilParser(t *testing.T) {
	parser := (*Parser)(nil)
	info, err := parser.Parse()
	if err != nil {
		t.Errorf("Parse()  = %v, want nil error.", err)
		return
	}
	if info.String() != "" {
		t.Errorf("Parse()  = \"%v\", want \"\".", info)
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
