package packet

import (
	"bytes"
	"io"
	"testing"

	"github.com/spiegel-im-spiegel/gpgpdump/options"
)

const (
	sample1 = `
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v2

iF4EARMIAAYFAlTDCN8ACgkQMfv9qV+7+hg2HwEA6h2iFFuCBv3VrsSf2BREQaT1
T1ZprZqwRPOjiLJg9AwA/ArTwCPz7c2vmxlv7sRlRLUI6CdsOqhuO1KfYXrq7idI
=ZOTN
-----END PGP SIGNATURE-----
`
)

const (
	result1 = "{}\n"
	result2 = `{
  "Packet": [
    {
      "name": "Packet",
      "value": "Signature Packet (tag 2)",
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
          "name": "Multi-precision integer",
          "note": "ECDSA r (256 bits)"
        },
        {
          "name": "Multi-precision integer",
          "note": "ECDSA s (252 bits)"
        }
      ]
    }
  ]
}
`
)

func TestParseNilOption(t *testing.T) {
	_, err := NewParser(bytes.NewBufferString(sample1), nil)
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
	}
}

func TestParse(t *testing.T) {
	opts := options.New(
		options.Set(options.ArmorOpt, true),
		options.Set(options.DebugOpt, true),
		options.Set(options.UTCOpt, true),
	)
	parser, err := NewParser(bytes.NewBufferString(sample1), opts)
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
