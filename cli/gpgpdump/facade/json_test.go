package facade

import (
	"bytes"
	"testing"

	"github.com/spiegel-im-spiegel/gocli/exitcode"
	"github.com/spiegel-im-spiegel/gocli/rwi"
)

var resJSON = `{
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
          "note": "current"
        },
        {
          "name": "Symmetric Algorithm",
          "value": "CAST5 (128 bit key, as per) (sym 3)"
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
          "value": "sym alg is specified in sym-key encrypted session key",
          "note": "56 bytes"
        }
      ]
    }
  ]
}
`

func TestJsonOn(t *testing.T) {
	inData := bytes.NewReader(bindata1)
	outBuf := new(bytes.Buffer)
	outErrBuf := new(bytes.Buffer)
	ui := rwi.New(rwi.WithReader(inData), rwi.WithWriter(outBuf), rwi.WithErrorWriter(outErrBuf))
	args := []string{"-j", "--indent", "2"}

	exit := Execute(ui, args)
	if exit != exitcode.Normal {
		t.Errorf("Execute(json) = \"%v\", want \"%v\".", exit, exitcode.Normal)
	}
	str := outErrBuf.String()
	if str != "" {
		t.Errorf("Execute(json) = \"%v\", want \"%v\".", str, "")
	}
	str = outBuf.String()
	if str != resJSON {
		t.Errorf("Execute(json) = \"%v\", want \"%v\".", str, resJSON)
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
