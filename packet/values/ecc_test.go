package values

import (
	"io"
	"testing"

	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
)

func TestEccOID(t *testing.T) {
	testCases := []struct {
		data  []byte
		value string
		dump  string
	}{
		{
			data:  []byte{0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07},
			value: "nistp256 (256bits key size)",
			dump:  "2a 86 48 ce 3d 03 01 07",
		},
		{
			data:  []byte{0x05, 0x2b, 0x81, 0x04, 0x00, 0x22},
			value: "nistp384 (384bits key size)",
			dump:  "2b 81 04 00 22",
		},
		{
			data:  []byte{0x05, 0x2b, 0x81, 0x04, 0x00, 0x23},
			value: "nistp521 (521bits key size)",
			dump:  "2b 81 04 00 23",
		},
		{
			data:  []byte{0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a},
			value: "secp256k1 (256bits key size)",
			dump:  "2b 81 04 00 0a",
		},
		{
			data:  []byte{0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07},
			value: "brainpoolP256r1 (256bits key size)",
			dump:  "2b 24 03 03 02 08 01 01 07",
		},
		{
			data:  []byte{0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B},
			value: "brainpoolP384r1 (384bits key size)",
			dump:  "2b 24 03 03 02 08 01 01 0b",
		},
		{
			data:  []byte{0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D},
			value: "brainpoolP512r1 (512bits key size)",
			dump:  "2b 24 03 03 02 08 01 01 0d",
		},
		{
			data:  []byte{0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01},
			value: "ed25519 (256bits key size)",
			dump:  "2b 06 01 04 01 da 47 0f 01",
		},
		{
			data:  []byte{0x0a, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01},
			value: "cv25519 (256bits key size)",
			dump:  "2b 06 01 04 01 97 55 01 05 01",
		},
	}

	for _, tc := range testCases {
		reader := reader.New(tc.data)
		oid, err := NewOID(reader)
		if err != nil {
			t.Errorf("OID = \"%+v\", want nil.", err)
		}
		i := oid.ToItem(true)
		if i.Name != "ECC Curve OID" {
			t.Errorf("OID.Name = \"%v\", want \"ECC Curve OID\".", i.Name)
		}
		if i.Value != tc.value {
			t.Errorf("OID.Value = \"%v\", want \"%s\"", i.Value, tc.value)
		}
		if i.Note != "" {
			t.Errorf("OID.Note = \"%v\", want \"\".", i.Note)
		}
		if i.Dump != tc.dump {
			t.Errorf("OIS.Dump = \"%v\", want \"%s\".", i.Dump, tc.dump)
		}
	}
}

func TestEccUnknown(t *testing.T) {
	data := []byte{0x05, 0x01, 0x02, 0x03, 0x04, 0x05}
	dump := "01 02 03 04 05"
	note := "Unknown"
	reader := reader.New(data)
	oid, err := NewOID(reader)
	if err != nil {
		t.Errorf("OID = \"%+v\", want nil.", err)
	}
	i := oid.ToItem(true)
	if i.Name != "ECC Curve OID" {
		t.Errorf("OID.Name = \"%v\", want \"ECC Curve OID\".", i.Name)
	}
	if i.Value != note {
		t.Errorf("OID.Note = \"%v\", want \"%s\"", i.Value, note)
	}
	if i.Note != "" {
		t.Errorf("OID.Note = \"%v\", want \"\".", i.Note)
	}
	if i.Dump != dump {
		t.Errorf("OIS.Dump = \"%v\", want \"%s\".", i.Dump, dump)
	}
}

func TestEccZero(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	reader := reader.New(data)
	oid, err := NewOID(reader)
	if err != nil {
		t.Errorf("OID = \"%+v\", want nil.", err)
	}
	if len(oid) > 0 {
		t.Errorf("OID length = %d, want 0.", len(oid))
	}
}

func TestEccErrorLen(t *testing.T) {
	data := []byte{}
	reader := reader.New(data)
	if _, err := NewOID(reader); err != nil {
		if !errs.Is(err, io.EOF) {
			t.Errorf("OID = \"%+v\", want \"%+v\".", err, io.EOF)
		}
	}
}

func TestEccError(t *testing.T) {
	data := []byte{0x05, 0x01, 0x02, 0x03, 0x04}
	reader := reader.New(data)
	if _, err := NewOID(reader); !errs.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("OID = \"%+v\", want \"%+v\".", err, io.ErrUnexpectedEOF)
	}
}

/* Copyright 2016-2019 Spiegel
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
