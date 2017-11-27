package values

import (
	"io"
	"testing"

	"github.com/pkg/errors"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
)

func TestEccNITSP256(t *testing.T) {
	data := []byte{0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
	dump := "2a 86 48 ce 3d 03 01 07"
	note := "NIST P-256"
	reader := reader.New(data)
	oid, err := NewOID(reader)
	if err != nil {
		t.Errorf("OID = \"%v\", want nil.", err.Error())
	}
	i := oid.ToItem(true)
	if i.Name != "ECC OID" {
		t.Errorf("OID.Name = \"%v\", want \"ECC OID\".", i.Name)
	}
	if i.Value != "" {
		t.Errorf("OID.Value = \"%v\", want \"\".", i.Value)
	}
	if i.Note != note {
		t.Errorf("OID.Note = \"%v\", want \"%s\"", i.Note, note)
	}
	if i.Dump != dump {
		t.Errorf("OIS.Dump = \"%v\", want \"%s\".", i.Dump, dump)
	}
}

func TestEccNITSP384(t *testing.T) {
	data := []byte{0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}
	dump := "2b 81 04 00 22"
	note := "NIST P-384"
	reader := reader.New(data)
	oid, err := NewOID(reader)
	if err != nil {
		t.Errorf("OID = \"%v\", want nil.", err.Error())
	}
	i := oid.ToItem(true)
	if i.Name != "ECC OID" {
		t.Errorf("OID.Name = \"%v\", want \"ECC OID\".", i.Name)
	}
	if i.Value != "" {
		t.Errorf("OID.Value = \"%v\", want \"\".", i.Value)
	}
	if i.Note != note {
		t.Errorf("OID.Note = \"%v\", want \"%s\"", i.Note, note)
	}
	if i.Dump != dump {
		t.Errorf("OIS.Dump = \"%v\", want \"%s\".", i.Dump, dump)
	}
}

func TestEccNITSP521(t *testing.T) {
	data := []byte{0x05, 0x2b, 0x81, 0x04, 0x00, 0x23}
	dump := "2b 81 04 00 23"
	note := "NIST P-521"
	reader := reader.New(data)
	oid, err := NewOID(reader)
	if err != nil {
		t.Errorf("OID = \"%v\", want nil.", err.Error())
	}
	i := oid.ToItem(true)
	if i.Name != "ECC OID" {
		t.Errorf("OID.Name = \"%v\", want \"ECC OID\".", i.Name)
	}
	if i.Value != "" {
		t.Errorf("OID.Value = \"%v\", want \"\".", i.Value)
	}
	if i.Note != note {
		t.Errorf("OID.Note = \"%v\", want \"%s\"", i.Note, note)
	}
	if i.Dump != dump {
		t.Errorf("OIS.Dump = \"%v\", want \"%s\".", i.Dump, dump)
	}
}

func TestEccUnknown(t *testing.T) {
	data := []byte{0x05, 0x01, 0x02, 0x03, 0x04, 0x05}
	dump := "01 02 03 04 05"
	note := "Unknown"
	reader := reader.New(data)
	oid, err := NewOID(reader)
	if err != nil {
		t.Errorf("OID = \"%v\", want nil.", err.Error())
	}
	i := oid.ToItem(true)
	if i.Name != "ECC OID" {
		t.Errorf("OID.Name = \"%v\", want \"ECC OID\".", i.Name)
	}
	if i.Value != "" {
		t.Errorf("OID.Value = \"%v\", want \"\".", i.Value)
	}
	if i.Note != note {
		t.Errorf("OID.Note = \"%v\", want \"%s\"", i.Note, note)
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
		t.Errorf("OID = \"%v\", want nil.", err)
	}
	if len(oid) > 0 {
		t.Errorf("OID length = %d, want 0.", len(oid))
	}
}

func TestEccErrorLen(t *testing.T) {
	data := []byte{}
	reader := reader.New(data)
	if _, err := NewOID(reader); err != nil {
		if errors.Cause(err) != io.EOF {
			t.Errorf("OID = \"%v\", want \"%v\".", err, io.EOF)
		}
	}
}

func TestEccError(t *testing.T) {
	data := []byte{0x05, 0x01, 0x02, 0x03, 0x04}
	reader := reader.New(data)
	if _, err := NewOID(reader); err != nil {
		if errors.Cause(err) != io.ErrUnexpectedEOF {
			t.Errorf("OID = \"%v\", want \"%v\".", err, io.ErrUnexpectedEOF)
		}
	} else {
		t.Errorf("NewMPI = nil error, want \"%v\".", io.ErrUnexpectedEOF)
	}
}

/* Copyright 2016 Spiegel
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
