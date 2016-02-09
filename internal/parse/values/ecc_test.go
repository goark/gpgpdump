package values

import (
	"bytes"
	"testing"
)

func TestEccNITSP256(t *testing.T) {
	var data = []byte{0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
	reader := bytes.NewReader(data)
	oid, err := OID(reader)
	if err != nil {
		t.Errorf("OID = \"%v\", want nil.", err.Error())
	}
	i := oid.Get()
	dump := "2a 86 48 ce 3d 03 01 07"
	if i.Name != "ECC OID" {
		t.Errorf("RawData.Name = \"%v\", want \"ECC OID\".", i.Name)
	}
	if i.Value != "" {
		t.Errorf("RawData.Value = \"%v\", want \"\".", i.Value)
	}
	if i.Note != "NIST curve P-256" {
		t.Errorf("RawData.Note = \"%v\", want \"NIST curve P-256\"", i.Note)
	}
	if i.Dump != dump {
		t.Errorf("RawData.Dump = \"%v\", want \"%s\".", i.Dump, dump)
	}
}

func TestEccNITSP384(t *testing.T) {
	var data = []byte{0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}
	reader := bytes.NewReader(data)
	oid, err := OID(reader)
	if err != nil {
		t.Errorf("OID = \"%v\", want nil.", err.Error())
	}
	i := oid.Get()
	dump := "2b 81 04 00 22"
	if i.Name != "ECC OID" {
		t.Errorf("RawData.Name = \"%v\", want \"ECC OID\".", i.Name)
	}
	if i.Value != "" {
		t.Errorf("RawData.Value = \"%v\", want \"\".", i.Value)
	}
	if i.Note != "NIST curve P-384" {
		t.Errorf("RawData.Note = \"%v\", want \"NIST curve P-384\"", i.Note)
	}
	if i.Dump != dump {
		t.Errorf("RawData.Dump = \"%v\", want \"%s\".", i.Dump, dump)
	}
}

func TestEccNITSP512(t *testing.T) {
	var data = []byte{0x05, 0x2b, 0x81, 0x04, 0x00, 0x23}
	reader := bytes.NewReader(data)
	oid, err := OID(reader)
	if err != nil {
		t.Errorf("OID = \"%v\", want nil.", err.Error())
	}
	i := oid.Get()
	dump := "2b 81 04 00 23"
	if i.Name != "ECC OID" {
		t.Errorf("RawData.Name = \"%v\", want \"ECC OID\".", i.Name)
	}
	if i.Value != "" {
		t.Errorf("RawData.Value = \"%v\", want \"\".", i.Value)
	}
	if i.Note != "NIST curve P-521" {
		t.Errorf("RawData.Note = \"%v\", want \"NIST curve P-521\"", i.Note)
	}
	if i.Dump != dump {
		t.Errorf("RawData.Dump = \"%v\", want \"%s\".", i.Dump, dump)
	}
}

func TestEccUnknown(t *testing.T) {
	var data = []byte{0x05, 0x01, 0x02, 0x03, 0x04, 0x05}
	reader := bytes.NewReader(data)
	oid, err := OID(reader)
	if err != nil {
		t.Errorf("OID = \"%v\", want nil.", err.Error())
	}
	i := oid.Get()
	dump := "01 02 03 04 05"
	if i.Name != "ECC OID" {
		t.Errorf("RawData.Name = \"%v\", want \"ECC OID\".", i.Name)
	}
	if i.Value != "" {
		t.Errorf("RawData.Value = \"%v\", want \"\".", i.Value)
	}
	if i.Note != "Unknown" {
		t.Errorf("RawData.Note = \"%v\", want \"Unknown\"", i.Note)
	}
	if i.Dump != dump {
		t.Errorf("RawData.Dump = \"%v\", want \"%s\".", i.Dump, dump)
	}
}

func TestEccError(t *testing.T) {
	var data = []byte{0x05, 0x01, 0x02, 0x03, 0x04}
	reader := bytes.NewReader(data)
	if _, err := OID(reader); err == nil {
		t.Error("OID = nil, want \"unexpected EOF\".")
	}
}
