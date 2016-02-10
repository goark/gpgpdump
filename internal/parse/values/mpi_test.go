package values

import (
	"bytes"
	"io"
	"testing"
)

func TestGetMPI(t *testing.T) {
	var data = []byte{0x00, 0x9f, 0x6f, 0x0b, 0x0c, 0x39, 0x68, 0x64, 0xf2, 0xff, 0xea, 0x63, 0x80, 0xc6, 0x6c, 0x69, 0xaa, 0x3d, 0x4e, 0x3c, 0x46, 0x54}
	reader := bytes.NewReader(data)
	dump := "6f 0b 0c 39 68 64 f2 ff ea 63 80 c6 6c 69 aa 3d 4e 3c 46 54"
	m, err := GetMPI(reader, "", true)
	if err != nil {
		t.Errorf("MPI = \"%v\", want nil.", err)
	}
	i := m.Get()
	if i.Name != "Multi-precision integer" {
		t.Errorf("MPI.Name = \"%v\", want \"Multi-precision integer\".", i.Name)
	}
	if i.Value != "" {
		t.Errorf("MPI.Value = \"%v\", want \"\".", i.Value)
	}
	if i.Note != "159 bits" {
		t.Errorf("MPI.Note = \"%v\", want \"159 bits\"", i.Note)
	}
	if i.Dump != dump {
		t.Errorf("MPI.Dump = \"%v\", want \"%s\".", i.Dump, dump)
	}
}
func TestGetMPIAddNote(t *testing.T) {
	var data = []byte{0x00, 0x9f, 0x6f, 0x0b, 0x0c, 0x39, 0x68, 0x64, 0xf2, 0xff, 0xea, 0x63, 0x80, 0xc6, 0x6c, 0x69, 0xaa, 0x3d, 0x4e, 0x3c, 0x46, 0x54}
	reader := bytes.NewReader(data)
	dump := "6f 0b 0c 39 68 64 f2 ff ea 63 80 c6 6c 69 aa 3d 4e 3c 46 54"
	m, err := GetMPI(reader, "note1", true)
	if err != nil {
		t.Errorf("MPI = \"%v\", want nil.", err)
	}
	i := m.Get()
	if i.Name != "Multi-precision integer" {
		t.Errorf("MPI.Name = \"%v\", want \"Multi-precision integer\".", i.Name)
	}
	if i.Value != "" {
		t.Errorf("MPI.Value = \"%v\", want \"\".", i.Value)
	}
	if i.Note != "note1 (159 bits)" {
		t.Errorf("MPI.Note = \"%v\", want \"note1 (159 bits)\"", i.Note)
	}
	if i.Dump != dump {
		t.Errorf("MPI.Dump = \"%v\", want \"%s\".", i.Dump, dump)
	}
}

func TestGetMPIErr(t *testing.T) {
	var data = []byte{0x00, 0x9f, 0x6f, 0x0b, 0x0c, 0x39, 0x68, 0x64, 0xf2, 0xff, 0xea, 0x63, 0x80, 0xc6, 0x6c, 0x69, 0xaa, 0x3d, 0x4e, 0x3c, 0x46}
	reader := bytes.NewReader(data)
	if _, err := GetMPI(reader, "note1", true); err != io.ErrUnexpectedEOF {
		t.Errorf("MPI = \"%v\", want \"%v\".", err, io.ErrUnexpectedEOF)
	}
}
