package values

import "testing"

func TestNewRawData(t *testing.T) {
	var data = []byte{0x01, 0x02, 0x03, 0x04}
	dump := "01 02 03 04"
	i := NewRawData("name1", "note1", data, true).Get()
	if i.Name != "name1" {
		t.Errorf("RawData.Name = \"%v\", want \"name1\".", i.Name)
	}
	if i.Value != "" {
		t.Errorf("RawData.Value = \"%v\", want \"\".", i.Value)
	}
	if i.Note != "note1" {
		t.Errorf("RawData.Note = \"%v\", want \"note1\"", i.Note)
	}
	if i.Dump != dump {
		t.Errorf("RawData.Dump = \"%v\", want \"%s\".", i.Dump, dump)
	}
}

func TestNewRawDataMask(t *testing.T) {
	var data = []byte{0x01, 0x02, 0x03, 0x04}
	dump := "..."
	i := NewRawData("name1", "note1", data, false).Get()
	if i.Name != "name1" {
		t.Errorf("RawData.Name = \"%v\", want \"name1\".", i.Name)
	}
	if i.Value != "" {
		t.Errorf("RawData.Value = \"%v\", want \"\".", i.Value)
	}
	if i.Note != "note1" {
		t.Errorf("RawData.Note = \"%v\", want \"note1\"", i.Note)
	}
	if i.Dump != dump {
		t.Errorf("RawData.Dump = \"%v\", want \"%s\".", i.Dump, dump)
	}
}
