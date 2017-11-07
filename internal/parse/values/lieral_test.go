package values

import "testing"

func TestLiteralFormat(t *testing.T) {
	for tag := byte(0x20); tag <= byte(0xfe); tag++ {
		i := LiteralFormat(tag).Get()
		if i.Name != "Literal data format" {
			t.Errorf("LiteralFormat.Name = \"%s\", want \"Literal data format\".", i.Name)
		}
		if i.Value != string(tag) {
			t.Errorf("LiteralFormat.Value = \"%s\", want \"%s\".", i.Value, string(tag))
		}
		var note string
		switch tag {
		case 0x62: //'b'
			note = "binary"
		case 0x74: //'t'
			note = "text"
		case 0x75: //'u'
			note = "UTF-8 text"
		case 0x31: //'l' -- RFC 1991 incorrectly stated this local mode flag as '1' (ASCII numeral one). Both of these local modes are deprecated.
			note = "local"
		case 0x6c: //'l'
			note = "local"
		default:
			note = "unknown"
		}
		if i.Note != note {
			t.Errorf("LiteralFormat.Note = \"%s\", want \"%s\"", i.Note, note)
		}
		if i.Dump != "" {
			t.Errorf("LiteralFormat.Dump = \"%s\", want \"\".", i.Dump)
		}
	}
}

func TestLiteralFname(t *testing.T) {
	i := LiteralFname("hoge").Get()
	if i.Name != "File name" {
		t.Errorf("LiteralFname.Name = \"%s\", want \"File name\".", i.Name)
	}
	if i.Value != "hoge" {
		t.Errorf("LiteralFname.Value = \"%s\", want \"hoge\".", i.Value)
	}
	if i.Note != "" {
		t.Errorf("LiteralFname.Note = \"%s\", want \"\"", i.Note)
	}
	if i.Dump != "" {
		t.Errorf("LiteralFname.Dump = \"%s\", want \"\".", i.Dump)
	}
}

func TestLiteralData(t *testing.T) {
	var data = []byte{0x01, 0x02, 0x03, 0x04}
	dump := "01 02 03 04"
	i := LiteralData(data, true).Get()
	if i.Name != "Literal data" {
		t.Errorf("LiteralData.Name = \"%v\", want \"Literal data\".", i.Name)
	}
	if i.Value != "" {
		t.Errorf("LiteralData.Value = \"%v\", want \"\".", i.Value)
	}
	if i.Note != "4 bytes" {
		t.Errorf("LiteralData.Note = \"%v\", want \"4 bytes\"", i.Note)
	}
	if i.Dump != dump {
		t.Errorf("LiteralData.Dump = \"%v\", want \"%s\".", i.Dump, dump)
	}
}
