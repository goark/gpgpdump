package values

import "testing"

var names = Msgs{
	1: "Name1",
}

func TestMsgsGetNormal(t *testing.T) {
	res := names.Get(1, "Unknown")
	if res != "Name1" {
		t.Errorf("Msgs.Get() = \"%v\", want \"Name1\".", res)

	}
}

func TestMsgsGetNG(t *testing.T) {
	res := names.Get(0, "Unknown")
	if res != "Unknown" {
		t.Errorf("Msgs.Get() = \"%v\", want \"Unknown\".", res)

	}
}

func TestKeyID(t *testing.T) {
	key := KeyID(0x1234567890123456)
	i := key.Get()

	if i.Name != "Key ID" {
		t.Errorf("KeyID.Name = \"%v\", want \"Key ID\".", i.Name)
	}
	if i.Value != "0x1234567890123456" {
		t.Errorf("KeyID.Value = \"%v\", want \"0x1234567890123456\".", i.Value)
	}
	if i.Note != "" {
		t.Errorf("KeyID.Note = \"%v\", want \"\".", i.Note)
	}
	if i.Dump != "" {
		t.Errorf("KeyID.Dump = \"%v\", want \"\".", i.Dump)
	}
}
