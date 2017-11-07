package errs

import "testing"

func TestError(t *testing.T) {
	e := ErrPacketInvalidData("test")
	value := "invalid data: test"
	if e.Error() != value {
		t.Errorf("facade.error = %v, want \"%s\".", e, value)
	}
	i := e.Get()
	if i.Name != "Error" {
		t.Errorf("Version.Name = \"%v\", want \"Version\".", i.Name)
	}
	if i.Value != value {
		t.Errorf("Version.Value = \"%v\", want \"%s\".", i.Value, value)
	}
	if i.Note != "" {
		t.Errorf("Version.Note = \"%v\", want \"\"", i.Note)
	}
	if i.Dump != "" {
		t.Errorf("Version.Dump = \"%v\", want \"\".", i.Dump)
	}
}
