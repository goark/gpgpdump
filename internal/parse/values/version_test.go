package values

import "testing"

func TestVersionNew(t *testing.T) {
	v := NewVersion(4, 4)
	if v.IsUnknown() {
		t.Errorf("Version.IsUnknown = %v, want false.", v.IsUnknown())
	}

	i := v.Get()
	if i.Name != "Version" {
		t.Errorf("Version.Name = \"%v\", want \"Version\".", i.Name)
	}
	if i.Value != "4" {
		t.Errorf("Version.Value = \"%v\", want \"4\".", i.Value)
	}
	if i.Note != "new" {
		t.Errorf("Version.Note = \"%v\", want \"new\"", i.Note)
	}
	if i.Dump != "" {
		t.Errorf("Version.Dump = \"%v\", want \"\".", i.Dump)
	}
}

func TestVersionOld(t *testing.T) {
	v := NewVersion(3, 4)
	if v.IsUnknown() {
		t.Errorf("Version.IsUnknown = %v, want false.", v.IsUnknown())
	}

	i := v.Get()
	if i.Name != "Version" {
		t.Errorf("Version.Name = \"%v\", want \"Version\".", i.Name)
	}
	if i.Value != "3" {
		t.Errorf("Version.Value = \"%v\", want \"3\".", i.Value)
	}
	if i.Note != "old" {
		t.Errorf("Version.Note = \"%v\", want \"old\"", i.Note)
	}
	if i.Dump != "" {
		t.Errorf("Version.Dump = \"%v\", want \"\".", i.Dump)
	}
}

func TestVersionUnknown(t *testing.T) {
	v := NewVersion(5, 4)
	if !v.IsUnknown() {
		t.Errorf("Version.IsUnknown = %v, want true.", v.IsUnknown())
	}

	i := v.Get()
	if i.Name != "Version" {
		t.Errorf("Version.Name = \"%v\", want \"Version\".", i.Name)
	}
	if i.Value != "5" {
		t.Errorf("Version.Value = \"%v\", want \"5\".", i.Value)
	}
	if i.Note != "unknown" {
		t.Errorf("Version.Note = \"%v\", want \"unknown\"", i.Note)
	}
	if i.Dump != "" {
		t.Errorf("Version.Dump = \"%v\", want \"\".", i.Dump)
	}
}

func TestPubVer4(t *testing.T) {
	i := PubVer(4).Get()

	if i.Note != "new" {
		t.Errorf("Version.Note = \"%v\", want \"new\"", i.Note)
	}
}

func TestSigVer4(t *testing.T) {
	i := SigVer(4).Get()

	if i.Note != "new" {
		t.Errorf("Version.Note = \"%v\", want \"new\"", i.Note)
	}
}

func TestOneSigVer3(t *testing.T) {
	i := OneSigVer(3).Get()

	if i.Note != "new" {
		t.Errorf("Version.Note = \"%v\", want \"new\"", i.Note)
	}
}

func TestPubSessKeyVer3(t *testing.T) {
	i := PubSessKeyVer(3).Get()

	if i.Note != "new" {
		t.Errorf("Version.Note = \"%v\", want \"new\"", i.Note)
	}
}

func TestSymSessKeyVer4(t *testing.T) {
	i := SymSessKeyVer(4).Get()

	if i.Note != "new" {
		t.Errorf("Version.Note = \"%v\", want \"new\"", i.Note)
	}
}
