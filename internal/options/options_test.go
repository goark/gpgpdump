package options

import "testing"

func TestResetSymAlgMode(t *testing.T) {
	opt := &Options{}

	opt.ResetSymAlgMode()
	if opt.Mode.IsPubEnc() {
		t.Errorf("Options.Mode = %v, want \"Not Specified\".", opt.GetSymAlgMode())

	}
	if opt.Mode.IsSymEnc() {
		t.Errorf("Options.Mode = %v, want \"Not Specified\".", opt.GetSymAlgMode())

	}
}

func TestSetSymAlgModeSymEnc(t *testing.T) {
	opt := &Options{}

	opt.SetSymAlgModeSymEnc()
	if opt.Mode.IsPubEnc() {
		t.Errorf("Options.Mode = %v, want \"Sym. Encryption Mode\".", opt.GetSymAlgMode())

	} else if !opt.Mode.IsSymEnc() {
		t.Errorf("Options.Mode = %v, want \"Sym. Encryption Mode\".", opt.GetSymAlgMode())

	}
}

func TestSSetSymAlgModePubEnc(t *testing.T) {
	opt := &Options{}

	opt.SetSymAlgModePubEnc()
	if opt.Mode.IsSymEnc() {
		t.Errorf("Options.Mode = %v, want \"Pubkey Encryption Mode\".", opt.GetSymAlgMode())

	} else if !opt.Mode.IsPubEnc() {
		t.Errorf("Options.Mode = %v, want \"Pubkey Encryption Mode\".", opt.GetSymAlgMode())

	}
}
