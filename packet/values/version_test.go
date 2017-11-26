package values

import "testing"

func TestVersionNew(t *testing.T) {
	v := NewVersion(4, 4)
	if v.IsUnknown() {
		t.Errorf("Version.IsUnknown = %v, want false.", v.IsUnknown())
	}
	if v.Number() != 4 {
		t.Errorf("Version.Number = %v, want 4.", v.Number())
	}

	i := v.ToItem(true)
	if i.Name != "Version" {
		t.Errorf("Version.Name = \"%v\", want \"Version\".", i.Name)
	}
	if i.Value != "4" {
		t.Errorf("Version.Value = \"%v\", want \"4\".", i.Value)
	}
	if i.Note != "current" {
		t.Errorf("Version.Note = \"%v\", want \"current\"", i.Note)
	}
	if i.Dump != "04" {
		t.Errorf("Version.Dump = \"%v\", want \"04\".", i.Dump)
	}
}

func TestVersionOldNew(t *testing.T) {
	v := (*Version)(nil)
	if v.IsCurrent() {
		t.Errorf("Current Version = %v, want false.", v.IsCurrent())
	}
	if v.IsOld() {
		t.Errorf("Old Version = %v, want false.", v.IsOld())
	}
	if v.Number() != 0 {
		t.Errorf("Version.Number = %v, want 0.", v.Number())
	}
}

func TestVersionOld(t *testing.T) {
	v := NewVersion(3, 4)
	if v.IsUnknown() {
		t.Errorf("Version.IsUnknown = %v, want false.", v.IsUnknown())
	}

	i := v.ToItem(true)
	if i.Name != "Version" {
		t.Errorf("Version.Name = \"%v\", want \"Version\".", i.Name)
	}
	if i.Value != "3" {
		t.Errorf("Version.Value = \"%v\", want \"3\".", i.Value)
	}
	if i.Note != "old" {
		t.Errorf("Version.Note = \"%v\", want \"old\"", i.Note)
	}
	if i.Dump != "03" {
		t.Errorf("Version.Dump = \"%v\", want \"03\".", i.Dump)
	}
}

func TestVersionOldNil(t *testing.T) {
	v := (*Version)(nil)
	if v.IsOld() {
		t.Errorf("Old Version = %v, want false.", v.IsOld())
	}
}

func TestVersionToItemNil(t *testing.T) {
	v := (*Version)(nil)
	if v.ToItem(true) != nil {
		t.Error("Version to Item: not nil, want nil.")
	}
}

func TestVersionUnknown(t *testing.T) {
	v := NewVersion(5, 4)
	if !v.IsUnknown() {
		t.Errorf("Version.IsUnknown = %v, want true.", v.IsUnknown())
	}

	i := v.ToItem(true)
	if i.Name != "Version" {
		t.Errorf("Version.Name = \"%v\", want \"Version\".", i.Name)
	}
	if i.Value != "5" {
		t.Errorf("Version.Value = \"%v\", want \"5\".", i.Value)
	}
	if i.Note != "unknown" {
		t.Errorf("Version.Note = \"%v\", want \"unknown\"", i.Note)
	}
	if i.Dump != "05" {
		t.Errorf("Version.Dump = \"%v\", want \"05\".", i.Dump)
	}
}

func TestPubVer4(t *testing.T) {
	i := PubVer(4).ToItem(true)

	if i.Note != "current" {
		t.Errorf("Version.Note = \"%v\", want \"current\"", i.Note)
	}
}

func TestSigVer4(t *testing.T) {
	i := SigVer(4).ToItem(true)

	if i.Note != "current" {
		t.Errorf("Version.Note = \"%v\", want \"current\"", i.Note)
	}
}

func TestOneSigVer3(t *testing.T) {
	i := OneSigVer(3).ToItem(true)

	if i.Note != "current" {
		t.Errorf("Version.Note = \"%v\", want \"current\"", i.Note)
	}
}

func TestPubSessKeyVer3(t *testing.T) {
	i := PubSessKeyVer(3).ToItem(true)

	if i.Note != "current" {
		t.Errorf("Version.Note = \"%v\", want \"current\"", i.Note)
	}
}

func TestSymSessKeyVer4(t *testing.T) {
	i := SymSessKeyVer(4).ToItem(true)

	if i.Note != "current" {
		t.Errorf("Version.Note = \"%v\", want \"current\"", i.Note)
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
