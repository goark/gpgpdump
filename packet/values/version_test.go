package values

import "testing"

func TestVersionNew(t *testing.T) {
	v := NewVersion(4, 4, 5)
	if !v.IsCurrent() {
		t.Errorf("Version.IsCurrent = %v, want true.", v.IsCurrent())
	}
	if v.IsOld() {
		t.Errorf("Version.IsOld = %v, want false.", v.IsOld())
	}
	if v.IsDraft() {
		t.Errorf("Version.IsUnknown = %v, want false.", v.IsDraft())
	}
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

func TestVersionOld(t *testing.T) {
	v := NewVersion(3, 4, 5)
	if v.IsCurrent() {
		t.Errorf("Version.IsCurrent = %v, want false.", v.IsCurrent())
	}
	if !v.IsOld() {
		t.Errorf("Version.IsOld = %v, want true.", v.IsOld())
	}
	if v.IsDraft() {
		t.Errorf("Version.IsUnknown = %v, want false.", v.IsDraft())
	}
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

func TestVersionDraft(t *testing.T) {
	v := NewVersion(5, 4, 5)
	if v.IsCurrent() {
		t.Errorf("Version.IsCurrent = %v, want false.", v.IsCurrent())
	}
	if v.IsOld() {
		t.Errorf("Version.IsOld = %v, want false.", v.IsOld())
	}
	if !v.IsDraft() {
		t.Errorf("Version.IsUnknown = %v, want true.", v.IsDraft())
	}
	if v.IsUnknown() {
		t.Errorf("Version.IsUnknown = %v, want false.", v.IsUnknown())
	}

	i := v.ToItem(true)
	if i.Name != "Version" {
		t.Errorf("Version.Name = \"%v\", want \"Version\".", i.Name)
	}
	if i.Value != "5" {
		t.Errorf("Version.Value = \"%v\", want \"5\".", i.Value)
	}
	if i.Note != "draft" {
		t.Errorf("Version.Note = \"%v\", want \"draft\"", i.Note)
	}
	if i.Dump != "05" {
		t.Errorf("Version.Dump = \"%v\", want \"05\".", i.Dump)
	}
}

func TestVersionNoDraft(t *testing.T) {
	v := NewVersion(5, 4, 0)
	if v.IsCurrent() {
		t.Errorf("Version.IsCurrent = %v, want false.", v.IsCurrent())
	}
	if v.IsOld() {
		t.Errorf("Version.IsOld = %v, want false.", v.IsOld())
	}
	if v.IsDraft() {
		t.Errorf("Version.IsUnknown = %v, want false.", v.IsDraft())
	}
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

func TestVersionUnknown(t *testing.T) {
	v := NewVersion(6, 4, 5)
	if v.IsCurrent() {
		t.Errorf("Version.IsCurrent = %v, want false.", v.IsCurrent())
	}
	if v.IsOld() {
		t.Errorf("Version.IsOld = %v, want false.", v.IsOld())
	}
	if v.IsDraft() {
		t.Errorf("Version.IsDraft = %v, want false.", v.IsDraft())
	}
	if !v.IsUnknown() {
		t.Errorf("Version.IsUnknown = %v, want true.", v.IsUnknown())
	}

	i := v.ToItem(true)
	if i.Name != "Version" {
		t.Errorf("Version.Name = \"%v\", want \"Version\".", i.Name)
	}
	if i.Value != "6" {
		t.Errorf("Version.Value = \"%v\", want \"6\".", i.Value)
	}
	if i.Note != "unknown" {
		t.Errorf("Version.Note = \"%v\", want \"unknown\"", i.Note)
	}
	if i.Dump != "06" {
		t.Errorf("Version.Dump = \"%v\", want \"06\".", i.Dump)
	}
}

func TestVersionNil(t *testing.T) {
	v := (*Version)(nil)
	if v.IsCurrent() {
		t.Errorf("Version.IsCurrent = %v, want false.", v.IsCurrent())
	}
	if v.IsOld() {
		t.Errorf("Version.IsOld = %v, want false.", v.IsOld())
	}
	if v.IsDraft() {
		t.Errorf("Version.IsDraft = %v, want false.", v.IsDraft())
	}
	if !v.IsUnknown() {
		t.Errorf("Version.IsUnknown = %v, want true.", v.IsUnknown())
	}
	if v.Number() != 0 {
		t.Errorf("Version.Number = %v, want 0.", v.Number())
	}
	if v.ToItem(true) != nil {
		t.Error("Version to Item: not nil, want nil.")
	}
}

func TestPubVer4(t *testing.T) {
	i := PubVer(4).ToItem(true)

	if i.Note != "current" {
		t.Errorf("Version.Note = \"%v\", want \"current\"", i.Note)
	}
}

func TestPubVer5(t *testing.T) {
	i := PubVer(5).ToItem(true)

	if i.Note != "draft" {
		t.Errorf("Version.Note = \"%v\", want \"draft\"", i.Note)
	}
}

func TestSigVer5(t *testing.T) {
	i := SigVer(5).ToItem(true)

	if i.Note != "draft" {
		t.Errorf("Version.Note = \"%v\", want \"draft\"", i.Note)
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

func TestSymSessKeyVer5(t *testing.T) {
	i := SymSessKeyVer(5).ToItem(true)

	if i.Note != "draft" {
		t.Errorf("Version.Note = \"%v\", want \"draft\"", i.Note)
	}
}

/* Copyright 2016-2019 Spiegel
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
