package context

import (
	"testing"

	"github.com/spiegel-im-spiegel/gpgpdump/options"
)

func TestResetSymAlgMode(t *testing.T) {
	cxt := NewContext(&options.Options{})

	cxt.ResetAlg()
	if cxt.AlgMode() != ModeNotSpecified {
		t.Errorf("Options.Mode = %v, want \"Mode not Specified\".", cxt.AlgMode())
	}
	if cxt.AlgMode().String() != "Mode not Specified" {
		t.Errorf("Options.Mode = %v, want \"Mode not Specified\".", cxt.AlgMode())
	}
	if cxt.IsPubEnc() {
		t.Errorf("Options.Mode = %v, want \"Mode not Specified\".", cxt.AlgMode())

	}
	if cxt.IsSymEnc() {
		t.Errorf("Options.Mode = %v, want \"Mode not Specified\".", cxt.AlgMode())

	}
}

func TestSetSymAlgModeSymEnc(t *testing.T) {
	cxt := NewContext(&options.Options{})

	cxt.SetAlgSymEnc()
	if cxt.AlgMode().String() != "Sym. Encryption Mode" {
		t.Errorf("Options.Mode = %v, want \"Sym. Encryption Mode\".", cxt.AlgMode())
	}
	if cxt.IsPubEnc() {
		t.Errorf("Options.Mode = %v, want \"Sym. Encryption Mode\".", cxt.AlgMode())

	} else if !cxt.IsSymEnc() {
		t.Errorf("Options.Mode = %v, want \"Sym. Encryption Mode\".", cxt.AlgMode())

	}
}

func TestSSetSymAlgModePubEnc(t *testing.T) {
	cxt := NewContext(&options.Options{})

	cxt.SetAlgPubEnc()
	if cxt.AlgMode().String() != "Pubkey Encryption Mode" {
		t.Errorf("Options.Mode = %v, want \"Pubkey Encryption Mode\".", cxt.AlgMode())
	}
	if cxt.IsSymEnc() {
		t.Errorf("Options.Mode = %v, want \"Pubkey Encryption Mode\".", cxt.AlgMode())

	} else if !cxt.IsPubEnc() {
		t.Errorf("cxtions.Mode = %v, want \"Pubkey Encryption Mode\".", cxt.AlgMode())

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
