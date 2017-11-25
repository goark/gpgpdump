package values

import "testing"

func TestFlag2Item(t *testing.T) {
	i := Flag2Item(0x01, "flag name")
	if i.Name != "Flag" {
		t.Errorf("Flag2Item() -> i.Name = \"%v\", want \"Flag\".", i.Name)
	}
	if i.Value != "flag name" {
		t.Errorf("Flag2Item() -> i.Value = \"%v\", want \"flag name\".", i.Value)
	}
	if i.Note != "" {
		t.Errorf("Flag2Item() -> i.Note = \"%v\", want \"\"", i.Note)
	}
	if i.Dump != "" {
		t.Errorf("Flag2Item() -> i.Dump = \"%v\", want \"\".", i.Dump)
	}
}

func TestFlag2ItemNil(t *testing.T) {
	i := Flag2Item(0x00, "flag name")
	if i != nil {
		t.Error("Flag2Item() = not nil, want nil.")
	}
}

/* Copyright 2017 Spiegel
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
