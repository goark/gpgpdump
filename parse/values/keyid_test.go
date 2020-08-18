package values

import "testing"

func TestKeyID(t *testing.T) {
	key := KeyID(0x1234567890123456)
	i := key.ToItem()

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

func TestNewKeyID(t *testing.T) {
	octets := []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56}
	i := NewKeyID(octets).ToItem()

	if i.Value != "0x1234567890123456" {
		t.Errorf("KeyID.Value = \"%v\", want \"0x1234567890123456\".", i.Value)
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
