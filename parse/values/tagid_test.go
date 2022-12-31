package values

import (
	"testing"

	"github.com/goark/gpgpdump/parse/reader"
)

var testTagNames = []string{
	"Reserved (tag 0)",
	"Public-Key Encrypted Session Key Packet (tag 1)",
	"Signature Packet (tag 2)",
	"Symmetric-Key Encrypted Session Key Packet (tag 3)",
	"One-Pass Signature Packet (tag 4)",
	"Secret-Key Packet (tag 5)",
	"Public-Key Packet (tag 6)",
	"Secret-Subkey Packet (tag 7)",
	"Compressed Data Packet (tag 8)",
	"Symmetrically Encrypted Data Packet (tag 9)",
	"Marker Packet (Obsolete Literal Packet) (tag 10)",
	"Literal Data Packet (tag 11)",
	"Trust Packet (tag 12)",
	"User ID Packet (tag 13)",
	"Public-Subkey Packet (tag 14)",
	"Unknown (tag 15)",
	"Unknown (tag 16)",
	"User Attribute Packet (tag 17)",
	"Sym. Encrypted Integrity Protected Data Packet (tag 18)",
	"Modification Detection Code Packet (tag 19)",
	"AEAD Encrypted Data Packet (tag 20)",
	"Padding Packet (tag 21)",
	"Unassigned Critical Packet (tag 22)",
	"Unassigned Critical Packet (tag 23)",
	"Unassigned Critical Packet (tag 24)",
	"Unassigned Critical Packet (tag 25)",
	"Unassigned Critical Packet (tag 26)",
	"Unassigned Critical Packet (tag 27)",
	"Unassigned Critical Packet (tag 28)",
	"Unassigned Critical Packet (tag 29)",
	"Unassigned Critical Packet (tag 30)",
	"Unassigned Critical Packet (tag 31)",
	"Unassigned Critical Packet (tag 32)",
	"Unassigned Critical Packet (tag 33)",
	"Unassigned Critical Packet (tag 34)",
	"Unassigned Critical Packet (tag 35)",
	"Unassigned Critical Packet (tag 36)",
	"Unassigned Critical Packet (tag 37)",
	"Unassigned Critical Packet (tag 38)",
	"Unassigned Critical Packet (tag 39)",
	"Unassigned Non-Critical Packet (tag 40)",
	"Unassigned Non-Critical Packet (tag 41)",
	"Unassigned Non-Critical Packet (tag 42)",
	"Unassigned Non-Critical Packet (tag 43)",
	"Unassigned Non-Critical Packet (tag 44)",
	"Unassigned Non-Critical Packet (tag 45)",
	"Unassigned Non-Critical Packet (tag 46)",
	"Unassigned Non-Critical Packet (tag 47)",
	"Unassigned Non-Critical Packet (tag 48)",
	"Unassigned Non-Critical Packet (tag 49)",
	"Unassigned Non-Critical Packet (tag 50)",
	"Unassigned Non-Critical Packet (tag 51)",
	"Unassigned Non-Critical Packet (tag 52)",
	"Unassigned Non-Critical Packet (tag 53)",
	"Unassigned Non-Critical Packet (tag 54)",
	"Unassigned Non-Critical Packet (tag 55)",
	"Unassigned Non-Critical Packet (tag 56)",
	"Unassigned Non-Critical Packet (tag 57)",
	"Unassigned Non-Critical Packet (tag 58)",
	"Unassigned Non-Critical Packet (tag 59)",
	"Private or Experimental Values (tag 60)",
	"Private or Experimental Values (tag 61)",
	"Private or Experimental Values (tag 62)",
	"Private or Experimental Values (tag 63)",
	"Unknown (tag 64)",
}

func TestTagID(t *testing.T) {
	var body = []byte{0x01, 0x02, 0x03, 0x04}
	for tag := 0; tag < len(testTagNames); tag++ {
		i := TagID(tag).ToItem(reader.New(body), true)
		if i.Name != testTagNames[tag] {
			t.Errorf("Tag.Name = \"%s\", want \"%s\".", i.Name, testTagNames[tag])
		}
		if i.Value != "" {
			t.Errorf("Tag.Value = \"%s\", want \"\".", i.Name)
		}
		if i.Note != "4 bytes" {
			t.Errorf("Tag.Note = \"%s\", want \"4 bytes\"", i.Note)
		}
		if i.Dump != "01 02 03 04" {
			t.Errorf("Tag.Dump = \"%s\", want \"01 02 03 04\".", i.Dump)
		}
	}
}

/* Copyright 2016-2022 Spiegel
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
