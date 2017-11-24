package values

import (
	"testing"

	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
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
	"Unknown (tag 20)",
	"Unknown (tag 21)",
	"Unknown (tag 22)",
	"Unknown (tag 23)",
	"Unknown (tag 24)",
	"Unknown (tag 25)",
	"Unknown (tag 26)",
	"Unknown (tag 27)",
	"Unknown (tag 28)",
	"Unknown (tag 29)",
	"Unknown (tag 30)",
	"Unknown (tag 31)",
	"Unknown (tag 32)",
	"Unknown (tag 33)",
	"Unknown (tag 34)",
	"Unknown (tag 35)",
	"Unknown (tag 36)",
	"Unknown (tag 37)",
	"Unknown (tag 38)",
	"Unknown (tag 39)",
	"Unknown (tag 40)",
	"Unknown (tag 41)",
	"Unknown (tag 42)",
	"Unknown (tag 43)",
	"Unknown (tag 44)",
	"Unknown (tag 45)",
	"Unknown (tag 46)",
	"Unknown (tag 47)",
	"Unknown (tag 48)",
	"Unknown (tag 49)",
	"Unknown (tag 50)",
	"Unknown (tag 51)",
	"Unknown (tag 52)",
	"Unknown (tag 53)",
	"Unknown (tag 54)",
	"Unknown (tag 55)",
	"Unknown (tag 56)",
	"Unknown (tag 57)",
	"Unknown (tag 58)",
	"Unknown (tag 59)",
	"Private or Experimental Values (tag 60)",
	"Private or Experimental Values (tag 61)",
	"Private or Experimental Values (tag 62)",
	"Private or Experimental Values (tag 63)",
	"Unknown (tag 64)",
}

func TestTagID(t *testing.T) {
	var body = []byte{0x01, 0x02, 0x03, 0x04}
	for tag := 0; tag <= 64; tag++ {
		i := TagID(tag).ToItem(reader.New(body), true)
		if i.Name != "Packet" {
			t.Errorf("Tag.Name = \"%s\", want \"Packet\".", i.Name)
		}
		if i.Value != testTagNames[tag] {
			t.Errorf("Tag.Value = \"%s\", want \"%s\".", i.Value, testTagNames[tag])
		}
		if i.Note != "4 bytes" {
			t.Errorf("Tag.Note = \"%s\", want \"4 bytes\"", i.Note)
		}
		if i.Dump != "01 02 03 04" {
			t.Errorf("Tag.Dump = \"%s\", want \"01 02 03 04\".", i.Dump)
		}
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
