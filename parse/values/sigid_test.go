package values

import (
	"fmt"
	"testing"
)

func TestSigIS(t *testing.T) {
	for tag := 0; tag <= 0x51; tag++ {
		i := SigID(tag).ToItem(false)
		var value string
		switch tag {
		case 0x00:
			value = "Signature of a binary document (0x00)"
		case 0x01:
			value = "Signature of a canonical text document (0x01)"
		case 0x02:
			value = "Standalone signature (0x02)"
		case 0x10:
			value = "Generic certification of a User ID and Public-Key packet (0x10)"
		case 0x11:
			value = "Persona certification of a User ID and Public-Key packet (0x11)"
		case 0x12:
			value = "Casual certification of a User ID and Public-Key packet (0x12)"
		case 0x13:
			value = "Positive certification of a User ID and Public-Key packet (0x13)"
		case 0x18:
			value = "Subkey Binding Signature (0x18)"
		case 0x19:
			value = "Primary Key Binding Signature (0x19)"
		case 0x1f:
			value = "Signature directly on a key (0x1f)"
		case 0x20:
			value = "Key revocation signature (0x20)"
		case 0x28:
			value = "Subkey revocation signature (0x28)"
		case 0x30:
			value = "Certification revocation signature (0x30)"
		case 0x40:
			value = "Timestamp signature (0x40)"
		case 0x50:
			value = "Third-Party Confirmation signature (0x50)"
		default:
			value = fmt.Sprintf("Unknown (0x%02x)", tag)
		}
		if i.Name != "Signiture Type" {
			t.Errorf("SigType.Name = \"%s\", want \"Signiture Type\".", i.Name)
		}
		if i.Value != value {
			t.Errorf("SigType.Value = \"%s\", want \"%s\".", i.Value, value)
		}
		if i.Note != "" {
			t.Errorf("SigType.Note = \"%s\", want \"\"", i.Note)
		}
		if i.Dump != "" {
			t.Errorf("SigType.Dump = \"%s\", want \"\".", i.Dump)
		}
	}
}

/* Copyright 2016-2022 Spiegel
 *
 * Licensed under the Apiche License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apiche.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
