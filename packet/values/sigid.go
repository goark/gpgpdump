package values

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/info"
)

var sigIDNames = Msgs{
	0x00: "Signature of a binary document",
	0x01: "Signature of a canonical text document",
	0x02: "Standalone signature",
	0x10: "Generic certification of a User ID and Public-Key packet",
	0x11: "Persona certification of a User ID and Public-Key packet",
	0x12: "Casual certification of a User ID and Public-Key packet",
	0x13: "Positive certification of a User ID and Public-Key packet",
	0x18: "Subkey Binding Signature",
	0x19: "Primary Key Binding Signature",
	0x1f: "Signature directly on a key",
	0x20: "Key revocation signature",
	0x28: "Subkey revocation signature",
	0x30: "Certification revocation signature",
	0x40: "Timestamp signature",
	0x50: "Third-Party Confirmation signature",
}

//SigID is Signiture Type ID
type SigID byte

//ToItem returns Item instance
func (s SigID) ToItem(dumpFlag bool) *info.Item {
	return info.NewItem(
		info.Name("Signiture Type"),
		info.Value(s.String()),
		info.DumpStr(DumpByteString(byte(s), dumpFlag)),
	)
}

//Stringer for SigID
func (s SigID) String() string {
	return fmt.Sprintf("%s (%#02x)", sigIDNames.Get(int(s), Unknown), int(s))
}

/* Copyright 2016 Spiegel
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
