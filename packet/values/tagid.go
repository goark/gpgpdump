package values

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
)

var tagNames = Msgs{
	0:  "Reserved",
	1:  "Public-Key Encrypted Session Key Packet",
	2:  "Signature Packet",
	3:  "Symmetric-Key Encrypted Session Key Packet",
	4:  "One-Pass Signature Packet",
	5:  "Secret-Key Packet",
	6:  "Public-Key Packet",
	7:  "Secret-Subkey Packet",
	8:  "Compressed Data Packet",
	9:  "Symmetrically Encrypted Data Packet",
	10: "Marker Packet (Obsolete Literal Packet)",
	11: "Literal Data Packet",
	12: "Trust Packet",
	13: "User ID Packet",
	14: "Public-Subkey Packet",
	17: "User Attribute Packet",
	18: "Sym. Encrypted Integrity Protected Data Packet",
	19: "Modification Detection Code Packet",
	60: "Private or Experimental Values",
	61: "Private or Experimental Values",
	62: "Private or Experimental Values",
	63: "Private or Experimental Values",
}

// TagID is tag ID of packet
type TagID int

// ToItem returns Item instance
func (t TagID) ToItem(r *reader.Reader, dumpFlag bool) *info.Item {
	return info.NewItem(
		info.Name("Packet"),
		info.Value(t.String()),
		info.Note(fmt.Sprintf("%d bytes", r.Len())),
		info.DumpStr(Dump(r, dumpFlag).String()),
	)
}

func (t TagID) String() string {
	return fmt.Sprintf("%s (tag %d)", tagNames.Get(int(t), Unknown), t)
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
