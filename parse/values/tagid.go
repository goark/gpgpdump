package values

import (
	"fmt"

	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/result"
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
	20: "AEAD Encrypted Data Packet",
	21: "Padding Packet",
	22: "Unassigned Critical Packet",
	23: "Unassigned Critical Packet",
	24: "Unassigned Critical Packet",
	25: "Unassigned Critical Packet",
	26: "Unassigned Critical Packet",
	27: "Unassigned Critical Packet",
	28: "Unassigned Critical Packet",
	29: "Unassigned Critical Packet",
	30: "Unassigned Critical Packet",
	31: "Unassigned Critical Packet",
	32: "Unassigned Critical Packet",
	33: "Unassigned Critical Packet",
	34: "Unassigned Critical Packet",
	35: "Unassigned Critical Packet",
	36: "Unassigned Critical Packet",
	37: "Unassigned Critical Packet",
	38: "Unassigned Critical Packet",
	39: "Unassigned Critical Packet",
	40: "Unassigned Non-Critical Packet",
	41: "Unassigned Non-Critical Packet",
	42: "Unassigned Non-Critical Packet",
	43: "Unassigned Non-Critical Packet",
	44: "Unassigned Non-Critical Packet",
	45: "Unassigned Non-Critical Packet",
	46: "Unassigned Non-Critical Packet",
	47: "Unassigned Non-Critical Packet",
	48: "Unassigned Non-Critical Packet",
	49: "Unassigned Non-Critical Packet",
	50: "Unassigned Non-Critical Packet",
	51: "Unassigned Non-Critical Packet",
	52: "Unassigned Non-Critical Packet",
	53: "Unassigned Non-Critical Packet",
	54: "Unassigned Non-Critical Packet",
	55: "Unassigned Non-Critical Packet",
	56: "Unassigned Non-Critical Packet",
	57: "Unassigned Non-Critical Packet",
	58: "Unassigned Non-Critical Packet",
	59: "Unassigned Non-Critical Packet",
	60: "Private or Experimental Values",
	61: "Private or Experimental Values",
	62: "Private or Experimental Values",
	63: "Private or Experimental Values",
}

// TagID is tag ID of packet
type TagID int

// ToItem returns Item instance
func (t TagID) ToItem(r *reader.Reader, dumpFlag bool) *result.Item {
	return result.NewItem(
		result.Name(t.String()),
		result.Note(fmt.Sprintf("%d bytes", r.Len())),
		result.DumpStr(Dump(r, dumpFlag).String()),
	)
}

func (t TagID) String() string {
	return fmt.Sprintf("%s (tag %d)", tagNames.Get(int(t), Unknown), t)
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
