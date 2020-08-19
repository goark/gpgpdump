package values

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/parse/result"
)

var hashIDNames = Msgs{
	0:  "Unknown",
	1:  "MD5",
	2:  "SHA-1",
	3:  "RIPE-MD/160",
	4:  "Reserved",
	5:  "Reserved",
	6:  "Reserved",
	7:  "Reserved",
	8:  "SHA2-256",
	9:  "SHA2-384",
	10: "SHA2-512",
	11: "SHA2-224",
	12: "SHA3-256",
	13: "Reserved",
	14: "SHA3-512",
}

// HashID is Hash Algorithm ID
type HashID byte

//ToItem returns Item instance
func (ha HashID) ToItem(dumpFlag bool) *result.Item {
	return result.NewItem(
		result.Name("Hash Algorithm"),
		result.Value(ha.String()),
		result.DumpStr(DumpByteString(byte(ha), dumpFlag)),
	)
}

//Stringer for SigID
func (ha HashID) String() string {
	var name string
	if 100 <= ha && ha <= 110 {
		name = PrivateAlgName
	} else {
		name = hashIDNames.Get(int(ha), "Unknown")
	}
	return fmt.Sprintf("%s (hash %d)", name, int(ha))
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
