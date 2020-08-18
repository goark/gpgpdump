package values

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/parse/result"
)

var symIDNames = Msgs{
	0:  "Plaintext or unencrypted data",
	1:  "IDEA",
	2:  "TripleDES (168 bit key derived from 192)",
	3:  "CAST5 (128 bit key, as per)",
	4:  "Blowfish (128 bit key, 16 rounds)",
	5:  "Reserved",
	6:  "Reserved",
	7:  "AES with 128-bit key",
	8:  "AES with 192-bit key",
	9:  "AES with 256-bit key",
	10: "Twofish with 256-bit key",
	11: "Camellia with 128-bit key",
	12: "Camellia with 192-bit key",
	13: "Camellia with 256-bit key",
}

var symIDIVLen = map[int]int{
	0:  8,  //Plaintext or unencrypted data
	1:  8,  //IDEA
	2:  8,  //TripleDES (168 bit key derived from 192)
	3:  8,  //CAST5
	4:  8,  //Blowfish
	5:  8,  //Reserved
	6:  8,  //Reserved
	7:  16, //AES with 128-bit key
	8:  16, //AES with 192-bit key
	9:  16, //AES with 256-bit key
	10: 16, //Twofish with 256-bit key
	11: 16, //Camellia with 128-bit key
	12: 16, //Camellia with 192-bit key
	13: 16, //Camellia with 256-bit key
}

//SymID is Symmetric-Key Algorithm ID
type SymID byte

//ToItem returns Item instance
func (s SymID) ToItem(dumpFlag bool) *result.Item {
	return result.NewItem(
		result.Name("Symmetric Algorithm"),
		result.Value(s.String()),
		result.DumpStr(DumpByteString(byte(s), dumpFlag)),
	)
}

// IVLen returns length of IV
func (s SymID) IVLen() int {
	if v, ok := symIDIVLen[int(s)]; ok {
		return v
	}
	return 0
}

//Stringer for SymID
func (s SymID) String() string {
	var name string
	if 100 <= s && s <= 110 {
		name = PrivateAlgName
	} else {
		name = symIDNames.Get(int(s), Unknown)
	}
	return fmt.Sprintf("%s (sym %d)", name, int(s))
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
