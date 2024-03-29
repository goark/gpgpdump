package values

import (
	"fmt"
	"strconv"

	"github.com/goark/gpgpdump/parse/result"
)

var s2kIDNames = Msgs{
	0: "Simple S2K",
	1: "Salted S2K",
	2: "Reserved",
	3: "Iterated and Salted S2K",
	4: "Argon2",
}

//S2KID is S2K Algorithm ID
type S2KID byte

// ToItem returns Item instance
func (sa S2KID) ToItem(dumpFlag bool) *result.Item {
	return result.NewItem(
		result.Name("String-to-Key (S2K) Algorithm"),
		result.Value(sa.String()),
		result.DumpStr(DumpByteString(byte(sa), dumpFlag)),
	)
}

func (sa S2KID) String() string {
	var name string
	if 100 <= sa && sa <= 110 {
		name = PrivateAlgName
	} else {
		name = s2kIDNames.Get(int(sa), Unknown)
	}
	return fmt.Sprintf("%s (s2k %d)", name, int(sa))
}

//Salt value class
type Salt []byte

// ToItem returns Item instance
func (s Salt) ToItem(dumpFlag bool) *result.Item {
	return result.NewItem(
		result.Name("Salt"),
		result.DumpStr(DumpBytes(s, dumpFlag).String()),
	)
}

//S2KEXPBIAS - S2K parameter
var S2KEXPBIAS = uint32(6)

//Stretch class for count of stretching hash
type Stretch byte

// ToItem returns Item instance
func (c Stretch) ToItem() *result.Item {
	count := (uint32(16) + (uint32(c) & 0x0f)) << ((uint32(c) >> 4) + S2KEXPBIAS)
	return result.NewItem(
		result.Name("Count"),
		result.Value(strconv.Itoa(int(count))),
		result.DumpStr(DumpByteString(byte(c), true)),
	)
}

//Argon2Params parameters for Argon2
type Argon2Params byte

// ToItem returns Item instance
func (c Argon2Params) ToItem(name string) *result.Item {
	count := (uint32(16) + (uint32(c) & 0x0f)) << ((uint32(c) >> 4) + S2KEXPBIAS)
	return result.NewItem(
		result.Name(name),
		result.Value(strconv.Itoa(int(count))),
		result.DumpStr(DumpByteString(byte(c), true)),
	)
}

/* Copyright 2016-2021 Spiegel
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
