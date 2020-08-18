package values

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/parse/result"
)

var compIDNames = Msgs{
	0: "Uncompressed",
	1: "ZIP <RFC1951>",
	2: "ZLIB <RFC1950>",
	3: "BZip2",
}

//CompID is Compression Algorithm ID
type CompID byte

// ToItem returns Item instance
func (ca CompID) ToItem(dumpFlag bool) *result.Item {
	return result.NewItem(
		result.Name("Compression Algorithm"),
		result.Value(ca.String()),
		result.DumpStr(DumpByteString(byte(ca), dumpFlag)),
	)
}

func (ca CompID) String() string {
	return fmt.Sprintf("%s (comp %d)", compIDNames.Get(int(ca), Unknown), ca)
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
