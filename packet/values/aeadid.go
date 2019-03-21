package values

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/info"
)

var aeadIDNames = Msgs{
	1: "EAX mode",
	2: "OCB mode <RFC7253>",
}

//AEADID is AEAD Algorithm ID
type AEADID byte

// ToItem returns Item instance
func (aa AEADID) ToItem(dumpFlag bool) *info.Item {
	return info.NewItem(
		info.Name("AEAD Algorithm"),
		info.Value(aa.String()),
		info.DumpStr(DumpByteString(byte(aa), dumpFlag)),
	)
}

func (aa AEADID) String() string {
	var name string
	if 100 <= aa && aa <= 110 {
		name = PrivateAlgName
	} else {
		name = aeadIDNames.Get(int(aa), Unknown)
	}
	return fmt.Sprintf("%s (aead %d)", name, int(aa))
}

/* Copyright 2019 Spiegel
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
