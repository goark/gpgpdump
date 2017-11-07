package values

import (
	"encoding/binary"
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/info"
)

// KeyID is Key ID
type KeyID uint64

//NewKeyID returns KeyID instance from octets
func NewKeyID(octets []byte) KeyID {
	return KeyID(binary.BigEndian.Uint64(octets))
}

//ToItem returns Item instance
func (k KeyID) ToItem() *info.Item {
	return info.NewItem(
		info.Name("Key ID"),
		info.Value(k.String()),
	)
}

func (k KeyID) String() string {
	return fmt.Sprintf("%#016x", uint64(k))
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
