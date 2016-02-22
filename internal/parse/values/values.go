package values

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

//Msgs is type of message list.
type Msgs map[int]string

//Get returns message.
func (m Msgs) Get(i int, def string) string {
	if msg, ok := m[i]; ok {
		return msg
	}
	return def
}

// KeyID is Key ID
type KeyID uint64

//Get returns Item instance
func (k KeyID) Get() *items.Item {
	return items.NewItem("Key ID", k.String(), "", "")
}

func (k KeyID) String() string {
	return fmt.Sprintf("0x%X", uint64(k))
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
