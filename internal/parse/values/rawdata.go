package values

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

//RawData - raw data
type RawData struct {
	name string
	note string
	buf  []byte
	dump bool
}

//NewRawData returns new RawData instance
func NewRawData(name, note string, buf []byte, dump bool) *RawData {
	return &RawData{name: name, note: note, buf: buf, dump: dump}
}

// Get returns Item instance
func (r RawData) Get() *items.Item {
	dump := "..."
	if r.dump {
		dump = DumpByte(r.buf)
	}
	return items.NewItemDump(r.name, dump, r.note)
}

// DumpByte returns string byte-data
func DumpByte(data []byte) string {
	sep := ""
	var buf = make([]byte, 0, 16)
	for _, b := range data {
		buf = append(buf, fmt.Sprintf("%s%02x", sep, b)...)
		sep = " "
	}
	return string(buf)
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
