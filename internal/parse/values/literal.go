package values

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

var literalFormatNames = Msgs{
	0x62: "binary",     //'b'
	0x74: "text",       //'t'
	0x75: "UTF-8 text", //'u'
	0x31: "local",      //'l' -- RFC 1991 incorrectly stated this local mode flag as '1' (ASCII numeral one). Both of these local modes are deprecated.
	0x6c: "local",      //'l'
}

// LiteralFormat is format of literal data
type LiteralFormat byte

// Get returns Item instance
func (l LiteralFormat) Get() *items.Item {
	return items.NewItem("Literal data format", l.String(), literalFormatNames.Get(int(l), "unknown"), "")
}

func (l LiteralFormat) String() string {
	return string(byte(l))
}

// LiteralFname is file name of literal data
type LiteralFname string

// Get returns Item instance
func (l LiteralFname) Get() *items.Item {
	return items.NewItem("File name", string(l), "", "")
}

//LiteralData returns new RawData instance for Literal data
func LiteralData(buf []byte, dump bool) *RawData {
	return NewRawData("Literal data", fmt.Sprintf("%d bytes", len(buf)), buf, dump)
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
