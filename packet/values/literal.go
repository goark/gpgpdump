package values

import (
	"fmt"
	"unicode"
	"unicode/utf8"

	"github.com/spiegel-im-spiegel/gpgpdump/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
)

var literalFormatNames = Msgs{
	0x62: "binary",     //'b'
	0x74: "text",       //'t'
	0x75: "UTF-8 text", //'u'
	0x31: "local",      //'l' -- RFC 1991 incorrectly stated this local mode flag as '1' (ASCII numeral one). Both of these local modes are deprecated.
	0x6c: "local",      //'l'
}

//LiteralFormat is format of literal data
type LiteralFormat byte

//ToItem returns Item instance
func (l LiteralFormat) ToItem() *info.Item {
	return info.NewItem(
		info.Name("Literal data format"),
		info.Value(l.String()),
		info.Note(literalFormatNames.Get(int(l), "unknown")),
	)
}

func (l LiteralFormat) String() string {
	return string(l)
}

//LiteralFname is file name of literal data
type LiteralFname struct {
	name []byte
}

//NewLiteralFname returns new LiteralFname instance
func NewLiteralFname(r *reader.Reader, l int64) (*LiteralFname, error) {
	if r == nil {
		return &LiteralFname{name: nil}, nil
	}
	if l < 1 {
		return &LiteralFname{name: nil}, nil
	}
	data, err := r.ReadBytes(l)
	if err != nil {
		return nil, errs.Wrapf(err, "illegal file name of literal packet (length: %d bytes)", l)
	}
	return &LiteralFname{name: data}, err
}

//ToItem returns Item instance
func (l *LiteralFname) ToItem(dumpFlag bool) *info.Item {
	if l == nil {
		return nil
	}
	name := "File name"
	if l.name == nil {
		return info.NewItem(
			info.Name(name),
			info.Value("<null>"),
		)
	}
	fname := stripString(l.name)
	if len(fname) == 0 {
		return info.NewItem(
			info.Name(name),
			info.Value("<invalid text string>"),
			info.DumpStr(DumpBytes(l.name, dumpFlag).String()),
		)
	}
	return info.NewItem(
		info.Name(name),
		info.Value(fname),
		info.DumpStr(DumpBytes(l.name, dumpFlag).String()),
	)
}

func stripString(b []byte) string {
	if !utf8.Valid(b) {
		return ""
	}
	rs := []rune{}
	for _, r := range string(b) {
		if unicode.IsControl(r) {
			c := fmt.Sprintf("(%U)", r)
			rs = append(rs, []rune(c)...)
		} else {
			rs = append(rs, r)
		}
	}
	return string(rs)
}

//RawData returns info.Item instance for raw data
func RawData(r *reader.Reader, name string, dumpFlag bool) *info.Item {
	rst := r.Rest()
	return info.NewItem(
		info.Name(name),
		info.Note(fmt.Sprintf("%d bytes", rst)),
		info.DumpStr(Dump(r, dumpFlag).String()),
	)
}

/* Copyright 2016-2019 Spiegel
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
