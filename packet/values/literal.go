package values

import (
	"fmt"
	"unicode"
	"unicode/utf8"

	"github.com/spiegel-im-spiegel/errs"
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

//Text is literal text
type Text struct {
	name string
	body []byte
}

//NewText returns new Text instance
func NewText(body []byte, name string) *Text {
	return &Text{name: name, body: body}
}

//NewLiteralFname returns new Text instance for file name of literal data
func NewLiteralFname(r *reader.Reader, l int64) (*Text, error) {
	name := "File name"
	if r == nil {
		return NewText(nil, name), nil
	}
	if l < 1 {
		return NewText(nil, name), nil
	}
	data, err := r.ReadBytes(l)
	if err != nil {
		return nil, errs.Wrap(
			err,
			fmt.Sprintf("illegal file name of literal packet (length: %d bytes)", l),
		)
	}
	return NewText(data, name), nil
}

func (t *Text) ToItem(dumpFlag bool) *info.Item {
	if t == nil {
		return info.NewItem(
			info.Note("null"),
		)
	}
	if t.body == nil || len(t.body) == 0 {
		return info.NewItem(
			info.Name(t.name),
			info.Note("0 byte"),
		)
	}
	if !utf8.Valid(t.body) {
		return info.NewItem(
			info.Name(t.name),
			info.Note("invalid text string"),
			info.DumpStr(DumpBytes(t.body, true).String()),
		)
	}
	rs := []rune{}
	for _, r := range string(t.body) {
		if unicode.IsControl(r) {
			c := fmt.Sprintf("(%U)", r)
			rs = append(rs, []rune(c)...)
		} else {
			rs = append(rs, r)
		}
	}
	return info.NewItem(
		info.Name(t.name),
		info.Value(string(rs)),
		info.DumpStr(DumpBytes(t.body, dumpFlag).String()),
	)
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
