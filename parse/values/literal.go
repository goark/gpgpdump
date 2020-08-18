package values

import (
	"fmt"
	"unicode"
	"unicode/utf8"

	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/result"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/reader"
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
func (l LiteralFormat) ToItem() *result.Item {
	return result.NewItem(
		result.Name("Literal data format"),
		result.Value(l.String()),
		result.Note(literalFormatNames.Get(int(l), "unknown")),
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
		return nil, errs.New(fmt.Sprintf("illegal file name of literal packet (length: %d bytes)", l), errs.WithCause(err))
	}
	return NewText(data, name), nil
}

func (t *Text) ToItem(dumpFlag bool) *result.Item {
	if t == nil {
		return result.NewItem(
			result.Note("null"),
		)
	}
	if t.body == nil || len(t.body) == 0 {
		return result.NewItem(
			result.Name(t.name),
			result.Note("0 byte"),
		)
	}
	if !utf8.Valid(t.body) {
		return result.NewItem(
			result.Name(t.name),
			result.Note("invalid text string"),
			result.DumpStr(DumpBytes(t.body, true).String()),
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
	return result.NewItem(
		result.Name(t.name),
		result.Value(string(rs)),
		result.DumpStr(DumpBytes(t.body, dumpFlag).String()),
	)
}

//RawData returns result.Item instance for raw data
func RawData(r *reader.Reader, name string, dumpFlag bool) *result.Item {
	rst := r.Rest()
	return result.NewItem(
		result.Name(name),
		result.Note(fmt.Sprintf("%d bytes", rst)),
		result.DumpStr(Dump(r, dumpFlag).String()),
	)
}

/* Copyright 2016-2020 Spiegel
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
