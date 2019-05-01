package values

import (
	"io"
	"testing"

	"github.com/spiegel-im-spiegel/gpgpdump/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
)

func TestLiteralFormat(t *testing.T) {
	for tag := byte(0x20); tag <= byte(0xfe); tag++ {
		i := LiteralFormat(tag).ToItem()
		if i.Name != "Literal data format" {
			t.Errorf("LiteralFormat.Name = \"%s\", want \"Literal data format\".", i.Name)
		}
		if i.Value != string(tag) {
			t.Errorf("LiteralFormat.Value = \"%s\", want \"%s\".", i.Value, string(tag))
		}
		var note string
		switch tag {
		case 0x62: //'b'
			note = "binary"
		case 0x74: //'t'
			note = "text"
		case 0x75: //'u'
			note = "UTF-8 text"
		case 0x31: //'l' -- RFC 1991 incorrectly stated this local mode flag as '1' (ASCII numeral one). Both of these local modes are deprecated.
			note = "local"
		case 0x6c: //'l'
			note = "local"
		default:
			note = "unknown"
		}
		if i.Note != note {
			t.Errorf("LiteralFormat.Note = \"%s\", want \"%s\"", i.Note, note)
		}
		if i.Dump != "" {
			t.Errorf("LiteralFormat.Dump = \"%s\", want \"\".", i.Dump)
		}
	}
}

func TestLiteralFname(t *testing.T) {
	testCases := []struct {
		data  []byte
		value string
		note  string
		dump  string
	}{
		{
			data:  []byte("hoge"),
			value: "hoge",
			note:  "",
			dump:  "68 6f 67 65",
		},
		{
			data:  []byte("\nhoge"),
			value: "(U+000A)hoge",
			note:  "",
			dump:  "0a 68 6f 67 65",
		},
		{
			data:  []byte{0xff, 0xfe, 0xfd},
			value: "",
			note:  "invalid text string",
			dump:  "ff fe fd",
		},
		{
			data:  []byte{},
			value: "",
			note:  "0 byte",
			dump:  "",
		},
		{
			data:  nil,
			value: "",
			note:  "0 byte",
			dump:  "",
		},
	}
	for _, tc := range testCases {
		var l *Text
		var err error
		if tc.data == nil {
			l, err = NewLiteralFname(nil, 0)
		} else {
			l, err = NewLiteralFname(reader.New(tc.data), int64(len(tc.data)))
		}
		if err != nil {
			t.Errorf("NewLiteralFname() = \"%+v\", want nil error.", err)
			continue
		}
		i := l.ToItem(true)
		if i.Name != "File name" {
			t.Errorf("LiteralFname.Name = \"%s\", want \"File name\".", i.Name)
		}
		if i.Value != tc.value {
			t.Errorf("LiteralFname.Value = \"%v\", want \"%v\".", i.Value, tc.value)
		}
		if i.Note != tc.note {
			t.Errorf("LiteralFname.Note = \"%s\", want \"%v\"", i.Note, tc.note)
		}
		if i.Dump != tc.dump {
			t.Errorf("LiteralFname.Dump = \"%v\", want \"%v\".", i.Dump, tc.dump)
		}
	}
}

func TestLiteralFnameErr(t *testing.T) {
	_, err := NewLiteralFname(reader.New([]byte("hoge")), 10)
	if !errs.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("NewLiteralFname() = \"%+v\", want \"%v\".", err, io.ErrUnexpectedEOF)
	}
}

func TestRawData(t *testing.T) {
	var data = []byte{0x01, 0x02, 0x03, 0x04}
	name := "Literal data"
	dump := "01 02 03 04"
	i := RawData(reader.New(data), name, true)
	if i.Name != "Literal data" {
		t.Errorf("LiteralData.Name = \"%v\", want \"Literal data\".", i.Name)
	}
	if i.Value != "" {
		t.Errorf("LiteralData.Value = \"%v\", want \"\".", i.Value)
	}
	if i.Note != "4 bytes" {
		t.Errorf("LiteralData.Note = \"%v\", want \"4 bytes\"", i.Note)
	}
	if i.Dump != dump {
		t.Errorf("LiteralData.Dump = \"%v\", want \"%s\".", i.Dump, dump)
	}
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
