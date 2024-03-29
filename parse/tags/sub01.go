package tags

import (
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/goark/errs"

	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/result"
	"github.com/goark/gpgpdump/parse/values"
)

// sub01 class for Image Attribute Sub-packet
type sub01 struct {
	subInfo
}

//newSubReserved return subInfo instance
func newSub01(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &sub01{subInfo{cxt: cxt, subID: subID, reader: reader.New(body)}}
}

// Parse parsing Image Attribute Sub-packet
func (s *sub01) Parse() (*result.Item, error) {
	rootInfo := s.ToItem()
	l, err := s.reader.ReadBytes(2)
	if err != nil {
		return rootInfo, errs.Wrap(err)
	}
	length := binary.BigEndian.Uint16(l)
	ver, err := s.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal version", errs.WithCause(err))
	}
	itm := result.NewItem(
		result.Name("Version"),
		result.Value(strconv.Itoa(int(ver))),
	)
	switch true {
	case ver == 1:
		itm.Note = ""
		rootInfo.Add(itm)
	case 100 <= ver && ver <= 110:
		itm.Note = "private or experimental use"
		rootInfo.Add(itm)
		enc, err := s.reader.ReadByte()
		if err != nil {
			return rootInfo, errs.New("illegal image encoding code", errs.WithCause(err))
		}
		itm = result.NewItem(
			result.Name("Encoding"),
			result.Note(fmt.Sprintf("(enc %d)", enc)),
		)
		if enc == 0x01 {
			itm.Value = "JPEG"
		} else {
			itm.Value = values.Unknown
		}
		rootInfo.Add(itm)
	default:
		itm.Note = values.Unknown
		rootInfo.Add(itm)
	}
	itm = result.NewItem(
		result.Name("Image data"),
		result.Note(fmt.Sprintf("%d bytes", s.reader.Len()-int(length))),
	)
	rootInfo.Add(itm)
	return rootInfo, nil
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
