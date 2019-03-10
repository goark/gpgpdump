package tags

import (
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/spiegel-im-spiegel/gpgpdump/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
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
func (s *sub01) Parse() (*info.Item, error) {
	rootInfo := s.ToItem()
	l, err := s.reader.ReadBytes(2)
	if err != nil {
		return rootInfo, errs.Wrapf(err, "error in parsing sub packet %d", int(s.subID))
	}
	length := binary.BigEndian.Uint16(l)
	ver, err := s.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.Wrapf(err, "illegal version in parsing sub packet %d", int(s.subID))
	}
	itm := info.NewItem(
		info.Name("Version"),
		info.Value(strconv.Itoa(int(ver))),
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
			return rootInfo, errs.Wrapf(err, "illegal image encoding code in parsing sub packet %d", int(s.subID))
		}
		itm = info.NewItem(
			info.Name("Encoding"),
			info.Note(fmt.Sprintf("(enc %d)", enc)),
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
	itm = info.NewItem(
		info.Name("Image data"),
		info.Note(fmt.Sprintf("%d bytes", s.reader.Len()-int(length))),
	)
	rootInfo.Add(itm)
	return rootInfo, nil
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
