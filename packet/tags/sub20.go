package tags

import (
	"encoding/binary"
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

//sub20 class for Notation Data Sub-packet
type sub20 struct {
	subInfo
}

//newSub20 return sub20 instance
func newSub20(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &sub20{subInfo{cxt: cxt, subID: subID, reader: reader.New(body)}}
}

// Parse parsing Notation Data Sub-packet
func (s *sub20) Parse() (*info.Item, error) {
	rootInfo := s.ToItem()
	flags, err := s.reader.ReadBytes(8)
	if err != nil {
		return rootInfo, errs.Wrapf(err, "illegal flags in parsing sub packet %d", int(s.subID))
	}
	human := flags[0] & 0x80
	rootInfo.Add(values.Flag2Item(human, "Human-readable"))
	rootInfo.Add(values.Flag2Item(flags[0]&0x7f, fmt.Sprintf("Unknown flag1(%#02x)", flags[0]&0x7f)))
	rootInfo.Add(values.Flag2Item(flags[1], fmt.Sprintf("Unknown flag2(%#02x)", flags[1])))
	rootInfo.Add(values.Flag2Item(flags[2], fmt.Sprintf("Unknown flag3(%#02x)", flags[2])))
	rootInfo.Add(values.Flag2Item(flags[3], fmt.Sprintf("Unknown flag4(%#02x)", flags[3])))

	nameLength, err := s.reader.ReadBytes(2)
	if err != nil {
		return rootInfo, errs.Wrapf(err, "illegal length of name in parsing sub packet %d", int(s.subID))
	}
	valueLength, err := s.reader.ReadBytes(2)
	if err != nil {
		return rootInfo, errs.Wrapf(err, "illegal length of value in parsing sub packet %d", int(s.subID))
	}
	name, err := s.reader.ReadBytes(int64(binary.BigEndian.Uint16(nameLength)))
	if err != nil {
		return rootInfo, errs.Wrapf(err, "illegal name in parsing sub packet %d (length: %d bytes)", int(s.subID), nameLength)
	}
	rootInfo.Add(info.NewItem(
		info.Name("Name"),
		info.Value(string(name)),
	))
	value, err := s.reader.ReadBytes(int64(binary.BigEndian.Uint16(valueLength)))
	if err != nil {
		return rootInfo, errs.Wrapf(err, "illegal value in parsing sub packet %d (length: %d bytes)", int(s.subID), valueLength)
	}
	itm := info.NewItem(
		info.Name("Value"),
	)
	if human != 0x00 {
		itm.Value = string(value)
	} else {
		itm.Dump = values.DumpBytes(value, true).String()
	}
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
