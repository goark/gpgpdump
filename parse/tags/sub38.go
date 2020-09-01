package tags

import (
	"strconv"

	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/context"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/result"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/values"
)

//sub38 class for Key Block Sub-packet
type sub38 struct {
	subInfo
}

//newSub38 return sub38 instance
func newSub38(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &subReserved{subInfo{cxt: cxt, subID: subID, reader: reader.New(body)}}
}

// Parse parsing Key Block Sub-packet
func (s *sub38) Parse() (*result.Item, error) {
	rootInfo := s.ToItem()
	v, err := s.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal Type in Key Block Sub-packet", errs.WithCause(err))
	}
	rootInfo.Add(result.NewItem(
		result.Name("Type"),
		result.Value(strconv.Itoa(int(v))),
	))
	switch v {
	case 0x00:
		//TODO: recursive call ?
		rootInfo.Add(values.RawData(s.reader, "Key data", true))
	default:
		rootInfo.Add(values.RawData(s.reader, "Key data", s.cxt.Debug()))
	}
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
