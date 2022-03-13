package tags

import (
	"io"
	"strconv"

	"github.com/goark/errs"

	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/result"
	"github.com/goark/gpgpdump/parse/values"
)

//sub38 class for Key Block Sub-packet
type sub38 struct {
	subInfo
}

//newSub38 return sub38 instance
func newSub38(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &sub38{subInfo{cxt: cxt, subID: subID, reader: reader.New(body)}}
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
		item := values.RawData(s.reader, "Key data", s.cxt.Debug())
		if err := s.parseKeyData(item); err != nil {
			return rootInfo, errs.New("illegal Key dtata in Key Block Sub-packet", errs.WithCause(err))
		}
		rootInfo.Add(item)
		//rootInfo.Add(values.RawData(s.reader, "Key data", true))
	default:
		rootInfo.Add(values.RawData(s.reader, "Key data", s.cxt.Debug()))
	}
	return rootInfo, nil
}

func (s *sub38) parseKeyData(rootInfo *result.Item) error {
	sp, err := NewPackets(s.cxt, s.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	for {
		if err := sp.Next(); err != nil {
			if !errs.Is(err, io.EOF) { //EOF is not error
				return errs.Wrap(err)
			}
			break
		}
		itm, err := sp.tag.Parse()
		if err != nil {
			return errs.Wrap(err)
		}
		rootInfo.Add(itm)
	}
	return nil
}

/* Copyright 2020 Spiegel
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
