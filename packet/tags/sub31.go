package tags

import (
	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

//sub31 class for Signature Target Sub-packet
type sub31 struct {
	subInfo
}

//newSub31 return sub31 instance
func newSub31(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &sub31{subInfo{cxt: cxt, subID: subID, reader: reader.New(body)}}
}

// Parse parsing Signature Target Sub-packet
func (s *sub31) Parse() (*info.Item, error) {
	rootInfo := s.ToItem()
	pubid, err := s.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.Wrapf(err, "illegal pubid in parsing sub packet %d", int(s.subID))
	}
	rootInfo.Add(values.PubID(pubid).ToItem(s.cxt.Debug()))
	hashid, err := s.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.Wrapf(err, "illegal hashid in parsing sub packet %d", int(s.subID))
	}
	rootInfo.Add(values.HashID(hashid).ToItem(s.cxt.Debug()))
	rootInfo.Add(values.RawData(s.reader, "Hash", true))
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
