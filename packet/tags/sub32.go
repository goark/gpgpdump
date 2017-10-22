package tags

import (
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

// sub32 class for Embedded Signature Sub-packet
type sub32 subInfo

//newSub32 return sub32 instance
func newSub32(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &sub32{cxt: cxt, subID: subID, reader: reader.NewReader(body)}
}

// Parse parsing Embedded Signature Sub-packet
func (s *sub32) Parse() (*info.Item, error) {
	rootInfo := s.subID.ToItem(s.reader, s.cxt.Debug())
	body, _ := s.reader.Read2EOF()
	itm, err := newTag02(s.cxt, values.TagID(2), body).Parse()
	if err != nil {
		return rootInfo, err
	}
	rootInfo.Add(itm)
	return rootInfo, nil
}

/* Copyright 2016 Spiegel
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
