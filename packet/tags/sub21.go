package tags

import (
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

//sub21 class for Preferred Hash Algorithms Sub-packet
type sub21 subInfo

//newSub21 return sub21 instance
func newSub21(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &sub21{cxt: cxt, subID: subID, reader: reader.NewReader(body)}
}

// Parse parsing Preferred Hash Algorithms Sub-packet
func (s *sub21) Parse() (*info.Item, error) {
	rootInfo := s.subID.ToItem(s.reader, s.cxt.Debug())
	algs, _ := s.reader.Read2EOF()
	for _, alg := range algs {
		rootInfo.Add(values.HashID(alg).ToItem(s.cxt.Debug()))
	}
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
