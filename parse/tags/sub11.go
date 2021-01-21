package tags

import (
	"github.com/spiegel-im-spiegel/gpgpdump/parse/context"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/result"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/values"
)

//sub11 class for Preferred Symmetric Algorithms Sub-packet
type sub11 struct {
	subInfo
}

//newSub11 return sub11 instance
func newSub11(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &sub11{subInfo{cxt: cxt, subID: subID, reader: reader.New(body)}}
}

// Parse parsing Preferred Symmetric Algorithms Sub-packet
func (s *sub11) Parse() (*result.Item, error) {
	rootInfo := s.ToItem()
	for _, alg := range s.reader.GetBody() {
		rootInfo.Add(values.SymID(alg).ToItem(s.cxt.Debug()))
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
