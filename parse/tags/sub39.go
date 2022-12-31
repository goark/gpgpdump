package tags

import (
	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/result"
	"github.com/goark/gpgpdump/parse/values"
)

// sub38 Preferred AEAD Ciphersuites Sub-packet
type sub39 struct {
	subInfo
}

// newSub39 return sub39 instance
func newSub39(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &sub39{subInfo{cxt: cxt, subID: subID, reader: reader.New(body)}}
}

// Parse parsing Preferred AEAD Ciphersuites Sub-packet
func (s *sub39) Parse() (*result.Item, error) {
	rootInfo := s.ToItem()
	body := s.reader.GetBody()
	for i := 0; i < len(body); i += 2 {
		rootInfo.Add(values.SymID(body[i]).ToItem(s.cxt.Debug()))
		if i+1 < len(body) {
			rootInfo.Add(values.AEADID(body[i+1]).ToItem(s.cxt.Debug()))
		}
	}
	return rootInfo, nil
}

/* Copyright 2022 Spiegel
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
