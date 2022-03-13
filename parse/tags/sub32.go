package tags

import (
	"github.com/goark/errs"

	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/result"
	"github.com/goark/gpgpdump/parse/values"
)

// sub32 class for Embedded Signature Sub-packet
type sub32 struct {
	subInfo
}

//newSub32 return sub32 instance
func newSub32(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &sub32{subInfo{cxt: cxt, subID: subID, reader: reader.New(body)}}
}

// Parse parsing Embedded Signature Sub-packet
func (s *sub32) Parse() (*result.Item, error) {
	rootInfo := s.ToItem()
	itm, err := newTag02(s.cxt, values.TagID(2), s.reader.GetBody()).Parse()
	if err != nil {
		return rootInfo, errs.New("illegal Embedded Signature packet", errs.WithCause(err))
	}
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
