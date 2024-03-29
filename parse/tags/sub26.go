package tags

import (
	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/result"
	"github.com/goark/gpgpdump/parse/values"
)

//sub26 class for Policy URI Sub-packet
type sub26 struct {
	subInfo
}

//newSub26 return sub26 instance
func newSub26(cxt *context.Context, subID values.SuboacketID, body []byte) Subs {
	return &sub26{subInfo{cxt: cxt, subID: subID, reader: reader.New(body)}}
}

// Parse parsing Policy URI Sub-packet
func (s *sub26) Parse() (*result.Item, error) {
	return values.NewText(s.reader.GetBody(), s.ToItem().Name).ToItem(s.cxt.Debug()), nil
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
