package tags

import (
	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/result"
	"github.com/goark/gpgpdump/parse/values"
)

// tag21 class for Padding Packet
type tag21 struct {
	tagInfo
}

// newTag21 return tag21 instance
func newTag21(cxt *context.Context, tag values.TagID, body []byte) Tags {
	return &tag21{tagInfo{cxt: cxt, tag: tag, reader: reader.New(body)}}
}

// Parse parsing Unknown Packet
func (t *tag21) Parse() (*result.Item, error) {
	rootInfo := t.ToItem()
	itm := values.RawData(t.reader, "Padding data", t.cxt.Debug())
	rootInfo.Add(itm)
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
