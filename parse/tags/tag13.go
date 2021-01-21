package tags

import (
	"github.com/spiegel-im-spiegel/gpgpdump/parse/context"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/result"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/values"
)

// tag13 class for User ID Packet
type tag13 struct {
	tagInfo
}

//newTag13 return tag13 instance
func newTag13(cxt *context.Context, tag values.TagID, body []byte) Tags {
	return &tag13{tagInfo{cxt: cxt, tag: tag, reader: reader.New(body)}}
}

// Parse parsing User ID Packet
func (t *tag13) Parse() (*result.Item, error) {
	rootInfo := t.ToItem()
	rootInfo.Add(values.NewText(t.reader.GetBody(), "User ID").ToItem(t.cxt.Debug()))
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
