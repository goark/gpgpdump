package tags

import (
	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/result"
	"github.com/goark/gpgpdump/parse/values"
)

// tag12 class for Trust Packet
type tag12 struct {
	tagInfo
}

//newTag12 return tag12 instance
func newTag12(cxt *context.Context, tag values.TagID, body []byte) Tags {
	return &tag12{tagInfo{cxt: cxt, tag: tag, reader: reader.New(body)}}
}

// Parse parsing Trust Packet
func (t *tag12) Parse() (*result.Item, error) {
	rootInfo := t.ToItem()
	rootInfo.Add(values.RawData(t.reader, "Trust", true))
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
