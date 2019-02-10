package tags

import (
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

// tagPrivate class for Unknown Packet
type tagPrivate struct {
	tagInfo
}

//NewTagUnknown return Unknown instance
func newTagPrivate(cxt *context.Context, tag values.TagID, body []byte) Tags {
	return &tagPrivate{tagInfo{cxt: cxt, tag: tag, reader: reader.New(body)}}
}

//ToItem returns info.Item instance
func (t *tagPrivate) ToItem() *info.Item {
	return t.tag.ToItem(t.reader, t.cxt.Private())
}

// Parse parsing Unknown Packet
func (t *tagPrivate) Parse() (*info.Item, error) {
	rootInfo := t.ToItem()
	return rootInfo, nil
}

/* Copyright 2017-2019 Spiegel
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
