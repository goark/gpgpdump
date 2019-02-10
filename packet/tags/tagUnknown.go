package tags

import (
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

// tagUnknown class for Unknown Packet
type tagUnknown struct {
	tagInfo
}

//NewTagUnknown return Unknown instance
func newTagUnknown(cxt *context.Context, tag values.TagID, body []byte) Tags {
	return &tagUnknown{tagInfo{cxt: cxt, tag: tag, reader: reader.New(body)}}
}

// Parse parsing Unknown Packet
func (t *tagUnknown) Parse() (*info.Item, error) {
	rootInfo := t.ToItem()
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
