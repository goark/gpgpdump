package tags

import (
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

// tag08 class for Compressed Data Packet
type tag08 tagInfo

//newTag08 return tag08 instance
func newTag08(cxt *context.Context, tag values.TagID, body []byte) Tags {
	return &tag08{cxt: cxt, tag: tag, reader: reader.NewReader(body)}
}

// Parse parsing Compressed Data Packet
func (t *tag08) Parse() (*info.Item, error) {
	rootInfo := t.tag.ToItem(t.reader, t.cxt.Debug())
	compID, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, err
	}
	version := values.CompID(compID)
	rootInfo.Add(version.ToItem())

	if t.reader.Rest() > 0 {
		rootInfo.Add(values.RawData(t.reader, "Compressed data", t.cxt.Debug()))
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
