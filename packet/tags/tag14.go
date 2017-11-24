package tags

import (
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

// tag14 class for Public-Subkey Packet
type tag14 tagInfo

//newTag14 return tag14 instance
func newTag14(cxt *context.Context, tag values.TagID, body []byte) Tags {
	return &tag14{cxt: cxt, tag: tag, reader: reader.New(body)}
}

// Parse parsing Public-Subkey Packet
func (t *tag14) Parse() (*info.Item, error) {
	body, _ := t.reader.Read2EOF()
	return newTag06(t.cxt, t.tag, body).Parse() //redirect to Tag06
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
