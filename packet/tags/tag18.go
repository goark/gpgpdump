package tags

import (
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

// tag18 class for TSym. Encrypted Integrity Protected Data Packet
type tag18 tagInfo

//NewTag18 return tag18 instance
func newTag18(cxt *context.Context, tag values.TagID, body []byte) Tags {
	return &tag18{cxt: cxt, tag: tag, reader: reader.New(body)}
}

// Parse parsing Sym. Encrypted Integrity Protected Data Packet
func (t *tag18) Parse() (*info.Item, error) {
	rootInfo := t.tag.ToItem(t.reader, t.cxt.Debug())
	itm := values.RawData(t.reader, "Encrypted data", t.cxt.Debug())
	switch true {
	case t.cxt.IsSymEnc():
		itm.Value = "sym alg is specified in sym-key encrypted session key; plain text + MDC SHA1(20 bytes)"
	case t.cxt.IsPubEnc():
		itm.Value = "sym alg is specified in pub-key encrypted session key"
	default:
	}
	rootInfo.Add(itm)

	t.cxt.ResetAlg()
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
