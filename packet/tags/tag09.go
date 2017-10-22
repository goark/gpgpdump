package tags

import (
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

// tag09 class for Symmetrically Encrypted Data Packet
type tag09 tagInfo

//newTag09 return Tag01 instance
func newTag09(cxt *context.Context, tag values.TagID, body []byte) Tags {
	return &tag09{cxt: cxt, tag: tag, reader: reader.NewReader(body)}
}

// Parse parsing Symmetrically Encrypted Data Packet
func (t *tag09) Parse() (*info.Item, error) {
	rootInfo := t.tag.ToItem(t.reader, t.cxt.Debug())
	itm := values.RawData(t.reader, "Encrypted data", t.cxt.Debug())
	switch true {
	case t.cxt.IsSymEnc():
		itm.Note = "sym alg is specified in sym-key encrypted session key"
	case t.cxt.IsPubEnc():
		itm.Note = "sym alg is specified in pub-key encrypted session key"
	default:
		itm.Note = "sym alg is IDEA, simple string-to-key"
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
