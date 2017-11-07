package tags

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/s2k"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

//tag03 class for Symmetric-Key Encrypted Session Key Packet
type tag03 tagInfo

//newTag03 return tag03 instance
func newTag03(cxt *context.Context, tag values.TagID, body []byte) Tags {
	return &tag03{cxt: cxt, tag: tag, reader: reader.NewReader(body)}
}

// Parse parsing tag03 instance
func (t *tag03) Parse() (*info.Item, error) {
	t.cxt.SetAlgSymEnc()
	rootInfo := t.tag.ToItem(t.reader, t.cxt.Debug())
	// [00] one-octet version number
	v, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, err
	}
	rootInfo.Add(values.SymSessKeyVer(v).ToItem(t.cxt.Debug()))
	// [01] one-octet number describing the symmetric algorithm used.
	symid, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, err
	}
	rootInfo.Add(values.SymID(symid).ToItem(t.cxt.Debug()))
	// [02] string-to-key (S2K) specifier
	s2k := s2k.New(t.reader)
	if err := s2k.Parse(rootInfo, t.cxt.Debug()); err != nil {
		return rootInfo, err
	}

	if t.reader.Rest() > 0 {
		rst := t.reader.Rest()
		itm := values.RawData(t.reader, "Encrypted session key", t.cxt.Debug())
		itm.Note = fmt.Sprintf("sym alg(1 bytes) + session key (%d bytes)", rst)
		rootInfo.Add(itm)
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
