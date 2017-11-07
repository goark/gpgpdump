package tags

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

// tag04 class for One-Pass Signature Packet
type tag04 tagInfo

//newTag04 return tag04 instance
func newTag04(cxt *context.Context, tag values.TagID, body []byte) Tags {
	return &tag04{cxt: cxt, tag: tag, reader: reader.NewReader(body)}
}

// Parse parsing tag04 instance
func (t *tag04) Parse() (*info.Item, error) {
	rootInfo := t.tag.ToItem(t.reader, t.cxt.Debug())
	// [00] one-octet version number
	v, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, err
	}
	version := values.OneSigVer(v)
	rootInfo.Add(version.ToItem(t.cxt.Debug()))
	// [01] one-octet signature type
	sig, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, err
	}
	rootInfo.Add(values.SigID(sig).ToItem(t.cxt.Debug()))
	// [02] one-octet number describing the hash algorithm used.
	hashid, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, err
	}
	rootInfo.Add(values.HashID(hashid).ToItem(t.cxt.Debug()))
	// [03] one-octet number describing the public-key algorithm used.
	pubid, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, err
	}
	rootInfo.Add(values.PubID(pubid).ToItem(t.cxt.Debug()))
	// [04] eight-octet number holding the Key ID of the signing key.
	keyid, err := t.reader.ReadBytes(8)
	if err != nil {
		return rootInfo, err
	}
	rootInfo.Add(values.NewKeyID(keyid).ToItem())
	// [12] one-octet number holding a flag showing whether the signature.
	flag, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, err
	}
	f := "other than one pass signature"
	if flag == 0 {
		f = "another one pass signature"
	}
	rootInfo.Add(info.NewItem(
		info.Name("Encrypted session key"),
		info.Value(f),
		info.Note(fmt.Sprintf("%02x", flag)),
	))

	if t.reader.Rest() > 0 {
		rootInfo.Add(values.RawData(t.reader, "Rest", t.cxt.Debug()))
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
