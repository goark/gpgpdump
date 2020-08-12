package tags

import (
	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/pubkey"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

// tag01 class for Public-Key Encrypted Session Key Packet
type tag01 struct {
	tagInfo
}

//newTag01 return tag01 instance
func newTag01(cxt *context.Context, tag values.TagID, body []byte) Tags {
	//func newTag01(cxt *context.Context, tag values.TagID, body []byte) *tag01 {
	return &tag01{tagInfo{cxt: cxt, tag: tag, reader: reader.New(body)}}
}

// Parse parsing tag01 instance
func (t *tag01) Parse() (*info.Item, error) {
	t.cxt.SetAlgPubEnc() //set Pubkey Encryption Mode
	rootInfo := t.ToItem()
	// [00] one-octet number giving the version number of the packet type.
	ver, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal version", errs.WithCause(err))
	}
	rootInfo.Add(values.PubSessKeyVer(ver).ToItem(t.cxt.Debug()))
	// [01] eight-octet number that gives the Key ID of the public key to which the session key is encrypted.
	keyid, err := t.reader.ReadBytes(8)
	if err != nil {
		return rootInfo, errs.New("illegal keyid", errs.WithCause(err))
	}
	rootInfo.Add(values.NewKeyID(keyid).ToItem())
	// [09] one-octet number giving the public-key algorithm used.
	pubid, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal pubid", errs.WithCause(err))
	}
	rootInfo.Add(values.PubID(pubid).ToItem(t.cxt.Debug()))
	// [10] string of octets that is the encrypted session key.
	if err := pubkey.New(t.cxt, values.PubID(pubid), t.reader).ParseSes(rootInfo); err != nil {
		return rootInfo, errs.Wrap(err)
	}

	if t.reader.Rest() > 0 {
		rootInfo.Add(values.RawData(t.reader, "Unknown data", t.cxt.Debug()))
	}
	return rootInfo, nil
}

/* Copyright 2016-2020 Spiegel
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
