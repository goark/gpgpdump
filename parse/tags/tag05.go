package tags

import (
	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/result"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/context"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/values"
)

// tag05 class for Secret-Key Packet
type tag05 struct {
	tagInfo
}

//newTag05 return tag05 instance
func newTag05(cxt *context.Context, tag values.TagID, body []byte) Tags {
	return &tag05{tagInfo{cxt: cxt, tag: tag, reader: reader.New(body)}}
}

// Parse parsing Secret-Key Packet
func (t *tag05) Parse() (*result.Item, error) {
	rootInfo := t.ToItem()
	// [00] One-octet version number.
	v, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal version", errs.WithCause(err))
	}
	version := values.PubVer(v)
	rootInfo.Add(version.ToItem(t.cxt.Debug()))

	pub := result.NewItem(result.Name("Public-Key"))
	rootInfo.Add(pub)
	pubkey := newPubkey(t.cxt, t.reader, version)
	if err := pubkey.Parse(pub); err != nil {
		return rootInfo, errs.Wrap(err)
	}

	sec := result.NewItem(result.Name("Secret-Key"))
	rootInfo.Add(sec)
	if err := newSeckey(t.cxt, t.reader, version, pubkey.PubID()).Parse(sec); err != nil {
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
