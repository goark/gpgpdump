package tags

import (
	"github.com/goark/errs"

	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/pubkey"
	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/result"
	"github.com/goark/gpgpdump/parse/values"
)

// tag01 class for Public-Key Encrypted Session Key Packet
type tag01 struct {
	tagInfo
}

// newTag01 return tag01 instance
func newTag01(cxt *context.Context, tag values.TagID, body []byte) Tags {
	//func newTag01(cxt *context.Context, tag values.TagID, body []byte) *tag01 {
	return &tag01{tagInfo{cxt: cxt, tag: tag, reader: reader.New(body)}}
}

// Parse parsing tag01 instance
func (t *tag01) Parse() (*result.Item, error) {
	t.cxt.SetAlgPubEnc() //set Pubkey Encryption Mode
	rootInfo := t.ToItem()
	// [00] one-octet number giving the version number of the packet type.
	v, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal version", errs.WithCause(err))
	}
	version := values.PubSessKeyVer(v)
	rootInfo.Add(version.ToItem(t.cxt.Debug()))
	switch true {
	case version.IsCurrent():
		_, err := t.parseV3(rootInfo)
		if err != nil {
			return rootInfo, errs.Wrap(err)
		}
	case version.IsDraft():
		_, err := t.parseV5(rootInfo)
		if err != nil {
			return rootInfo, errs.Wrap(err)
		}
	}

	if t.reader.Rest() > 0 {
		rootInfo.Add(values.RawData(t.reader, "Unknown data", t.cxt.Debug()))
	}
	return rootInfo, nil
}

func (t *tag01) parseV3(rootInfo *result.Item) (*result.Item, error) {
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
	return rootInfo, nil
}

func (t *tag01) parseV5(rootInfo *result.Item) (*result.Item, error) {
	// [01] one octet key version number
	v, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal key version number", errs.WithCause(err))
	}
	item, err := t.fingerprint(v)
	if err != nil {
		return rootInfo, err
	}
	if item != nil {
		rootInfo.Add(item)
	}
	// [01+N] one-octet number giving the public-key algorithm used.
	pubid, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal pubid", errs.WithCause(err))
	}
	rootInfo.Add(values.PubID(pubid).ToItem(t.cxt.Debug()))
	// [01+N+1] string of octets that is the encrypted session key.
	if err := pubkey.New(t.cxt, values.PubID(pubid), t.reader).ParseSes(rootInfo); err != nil {
		return rootInfo, errs.Wrap(err)
	}
	return rootInfo, nil
}

func (t *tag01) fingerprint(ver byte) (*result.Item, error) {
	var n int64 = 0
	switch ver {
	case 4:
		n = 20
	case 5:
		n = 32
	}
	if n == 0 {
		return nil, nil
	}
	// [02] N octets of the fingerprint of the public key or subkey
	fp, err := t.reader.ReadBytes(n)
	if err != nil {
		return nil, errs.New("illegal length of the fingerprint", errs.WithCause(err))
	}
	return result.NewItem(
		result.Name("Fingerprint of the public key or subkey"),
		result.DumpStr(values.DumpBytes(fp, true).String()),
	), nil
}

/* Copyright 2016-2022 Spiegel
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
