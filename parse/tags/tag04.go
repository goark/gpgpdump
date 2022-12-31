package tags

import (
	"fmt"

	"github.com/goark/errs"

	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/result"
	"github.com/goark/gpgpdump/parse/values"
)

// tag04 class for One-Pass Signature Packet
type tag04 struct {
	tagInfo
}

// newTag04 return tag04 instance
func newTag04(cxt *context.Context, tag values.TagID, body []byte) Tags {
	return &tag04{tagInfo{cxt: cxt, tag: tag, reader: reader.New(body)}}
}

// Parse parsing One-Pass Signature Packet
func (t *tag04) Parse() (*result.Item, error) {
	rootInfo := t.ToItem()
	// [00] one-octet version number
	v, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal version", errs.WithCause(err))
	}
	version := values.OneSigVer(v)
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
	return rootInfo, nil
}

func (t *tag04) parseV3(rootInfo *result.Item) (*result.Item, error) {
	// [01] one-octet signature type
	sig, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal sigid", errs.WithCause(err))
	}
	rootInfo.Add(values.SigID(sig).ToItem(t.cxt.Debug()))
	// [02] one-octet number describing the hash algorithm used.
	hashid, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal hashid", errs.WithCause(err))
	}
	rootInfo.Add(values.HashID(hashid).ToItem(t.cxt.Debug()))
	// [03] one-octet number describing the public-key algorithm used.
	pubid, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal pubid", errs.WithCause(err))
	}
	rootInfo.Add(values.PubID(pubid).ToItem(t.cxt.Debug()))
	// [04] eight-octet number holding the Key ID of the signing key.
	keyid, err := t.reader.ReadBytes(8)
	if err != nil {
		return rootInfo, errs.New("illegal keyid", errs.WithCause(err))
	}
	rootInfo.Add(values.NewKeyID(keyid).ToItem())
	// [12] one-octet number holding a flag showing whether the signature.
	flag, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal flag", errs.WithCause(err))
	}
	f := "other than one pass signature"
	if flag == 0 {
		f = "another one pass signature"
	}
	rootInfo.Add(result.NewItem(
		result.Name("Encrypted session key"),
		result.Value(f),
		result.Note(fmt.Sprintf("flag %#02x", flag)),
	))
	return rootInfo, nil
}

func (t *tag04) parseV5(rootInfo *result.Item) (*result.Item, error) {
	// [01] one-octet signature type
	sig, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal sigid", errs.WithCause(err))
	}
	rootInfo.Add(values.SigID(sig).ToItem(t.cxt.Debug()))
	// [02] one-octet number describing the hash algorithm used.
	hashid, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal hashid", errs.WithCause(err))
	}
	rootInfo.Add(values.HashID(hashid).ToItem(t.cxt.Debug()))
	// [03] one-octet number describing the public-key algorithm used.
	pubid, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal pubid", errs.WithCause(err))
	}
	rootInfo.Add(values.PubID(pubid).ToItem(t.cxt.Debug()))
	// [04] 16 octet field containing random values used as salt.
	rv, err := t.reader.ReadBytes(16)
	if err != nil {
		return rootInfo, errs.New("illegal andom values used as salt", errs.WithCause(err))
	}
	rootInfo.Add(t.randomValue(rv))
	// [20] one octet key version number and N octets of the fingerprint of the signing key.
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
	// [21+N] one-octet number holding a flag showing whether the signature.
	flag, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal flag", errs.WithCause(err))
	}
	f := "other than one pass signature"
	if flag == 0 {
		f = "another one pass signature"
	}
	rootInfo.Add(result.NewItem(
		result.Name("Encrypted session key"),
		result.Value(f),
		result.Note(fmt.Sprintf("flag %#02x", flag)),
	))
	return rootInfo, nil
}

func (t *tag04) randomValue(rv []byte) *result.Item {
	return result.NewItem(
		result.Name("Random values used as salt"),
		result.DumpStr(values.DumpBytes(rv, true).String()),
	)
}

func (t *tag04) fingerprint(ver byte) (*result.Item, error) {
	if ver != 5 {
		return nil, errs.New("illegal key version number", errs.WithContext("key_version", int(ver)))
	}
	var n int64 = 32
	// [02] N octets of the fingerprint of the public key or subkey
	fp, err := t.reader.ReadBytes(n)
	if err != nil {
		return nil, errs.New("illegal length of the fingerprint", errs.WithCause(err))
	}
	return result.NewItem(
		result.Name("Fingerprint of the signing key"),
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
