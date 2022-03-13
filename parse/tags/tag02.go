package tags

import (
	"encoding/binary"
	"fmt"

	"github.com/goark/errs"

	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/pubkey"
	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/result"
	"github.com/goark/gpgpdump/parse/values"
)

// tag02 class for Signature Packet
type tag02 struct {
	tagInfo
}

//newTag02 return tag02 instance
func newTag02(cxt *context.Context, tag values.TagID, body []byte) Tags {
	return &tag02{tagInfo{cxt: cxt, tag: tag, reader: reader.New(body)}}
}

// Parse parsing tag02 instance
func (t *tag02) Parse() (*result.Item, error) {
	rootInfo := t.ToItem()
	// [00] One-octet version number.
	v, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal version", errs.WithCause(err))
	}
	version := values.SigVer(v)
	rootInfo.Add(version.ToItem(t.cxt.Debug()))

	switch true {
	case version.IsDraft():
		_, err := t.parseV5(rootInfo)
		if err != nil {
			return rootInfo, errs.Wrap(err)
		}
	case version.IsCurrent():
		_, err := t.parseV4(rootInfo)
		if err != nil {
			return rootInfo, errs.Wrap(err)
		}
	case version.IsOld():
		if version.Number() == 3 {
			_, err2 := t.parseV3(rootInfo)
			if err2 != nil {
				return rootInfo, errs.Wrap(err)
			}
		}
	}

	if t.reader.Rest() > 0 {
		rootInfo.Add(values.RawData(t.reader, "Unknown data", t.cxt.Debug()))
	}
	return rootInfo, nil
}

func (t *tag02) parseV3(rootInfo *result.Item) (*result.Item, error) {
	//Structure of Signiture Packet (Ver3)
	// [00] One-octet version number (3).
	// [01] One-octet length of following hashed material.  MUST be 5.
	//      [02] One-octet signature type.
	//      [03] Four-octet creation time.
	sz, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal hashed material", errs.WithCause(err))
	}
	hm := result.NewItem(
		result.Name("Hashed material"),
		result.Note(fmt.Sprintf("%d bytes", sz)),
	)
	rootInfo.Add(hm)
	if sz != 5 {
		hm.Value = values.Unknown
		b, err := t.reader.ReadBytes(int64(sz))
		if err != nil {
			return rootInfo, errs.New(fmt.Sprintf("illegal hashed material (size %d bytes)", sz), errs.WithCause(err))
		}
		hm.Dump = values.DumpBytes(b, t.cxt.Debug()).String()
	} else {
		sig, err := t.reader.ReadByte()
		if err != nil {
			return rootInfo, errs.New("illegal hashed material (sig id)", errs.WithCause(err))
		}
		hm.Add(values.SigID(sig).ToItem(t.cxt.Debug()))
		tm, err := values.NewDateTime(t.reader, t.cxt.UTC())
		if err != nil {
			return rootInfo, errs.New("illegal hashed material (creation time)", errs.WithCause(err))
		}
		hm.Add(values.SigTimeItem(tm, t.cxt.Debug()))
	}
	// [07] Eight-octet Key ID of signer.
	keyid, err := t.reader.ReadBytes(8)
	if err != nil {
		return rootInfo, errs.New("illegal keyid", errs.WithCause(err))
	}
	rootInfo.Add(values.NewKeyID(keyid).ToItem())
	// [15] One-octet public-key algorithm.
	pubid, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal pubid", errs.WithCause(err))
	}
	rootInfo.Add(values.PubID(pubid).ToItem(t.cxt.Debug()))
	// [16] One-octet hash algorithm.
	hashid, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal hashid", errs.WithCause(err))
	}
	rootInfo.Add(values.HashID(hashid).ToItem(t.cxt.Debug()))
	// [17] Two-octet field holding left 16 bits of signed hash value.
	hv, err := t.reader.ReadBytes(2)
	if err != nil {
		return rootInfo, errs.New("illegal hash value", errs.WithCause(err))
	}
	rootInfo.Add(t.hashLeft2(hv))
	// [19] One or more multiprecision integers comprising the signature.
	if err := pubkey.New(t.cxt, values.PubID(pubid), t.reader).ParseSig(rootInfo); err != nil {
		return rootInfo, errs.Wrap(err)
	}
	return rootInfo, nil
}

func (t *tag02) parseV4(rootInfo *result.Item) (*result.Item, error) {
	// [00] One-octet version number (4).
	// [01] One-octet signature type.
	sig, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal sigid", errs.WithCause(err))
	}
	rootInfo.Add(values.SigID(sig).ToItem(t.cxt.Debug()))
	// [02] One-octet public-key algorithm.
	pubid, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal pubid", errs.WithCause(err))
	}
	rootInfo.Add(values.PubID(pubid).ToItem(t.cxt.Debug()))
	// [03] One-octet hash algorithm.
	hashid, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal hashid", errs.WithCause(err))
	}
	rootInfo.Add(values.HashID(hashid).ToItem(t.cxt.Debug()))
	// [04] Two-octet scalar octet count for following hashed subpacket data.(= HS)
	s, err := t.reader.ReadBytes(2)
	if err != nil {
		return rootInfo, errs.New("illegal length of hashed subpacket", errs.WithCause(err))
	}
	sizeHS := binary.BigEndian.Uint16(s)
	// [06] Hashed subpacket data set (zero or more subpackets).
	if sizeHS > 0 {
		sp, err := t.reader.ReadBytes(int64(sizeHS))
		if err != nil {
			return rootInfo, errs.New(fmt.Sprintf("illegal hashed subpacket (size: %d bytes)", int64(sizeHS)), errs.WithCause(err))
		}
		subpcket, err := newSubparser(t.cxt, t.tag, "Hashed Subpacket", sp)
		if err != nil {
			return rootInfo, errs.New("illegal subpacket", errs.WithCause(err))
		}
		itm, err := subpcket.Parse()
		if err != nil {
			return rootInfo, errs.Wrap(err)
		}
		rootInfo.Add(itm)
	}
	// [06+HS] Two-octet scalar octet count for the following unhashed subpacket data.(= US)
	s, err = t.reader.ReadBytes(2)
	if err != nil {
		return rootInfo, errs.Wrap(err)
	}
	sizeUS := binary.BigEndian.Uint16(s)
	// [08+HS] Unhashed subpacket data set (zero or more subpackets).
	if sizeUS > 0 {
		sp, err := t.reader.ReadBytes(int64(sizeUS))
		if err != nil {
			return rootInfo, errs.New(fmt.Sprintf("illegal unhashed subpacket (size: %d bytes)", int64(sizeUS)), errs.WithCause(err))
		}
		subpcket, err := newSubparser(t.cxt, t.tag, "Unhashed Subpacket", sp)
		if err != nil {
			return rootInfo, errs.New("illegal subpacket", errs.WithCause(err))
		}
		itm, err := subpcket.Parse()
		if err != nil {
			return rootInfo, errs.Wrap(err)
		}
		rootInfo.Add(itm)
	}
	// [08+HS+US] Two-octet field holding the left 16 bits of the signed hash value.
	hv, err := t.reader.ReadBytes(2)
	if err != nil {
		return rootInfo, errs.New("illegal hash value", errs.WithCause(err))
	}
	rootInfo.Add(t.hashLeft2(hv))
	// [10+HS+US] One or more multiprecision integers comprising the signature.
	if err := pubkey.New(t.cxt, values.PubID(pubid), t.reader).ParseSig(rootInfo); err != nil {
		return rootInfo, errs.Wrap(err)
	}
	return rootInfo, nil
}

func (t *tag02) parseV5(rootInfo *result.Item) (*result.Item, error) {
	return t.parseV4(rootInfo)
}

func (t *tag02) hashLeft2(hv []byte) *result.Item {
	return result.NewItem(
		result.Name("Hash left 2 bytes"),
		result.DumpStr(values.DumpBytes(hv, true).String()),
	)
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
