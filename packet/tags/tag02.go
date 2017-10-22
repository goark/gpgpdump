package tags

import (
	"encoding/binary"
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/pubkey"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

// tag02 class for Signature Packet
type tag02 tagInfo

//newTag02 return tag02 instance
func newTag02(cxt *context.Context, tag values.TagID, body []byte) Tags {
	return &tag02{cxt: cxt, tag: tag, reader: reader.NewReader(body)}
}

// Parse parsing tag02 instance
func (t *tag02) Parse() (*info.Item, error) {
	rootInfo := t.tag.ToItem(t.reader, t.cxt.Debug())
	// [00] One-octet version number.
	v, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, err
	}
	version := values.SigVer(v)
	rootInfo.Add(version.ToItem())

	if version.IsOld() {
		_, err2 := t.parseV3(rootInfo)
		if err2 != nil {
			return rootInfo, err
		}
	} else if version.IsNew() {
		_, err2 := t.parseV4(rootInfo)
		if err2 != nil {
			return rootInfo, err
		}
	}

	if t.reader.Rest() > 0 {
		rootInfo.Add(values.RawData(t.reader, "Rest", t.cxt.Debug()))
	}
	return rootInfo, nil
}

func (t *tag02) parseV3(rootInfo *info.Item) (*info.Item, error) {
	//Structure of Signiture Packet (Ver3)
	// [00] One-octet version number (3).
	// [01] One-octet length of following hashed material.  MUST be 5.
	//      [02] One-octet signature type.
	//      [03] Four-octet creation time.
	sz, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, err
	}
	hm := info.NewItem(
		info.Name("Hashed material"),
		info.Note(fmt.Sprintf("%d bytes", sz)),
	)
	rootInfo.Add(hm)
	if sz != 5 {
		hm.Value = values.Unknown
		b, err2 := t.reader.ReadBytes(int64(sz))
		if err2 != nil {
			return rootInfo, err2
		}
		hm.Dump = values.DumpBytes(b, true).String()
	} else {
		sig, err2 := t.reader.ReadByte()
		if err2 != nil {
			return rootInfo, err2
		}
		hm.Add(values.SigID(sig).ToItem())
		tm, err2 := values.NewDateTime(t.reader, t.cxt.UTC())
		if err2 != nil {
			return rootInfo, err2
		}
		hm.Add(values.SigTimeItem(tm, true))
	}
	// [07] Eight-octet Key ID of signer.
	keyid, err := t.reader.ReadBytes(8)
	if err != nil {
		return rootInfo, err
	}
	rootInfo.Add(values.NewKeyID(keyid).ToItem())
	// [15] One-octet public-key algorithm.
	pubid, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, err
	}
	rootInfo.Add(values.PubID(pubid).ToItem())
	// [16] One-octet hash algorithm.
	hashid, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, err
	}
	rootInfo.Add(values.HashID(hashid).ToItem())
	// [17] Two-octet field holding left 16 bits of signed hash value.
	hv, err := t.reader.ReadBytes(2)
	if err != nil {
		return rootInfo, err
	}
	rootInfo.Add(t.hashLeft2(hv))
	// [19] One or more multiprecision integers comprising the signature.
	if err := pubkey.New(t.cxt, values.PubID(pubid), t.reader).ParseSig(rootInfo); err != nil {
		return rootInfo, err
	}
	return rootInfo, nil
}

func (t *tag02) parseV4(rootInfo *info.Item) (*info.Item, error) {
	// [00] One-octet version number (4).
	// [01] One-octet signature type.
	sig, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, err
	}
	rootInfo.Add(values.SigID(sig).ToItem())
	// [02] One-octet public-key algorithm.
	pubid, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, err
	}
	rootInfo.Add(values.PubID(pubid).ToItem())
	// [03] One-octet hash algorithm.
	hashid, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, err
	}
	rootInfo.Add(values.HashID(hashid).ToItem())
	// [04] Two-octet scalar octet count for following hashed subpacket data.(= HS)
	s, err := t.reader.ReadBytes(2)
	if err != nil {
		return rootInfo, err
	}
	sizeHS := binary.BigEndian.Uint16(s)
	// [06] Hashed subpacket data set (zero or more subpackets).
	if sizeHS > 0 {
		sp, err2 := t.reader.ReadBytes(int64(sizeHS))
		if err2 != nil {
			return rootInfo, err2
		}
		subpcket, err2 := newSubparser(t.cxt, t.tag, "Hashed Subpacket", sp)
		if err2 != nil {
			return rootInfo, err2
		}
		itm, err2 := subpcket.Parse()
		if err2 != nil {
			return rootInfo, err2
		}
		rootInfo.Add(itm)
	}
	// [06+HS] Two-octet scalar octet count for the following unhashed subpacket data.(= US)
	s, err = t.reader.ReadBytes(2)
	if err != nil {
		return rootInfo, err
	}
	sizeUS := binary.BigEndian.Uint16(s)
	// [08+HS] Unhashed subpacket data set (zero or more subpackets).
	if sizeUS > 0 {
		sp, err2 := t.reader.ReadBytes(int64(sizeUS))
		if err2 != nil {
			return rootInfo, err2
		}
		subpcket, err2 := newSubparser(t.cxt, t.tag, "Unhashed Subpacket", sp)
		if err2 != nil {
			return rootInfo, err2
		}
		itm, err2 := subpcket.Parse()
		if err2 != nil {
			return rootInfo, err2
		}
		rootInfo.Add(itm)
	}
	// [08+HS+US] Two-octet field holding the left 16 bits of the signed hash value.
	hv, err := t.reader.ReadBytes(2)
	if err != nil {
		return rootInfo, err
	}
	rootInfo.Add(t.hashLeft2(hv))
	// [10+HS+US] One or more multiprecision integers comprising the signature.
	if err := pubkey.New(t.cxt, values.PubID(pubid), t.reader).ParseSig(rootInfo); err != nil {
		return rootInfo, err
	}
	return rootInfo, nil
}

func (t *tag02) hashLeft2(hv []byte) *info.Item {
	return info.NewItem(
		info.Name("Hash left 2 bytes"),
		info.DumpStr(values.DumpBytes(hv, true).String()),
	)
	//return values.NewRawData("Hash left 2 bytes", "", h, true)
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
