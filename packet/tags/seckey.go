package tags

import (
	"encoding/binary"
	"fmt"

	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/pubkey"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/s2k"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

//seckeyInfo class for parsing Secret-key in Tag05
type seckeyInfo struct {
	cxt    *context.Context
	reader *reader.Reader
	pubVer *values.Version
	pubID  values.PubID
}

//newSeckey returns seckeyInfo instance
func newSeckey(cxt *context.Context, reader *reader.Reader, pubVer *values.Version, pubID values.PubID) *seckeyInfo {
	return &seckeyInfo{cxt: cxt, reader: reader, pubVer: pubVer, pubID: pubID}
}

//Parse Secret-key packet
func (p *seckeyInfo) Parse(parent *info.Item) error {
	usage, err := p.reader.ReadByte()
	if err != nil {
		return errs.Wrap(err, "illegal s2k usage")
	}

	if rOpt, err := p.getField1(); err != nil {
		return err
	} else if rOpt != nil {
		//[Optional] If string-to-key usage octet was 255, 254, or 253, a one-octet symmetric encryption algorithm.
		var symid values.SymID
		if usage != 0 { //encrypted secret-key
			alg, err := rOpt.ReadByte()
			if err != nil {
				return errs.Wrap(
					err,
					"illegal symid",
					errs.WithContext("s2k_usage", usage),
				)
			}
			symid = values.SymID(alg)
			parent.Add(symid.ToItem(p.cxt.Debug()))
		}
		//[Optional] If string-to-key usage octet was 253, a one-octet AEAD algorithm.
		if usage == 253 {
			alg, err := rOpt.ReadByte()
			if err != nil {
				return errs.Wrap(
					err,
					"illegal AEAD",
					errs.WithContext("s2k_usage", usage),
				)
			}
			parent.Add(values.AEADID(alg).ToItem(p.cxt.Debug()))
		}
		//[Optional] If string-to-key usage octet was 255, 254, or 253, a string-to-key specifier.
		hasIV := false
		switch usage {
		case 0:
		case 253, 254, 255:
			s2k := s2k.New(rOpt)
			if err := s2k.Parse(parent, p.cxt.Debug()); err != nil {
				return errs.Wrap(
					err,
					"illegal s2k",
					errs.WithContext("s2k_usage", usage),
				)
			}
			hasIV = s2k.HasIV()
		default:
			hasIV = true
		}
		//[Optional] If secret data is encrypted (string-to-key usage octet not zero), an Initial Vector (IV) of the same length as the cipher's block size.
		if usage != 0 && hasIV {
			iv, err := p.iv(values.SymID(symid), usage == 253)
			if err != nil {
				return err
			}
			parent.Add(iv)
		}

		if p.pubVer.Number() == 5 {
			if rOpt.Rest() > 0 {
				parent.Add(values.RawData(rOpt, "Unknown data", p.cxt.Debug()))
			}
		}
	}

	if rOpt, err := p.getField2(); err != nil {
		return err
	} else if rOpt != nil {
		switch usage {
		case 0:
			parent.Note = "s2k usage 0; plain secret-key material"
			//parse plain key material
			if err := pubkey.New(p.cxt, p.pubID, rOpt).ParseSecPlain(parent); err != nil {
				return errs.Wrap(
					err,
					"",
					errs.WithContext("s2k_usage", usage),
				)
			}
			//checksum
			chk, err := p.reader.ReadBytes(2)
			if err != nil {
				return errs.Wrap(err, "illegal checksum value")
			}
			parent.Add(info.NewItem(
				info.Name("2-octet checksum"),
				info.DumpStr(values.DumpBytes(chk, true).String()),
			))
		case 253:
			parent.Note = "s2k usage 253; encrypted secret-key material and AEAD authentication tag"
			if err := pubkey.New(p.cxt, p.pubID, rOpt).ParseSecEnc(parent); err != nil {
				return errs.Wrap(
					err,
					"illegal pubkey",
					errs.WithContext("s2k_usage", usage),
				)
			}
		case 254:
			parent.Note = "s2k usage 254; encrypted secret-key material and 20-octet SHA-1 hash"
			if err := pubkey.New(p.cxt, p.pubID, rOpt).ParseSecEnc(parent); err != nil {
				return errs.Wrap(
					err,
					"illegal pubkey",
					errs.WithContext("s2k_usage", usage),
				)
			}
		default:
			parent.Note = fmt.Sprintf("s2k usage %d; encrypted secret-key material and 2-octet checksum", usage)
			if err := pubkey.New(p.cxt, p.pubID, rOpt).ParseSecEnc(parent); err != nil {
				return errs.Wrap(
					err,
					"illegal pubkey",
					errs.WithContext("s2k_usage", usage),
				)
			}
		}

		if p.pubVer.Number() == 5 {
			if rOpt.Rest() > 0 {
				parent.Add(values.RawData(rOpt, "Unknown data", p.cxt.Debug()))
			}
		}
	}
	return nil
}

//getField1 returns reader.Reader for optional fields
func (p *seckeyInfo) getField1() (*reader.Reader, error) {
	if p.pubVer.Number() == 5 {
		l, err := p.reader.ReadByte()
		if err != nil {
			return nil, errs.Wrap(err, "illegal length of option field")
		}
		if l == 0 {
			return nil, nil
		}
		b, err := p.reader.ReadBytes(int64(l))
		if err != nil {
			return nil, errs.Wrap(err, "illegal option field")
		}
		return reader.New(b), nil
	}
	return p.reader, nil
}

//getField2 returns reader.Reader for secret key material
func (p *seckeyInfo) getField2() (*reader.Reader, error) {
	if p.pubVer.Number() == 5 {
		l, err := p.reader.ReadBytes(4)
		ll := binary.BigEndian.Uint32(l)
		if err != nil {
			return nil, errs.Wrap(err, "illegal length of key materia")
		}
		if ll == 0 {
			return nil, nil
		}
		b, err := p.reader.ReadBytes(int64(ll))
		if err != nil {
			return nil, errs.Wrap(err, "illegal key materia")
		}
		return reader.New(b), nil
	}
	return p.reader, nil
}

//iv returns info.Item for Initialization Vector
func (p *seckeyInfo) iv(symid values.SymID, isAEAD bool) (*info.Item, error) {
	sz64 := int64(symid.IVLen())
	iv, err := p.reader.ReadBytes(sz64)
	if err != nil {
		return nil, errs.Wrap(
			err,
			fmt.Sprintf("illegal s2k iv (length: %d bytes)", sz64),
		)
	}
	var name string
	if isAEAD {
		name = "nonce for the AEAD"

	} else {
		name = "IV"
	}
	return info.NewItem(
		info.Name(name),
		info.DumpStr(values.DumpBytes(iv, true).String()),
	), nil
}

/* Copyright 2016-2019 Spiegel
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
