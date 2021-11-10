package tags

import (
	"fmt"

	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/context"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/result"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/s2k"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/values"
)

//tag03 class for Symmetric-Key Encrypted Session Key Packet
type tag03 struct {
	tagInfo
}

//newTag03 return tag03 instance
func newTag03(cxt *context.Context, tag values.TagID, body []byte) Tags {
	return &tag03{tagInfo{cxt: cxt, tag: tag, reader: reader.New(body)}}
}

// Parse parsing tag03 instance
func (t *tag03) Parse() (*result.Item, error) {
	t.cxt.SetAlgSymEnc()
	rootInfo := t.ToItem()
	// [00] one-octet version number
	v, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal version", errs.WithCause(err))
	}
	version := values.SymSessKeyVer(v)
	rootInfo.Add(version.ToItem(t.cxt.Debug()))

	if version.IsCurrent() {
		_, err := t.parseV4(rootInfo)
		if err != nil {
			return rootInfo, errs.Wrap(err)
		}
	} else if version.IsDraft() {
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

func (t *tag03) parseV4(rootInfo *result.Item) (*result.Item, error) {
	// [00] one-octet version number
	// [01] one-octet number describing the symmetric algorithm used.
	symid, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal symid", errs.WithCause(err))
	}
	rootInfo.Add(values.SymID(symid).ToItem(t.cxt.Debug()))
	// [02] string-to-key (S2K) specifier
	s2k := s2k.New(t.reader)
	if err := s2k.Parse(rootInfo, t.cxt.Debug()); err != nil {
		return rootInfo, errs.New("illegal s2k", errs.WithCause(err))
	}
	return rootInfo, nil
}

func (t *tag03) parseV5(rootInfo *result.Item) (*result.Item, error) {
	// [00] one-octet version number
	// [01] one-octet cipher algorithm.
	symid, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal symid", errs.WithCause(err))
	}
	rootInfo.Add(values.SymID(symid).ToItem(t.cxt.Debug()))
	// [02] one-octet AEAD algorithm.
	aeadalg, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal aeadid", errs.WithCause(err))
	}
	aeadid := values.AEADID(aeadalg)
	rootInfo.Add(aeadid.ToItem(t.cxt.Debug()))
	// [03] string-to-key (S2K) specifier
	s2k := s2k.New(t.reader)
	if err := s2k.Parse(rootInfo, t.cxt.Debug()); err != nil {
		return rootInfo, errs.New("illegal s2k", errs.WithCause(err))
	}
	// [NN] A starting initialization vector of size specified by the AEAD algorithm.
	//A starting initialization vector of size specified by the AEAD algorithm.
	iv, err := t.iv(aeadid)
	if err != nil {
		return rootInfo, nil
	}
	rootInfo.Add(iv)
	// [NN] The encrypted session key itself, which is decrypted with the string-to-key object using the given cipher and AEAD mode.
	// [NN] An authentication tag for the AEAD mode.
	if t.reader.Rest() > 0 {
		rootInfo.Add(values.RawData(t.reader, "Encrypted data and authentication tag", t.cxt.Debug()))
	}

	return rootInfo, nil
}

func (t *tag03) iv(aeadid values.AEADID) (*result.Item, error) {
	sz64 := int64(aeadid.IVLen())
	iv, err := t.reader.ReadBytes(sz64)
	if err != nil {
		return nil, errs.New(fmt.Sprintf("illegal initialization vector (length: %d bytes)", sz64), errs.WithCause(err))
	}
	return result.NewItem(
		result.Name("IV"),
		result.DumpStr(values.DumpBytes(iv, true).String()),
	), nil
}

/* Copyright 2016-2021 Spiegel
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
