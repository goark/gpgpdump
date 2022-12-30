package tags

import (
	"strconv"

	"github.com/goark/errs"
	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/result"
	"github.com/goark/gpgpdump/parse/values"
)

// tag18 class for TSym. Encrypted Integrity Protected Data Packet
type tag18 struct {
	tagInfo
}

// NewTag18 return tag18 instance
func newTag18(cxt *context.Context, tag values.TagID, body []byte) Tags {
	return &tag18{tagInfo{cxt: cxt, tag: tag, reader: reader.New(body)}}
}

// Parse parsing Sym. Encrypted Integrity Protected Data Packet
func (t *tag18) Parse() (*result.Item, error) {
	rootInfo := t.ToItem()
	// [00] one-octet version number
	v, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal version", errs.WithCause(err))
	}
	switch v {
	case 1:
		_, err := t.parseV1(rootInfo)
		if err != nil {
			return rootInfo, errs.Wrap(err, errs.WithContext("version_number", int(v)))
		}
	case 2:
		_, err := t.parseV2(rootInfo)
		if err != nil {
			return rootInfo, errs.Wrap(err, errs.WithContext("version_number", int(v)))
		}
	}

	t.cxt.ResetAlg()
	return rootInfo, nil
}

func (t *tag18) parseV1(rootInfo *result.Item) (*result.Item, error) {
	// [00] one-octet version number
	// [01] Encrypted data, the output of the selected symmetric-key cipher operating in Cipher Feedback mode with shift amount equal to the block size of the cipher (CFB-n where n is the block size).
	itm := values.RawData(t.reader, "Encrypted data", t.cxt.Debug())
	switch true {
	case t.cxt.IsSymEnc():
		itm.Note = "plain text + MDC SHA1(20 bytes); sym alg is specified in sym-key encrypted session key"
	case t.cxt.IsPubEnc():
		itm.Note = "plain text + MDC SHA1(20 bytes); sym alg is specified in pub-key encrypted session key"
	default:
	}
	rootInfo.Add(itm)
	return rootInfo, nil
}

func (t *tag18) parseV2(rootInfo *result.Item) (*result.Item, error) {
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
	rootInfo.Add(values.AEADID(aeadalg).ToItem(t.cxt.Debug()))
	// [03] one-octet chunk size.
	sz, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal chunk size", errs.WithCause(err))
	}
	rootInfo.Add(result.NewItem(
		result.Name("chunk size"),
		result.Value(strconv.Itoa(int(sz))),
	))
	// [04] Thirty-two octets of salt.
	s, err := t.reader.ReadBytes(32)
	if err != nil {
		return rootInfo, errs.New("illegal salt", errs.WithCause(err))
	}
	rootInfo.Add(result.NewItem(
		result.Name("salt"),
		result.DumpStr(values.DumpBytes(s, true).String()),
	))
	itm := values.RawData(t.reader, "Encrypted data", t.cxt.Debug())
	switch true {
	case t.cxt.IsSymEnc():
		itm.Note = "sym alg is specified in sym-key encrypted session key, operating in the AEAD mode"
	case t.cxt.IsPubEnc():
		itm.Note = "sym alg is specified in pub-key encrypted session key, operating in the AEAD mode"
	default:
	}
	rootInfo.Add(itm)
	return rootInfo, nil
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
