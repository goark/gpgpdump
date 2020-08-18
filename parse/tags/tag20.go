package tags

import (
	"fmt"
	"strconv"

	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/result"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/context"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/values"
)

// tag20 class for AEAD Encrypted Data Packet Packet
type tag20 struct {
	tagInfo
}

//newTag20 return tag20 instance
func newTag20(cxt *context.Context, tag values.TagID, body []byte) Tags {
	return &tag20{tagInfo{cxt: cxt, tag: tag, reader: reader.New(body)}}
}

// Parse parsing AEAD Encrypted Data Packet Packet
func (t *tag20) Parse() (*result.Item, error) {
	rootInfo := t.ToItem()
	//A one-octet version number.  The only currently defined value is 1.
	v, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal version", errs.WithCause(err))
	}
	version := values.AEADVer(v)
	rootInfo.Add(version.ToItem(t.cxt.Debug()))
	//A one-octet cipher algorithm.
	alg, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal symid", errs.WithCause(err))
	}
	symid := values.SymID(alg)
	rootInfo.Add(symid.ToItem(t.cxt.Debug()))
	//A one-octet AEAD algorithm.
	alg, err = t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal aeadid", errs.WithCause(err))
	}
	aeadid := values.AEADID(alg)
	rootInfo.Add(aeadid.ToItem(t.cxt.Debug()))
	//A one-octet chunk size.
	c, err := t.reader.ReadByte()
	if err != nil {
		return rootInfo, errs.New("illegal chunk size", errs.WithCause(err))
	}
	chunkSize := uint64(1) << (c + 6)
	rootInfo.Add(result.NewItem(
		result.Name("Chunk size"),
		result.Value(strconv.FormatUint(chunkSize, 10)),
		result.DumpStr(values.DumpByteString(byte(c), true)),
	))
	//A starting initialization vector of size specified by the AEAD algorithm.
	iv, err := t.iv(aeadid)
	if err != nil {
		return rootInfo, nil
	}
	rootInfo.Add(iv)

	if t.reader.Rest() > 0 {
		rootInfo.Add(values.RawData(t.reader, "Encrypted data and authentication tag", t.cxt.Debug()))
	}
	return rootInfo, nil
}

func (t *tag20) iv(aeadid values.AEADID) (*result.Item, error) {
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

// func (t *tag20) tag(aeadid values.AEADID) (*result.Item, error) {
// 	sz64 := int64(aeadid.TagLen())
// 	tag, err := t.reader.ReadBytes(sz64)
// 	if err != nil {
// 		return nil, errs.Wrapf(err, "illegal authentication tag (length: %d bytes)", sz64)
// 	}
// 	return result.NewItem(
// 		result.Name("Summary authentication tag for the AEAD mode"),
// 		result.DumpStr(values.DumpBytes(tag, true).String()),
// 	), nil
// }

/* Copyright 2018-2020 Spiegel
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
