package tags

import (
	"encoding/binary"
	"strconv"

	"github.com/pkg/errors"
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/context"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/pubkey"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

//pubkeyInfo class for parsing Public-key packet in Tag05 and Tag06
type pubkeyInfo struct {
	cxt    *context.Context
	reader *reader.Reader
	pubVer *values.Version
	pubID  values.PubID
}

//newPubkey returns pubkey instance
func newPubkey(cxt *context.Context, reader *reader.Reader, pubVer *values.Version) *pubkeyInfo {
	return &pubkeyInfo{cxt: cxt, reader: reader, pubVer: pubVer}
}

//Parse Public-key packet
func (p *pubkeyInfo) Parse(parent *info.Item) error {
	if p.pubVer.IsCurrent() {
		return p.parseV4(parent)
	} else if p.pubVer.IsOld() {
		switch p.pubVer.Number() {
		case 3:
			return p.parseV3(parent)
		default:
		}
	}
	return nil
}

func (p *pubkeyInfo) parseV3(parent *info.Item) error {
	//Structure of Signiture Packet (Ver3)
	// [01] four-octet number denoting the time that the key was created.
	tm, err := values.NewDateTime(p.reader, p.cxt.UTC())
	if err != nil {
		return errors.Wrap(err, "error in tags.pubkey,parseV3() function (Key Creation Time)")
	}
	p.cxt.KeyCreationTime = tm
	parent.Add(values.PubKeyTimeItem(tm, true))
	// [05] two-octet number denoting the time in days that this key is valid.
	days, err := p.reader.ReadBytes(2)
	if err != nil {
		return errors.Wrap(err, "error in tags.pubkey,parseV3() function (Valid days)")
	}
	parent.Add(info.NewItem(
		info.Name("Valid days"),
		info.Value(strconv.Itoa(int(binary.BigEndian.Uint16(days)))),
		info.Note("0 is forever"),
	))
	// [07] one-octet number denoting the public-key algorithm of this key.
	pubid, err := p.reader.ReadByte()
	if err != nil {
		return errors.Wrap(err, "error in tags.pubkey,parseV3() function (pub id)")
	}
	p.pubID = values.PubID(pubid)
	parent.Add(p.pubID.ToItem(p.cxt.Debug()))
	// [08] series of multiprecision integers comprising the key material
	return pubkey.New(p.cxt, p.pubID, p.reader).ParsePub(parent)
}

func (p *pubkeyInfo) parseV4(parent *info.Item) error {
	//Structure of Signiture Packet (Ver4)
	// [01] four-octet number denoting the time that the key was created.
	tm, err := values.NewDateTime(p.reader, p.cxt.UTC())
	if err != nil {
		return errors.Wrap(err, "error in tags.pubkey,parseV4() function (Key Creation Time)")
	}
	p.cxt.KeyCreationTime = tm
	parent.Add(values.PubKeyTimeItem(tm, true))
	// [05] one-octet number denoting the public-key algorithm of this key.
	pubid, err := p.reader.ReadByte()
	if err != nil {
		return errors.Wrap(err, "error in tags.pubkey,parseV3() function (pub id)")
	}
	p.pubID = values.PubID(pubid)
	parent.Add(p.pubID.ToItem(p.cxt.Debug()))
	// [06] series of multiprecision integers comprising the key material.
	return pubkey.New(p.cxt, p.pubID, p.reader).ParsePub(parent)
}

//PubID returns pubID
func (p *pubkeyInfo) PubID() values.PubID {
	return p.pubID
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
