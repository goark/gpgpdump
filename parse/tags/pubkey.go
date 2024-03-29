package tags

import (
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/goark/errs"

	"github.com/goark/gpgpdump/parse/context"
	"github.com/goark/gpgpdump/parse/pubkey"
	"github.com/goark/gpgpdump/parse/reader"
	"github.com/goark/gpgpdump/parse/result"
	"github.com/goark/gpgpdump/parse/values"
)

// pubkeyInfo class for parsing Public-key packet in Tag05 and Tag06
type pubkeyInfo struct {
	cxt    *context.Context
	reader *reader.Reader
	pubVer *values.Version
	pubID  values.PubID
}

// newPubkey returns pubkey instance
func newPubkey(cxt *context.Context, reader *reader.Reader, pubVer *values.Version) *pubkeyInfo {
	return &pubkeyInfo{cxt: cxt, reader: reader, pubVer: pubVer}
}

// Parse Public-key packet
func (p *pubkeyInfo) Parse(parent *result.Item) error {
	switch true {
	case p.pubVer.IsDraft():
		return p.parseV5(parent)
	case p.pubVer.IsCurrent():
		return p.parseV4(parent)
	case p.pubVer.IsOld():
		switch p.pubVer.Number() {
		case 3:
			return p.parseV3(parent)
		default:
		}
	default:
	}
	return nil
}

// parseV3 parses V3 packet
func (p *pubkeyInfo) parseV3(parent *result.Item) error {
	//Structure of Signiture Packet (Ver3)
	// [01] four-octet number denoting the time that the key was created.
	tm, err := values.NewDateTime(p.reader, p.cxt.UTC())
	if err != nil {
		return errs.New("illegal Key Creation Time", errs.WithCause(err))
	}
	p.cxt.KeyCreationTime = tm
	parent.Add(values.PubKeyTimeItem(tm, p.cxt.Debug()))
	// [05] two-octet number denoting the time in days that this key is valid.
	days, err := p.reader.ReadBytes(2)
	if err != nil {
		return errs.New("illegal Valid days", errs.WithCause(err))
	}
	parent.Add(result.NewItem(
		result.Name("Valid days"),
		result.Value(strconv.Itoa(int(binary.BigEndian.Uint16(days)))),
		result.Note("0 is forever"),
	))
	// [07] one-octet number denoting the public-key algorithm of this key.
	pubid, err := p.reader.ReadByte()
	if err != nil {
		return errs.New("illegal pub ID", errs.WithCause(err))
	}
	p.pubID = values.PubID(pubid)
	parent.Add(p.pubID.ToItem(p.cxt.Debug()))
	// [08] series of multiprecision integers comprising the key material
	return pubkey.New(p.cxt, p.pubID, p.reader).ParsePub(parent)
}

// parseV4 parses V4 packet
func (p *pubkeyInfo) parseV4(parent *result.Item) error {
	//Structure of Signiture Packet (Ver4)
	// [01] four-octet number denoting the time that the key was created.
	tm, err := values.NewDateTime(p.reader, p.cxt.UTC())
	if err != nil {
		return errs.New("illegal Key Creation Time", errs.WithCause(err))
	}
	p.cxt.KeyCreationTime = tm
	parent.Add(values.PubKeyTimeItem(tm, p.cxt.Debug()))
	// [05] one-octet number denoting the public-key algorithm of this key.
	pubid, err := p.reader.ReadByte()
	if err != nil {
		return errs.New("illegal pub ID", errs.WithCause(err))
	}
	p.pubID = values.PubID(pubid)
	parent.Add(p.pubID.ToItem(p.cxt.Debug()))
	// [06] series of values comprising the key material.
	return pubkey.New(p.cxt, p.pubID, p.reader).ParsePub(parent)
}

// parseV5 parses V5 packet
func (p *pubkeyInfo) parseV5(parent *result.Item) error {
	//Structure of Signiture Packet (Ver5)
	// [01] four-octet number denoting the time that the key was created.
	tm, err := values.NewDateTime(p.reader, p.cxt.UTC())
	if err != nil {
		return errs.New("illegal Key Creation Time", errs.WithCause(err))
	}
	p.cxt.KeyCreationTime = tm
	parent.Add(values.PubKeyTimeItem(tm, p.cxt.Debug()))
	// [05] one-octet number denoting the public-key algorithm of this key.
	pubid, err := p.reader.ReadByte()
	if err != nil {
		return errs.New("illegal pub ID", errs.WithCause(err))
	}
	p.pubID = values.PubID(pubid)
	parent.Add(p.pubID.ToItem(p.cxt.Debug()))
	// [06] four-octet scalar octet count for the following key material.
	sz, err := p.reader.ReadBytes(4)
	if err != nil {
		return errs.New("illegal key material data size", errs.WithCause(err))
	}
	sz64 := int64(binary.BigEndian.Uint32(sz))
	b, err := p.reader.ReadBytes(sz64)
	if err != nil {
		return errs.New(fmt.Sprintf("illegal key material data (size: %d bytes)", sz64), errs.WithCause(err))
	}
	// [10] series of multiprecision integers comprising the key material.
	return pubkey.New(p.cxt, p.pubID, reader.New(b)).ParsePub(parent)
}

// PubID returns pubID
func (p *pubkeyInfo) PubID() values.PubID {
	return p.pubID
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
