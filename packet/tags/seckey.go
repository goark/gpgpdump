package tags

import (
	"fmt"
	"io"

	"github.com/pkg/errors"
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
	sid, err := p.reader.ReadByte()
	if err != nil {
		return errors.Wrap(err, "error in tags.seckeyInfo,Parse() function (sid)")
	}
	switch sid {
	case 0:
		parent.Note = "the secret-key data is not encrypted."
		parent.Add(p.pubVer.ToItem(p.cxt.Debug()))
		if !p.pubVer.IsUnknown() {
			if err := pubkey.New(p.cxt, p.pubID, p.reader).ParseSecPlain(parent); err != nil {
				return err
			}
		} else {
			parent.Add(p.unknownMPI())
			if _, err := p.reader.Seek(0, io.SeekEnd); err != nil { //skip
				return errors.Wrap(err, "error in tags.seckeyInfo.Parse() function (skip)")
			}
		}
	case 254, 255:
		if sid == 254 {
			parent.Note = "encrypted SHA1 hash"
		} else {
			parent.Note = "encrypted checksum"
		}
		symid, err := p.reader.ReadByte()
		if err != nil {
			return errors.Wrap(err, "error in tags.seckeyInfo.Parse() function (sym id)")
		}
		parent.Add(values.SymID(symid).ToItem(p.cxt.Debug()))
		s2k := s2k.New(p.reader)
		if err := s2k.Parse(parent, p.cxt.Debug()); err != nil {
			return errors.Wrap(err, "error in tags.seckeyInfo.Parse() function (s2k)")
		}
		if s2k.HasIV() {
			iv, err := p.iv(values.SymID(symid))
			if err != nil {
				return err
			}
			parent.Add(iv)
		}
		if !p.pubVer.IsUnknown() {
			if err := pubkey.New(p.cxt, p.pubID, p.reader).ParseSecEnc(parent); err != nil {
				return err
			}
		} else {
			parent.Add(p.unknownMPI())
			if _, err := p.reader.Seek(0, io.SeekEnd); err != nil { //skip
				return errors.Wrap(err, "error in tags.seckeyInfo.Parse() function (skip)")
			}
		}
	default:
		parent.Note = "Simple string-to-key for IDEA (encrypted checksum)."
		symid, err := p.reader.ReadByte()
		if err != nil {
			return errors.Wrap(err, "error in tags.seckeyInfo.Parse() function (sym id)")
		}
		parent.Add(values.SymID(symid).ToItem(p.cxt.Debug()))
		iv, err := p.iv(values.SymID(symid))
		if err != nil {
			return err
		}
		parent.Add(iv)
		if !p.pubVer.IsUnknown() {
			if err := pubkey.New(p.cxt, p.pubID, p.reader).ParseSecEnc(parent); err != nil {
				return err
			}
		} else {
			parent.Add(p.unknownMPI())
			if _, err := p.reader.Seek(0, io.SeekEnd); err != nil { //skip
				return errors.Wrap(err, "error in tags.seckeyInfo.Parse() function (skip)")
			}
		}
	}
	return nil
}

func (p *seckeyInfo) unknownMPI() *info.Item {
	return info.NewItem(
		info.Name("Multi-precision integers"),
		info.Note(fmt.Sprintf("Unknown Version %s, %d bytes", p.pubVer.String(), p.reader.Rest())),
	)
}

func (p *seckeyInfo) iv(symid values.SymID) (*info.Item, error) {
	iv, err := p.reader.ReadBytes(int64(symid.IVLen()))
	if err != nil {
		return nil, errors.Wrap(err, "error in tags.seckeyInfo.iv() function (s2k iv)")
	}
	return info.NewItem(
		info.Name("IV"),
		info.DumpStr(values.DumpBytes(iv, true).String()),
	), nil
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
