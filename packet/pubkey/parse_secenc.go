package pubkey

import (
	"fmt"
	"io"

	"github.com/pkg/errors"
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

//ParseSecEnc multi-precision integers of public key algorithm for Secret-Key Packet (encrypted)
func (p *Pubkey) ParseSecEnc(parent *info.Item) error {
	switch true {
	case p.pubID.IsRSA():
		parent.Add(info.NewItem(
			info.Name("RSA encrypted key (d, p, q, u)"),
			info.Note(fmt.Sprintf("%d bytes", p.size)),
			info.DumpStr(values.Dump(p.reader, p.cxt.Debug()).String()),
		))
	case p.pubID.IsDSA():
		parent.Add(info.NewItem(
			info.Name("DSA encrypted key"),
			info.Note(fmt.Sprintf("%d bytes", p.size)),
			info.DumpStr(values.Dump(p.reader, p.cxt.Debug()).String()),
		))
	case p.pubID.IsElgamal():
		parent.Add(info.NewItem(
			info.Name("Elgamal encrypted key"),
			info.Note(fmt.Sprintf("%d bytes", p.size)),
			info.DumpStr(values.Dump(p.reader, p.cxt.Debug()).String()),
		))
	case p.pubID.IsECDH():
		parent.Add(info.NewItem(
			info.Name("ECDH encrypted key"),
			info.Note(fmt.Sprintf("%d bytes", p.size)),
			info.DumpStr(values.Dump(p.reader, p.cxt.Debug()).String()),
		))
	case p.pubID.IsECDSA():
		parent.Add(info.NewItem(
			info.Name("ECDSA encrypted key"),
			info.Note(fmt.Sprintf("%d bytes", p.size)),
			info.DumpStr(values.Dump(p.reader, p.cxt.Debug()).String()),
		))
	case p.pubID.IsEdDSA():
		parent.Add(info.NewItem(
			info.Name("EdDSA encrypted key"),
			info.Note(fmt.Sprintf("%d bytes", p.size)),
			info.DumpStr(values.Dump(p.reader, p.cxt.Debug()).String()),
		))
	default:
		parent.Add(info.NewItem(
			info.Name(fmt.Sprintf("Multi-precision integers of unknown encrypted key (pub %d)", p.pubID)),
			info.Note(fmt.Sprintf("%d bytes", p.size)),
			info.DumpStr(values.Dump(p.reader, p.cxt.Debug()).String()),
		))
	}
	if _, err := p.reader.Seek(0, io.SeekEnd); err != nil { //skip
		return errors.Wrap(err, "error in pubkey.Pubkey.ParseSecPlain() function (skip)")
	}
	return nil
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
