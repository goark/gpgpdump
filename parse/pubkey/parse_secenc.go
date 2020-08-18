package pubkey

import (
	"fmt"
	"io"

	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/result"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/values"
)

//ParseSecEnc multi-precision integers of public key algorithm for Secret-Key Packet (encrypted)
func (p *Pubkey) ParseSecEnc(parent *result.Item) error {
	switch true {
	case p.pubID.IsRSA():
		parent.Add(result.NewItem(
			result.Name("RSA encrypted key (d, p, q, u)"),
			result.Note(fmt.Sprintf("%d bytes", p.size)),
			result.DumpStr(values.Dump(p.reader, p.cxt.Debug()).String()),
		))
	case p.pubID.IsDSA():
		parent.Add(result.NewItem(
			result.Name("DSA encrypted key"),
			result.Note(fmt.Sprintf("%d bytes", p.size)),
			result.DumpStr(values.Dump(p.reader, p.cxt.Debug()).String()),
		))
	case p.pubID.IsElgamal():
		parent.Add(result.NewItem(
			result.Name("Elgamal encrypted key"),
			result.Note(fmt.Sprintf("%d bytes", p.size)),
			result.DumpStr(values.Dump(p.reader, p.cxt.Debug()).String()),
		))
	case p.pubID.IsECDH():
		parent.Add(result.NewItem(
			result.Name("ECDH encrypted key"),
			result.Note(fmt.Sprintf("%d bytes", p.size)),
			result.DumpStr(values.Dump(p.reader, p.cxt.Debug()).String()),
		))
	case p.pubID.IsECDSA():
		parent.Add(result.NewItem(
			result.Name("ECDSA encrypted key"),
			result.Note(fmt.Sprintf("%d bytes", p.size)),
			result.DumpStr(values.Dump(p.reader, p.cxt.Debug()).String()),
		))
	case p.pubID.IsEdDSA():
		parent.Add(result.NewItem(
			result.Name("EdDSA encrypted key"),
			result.Note(fmt.Sprintf("%d bytes", p.size)),
			result.DumpStr(values.Dump(p.reader, p.cxt.Debug()).String()),
		))
	default:
		parent.Add(result.NewItem(
			result.Name(fmt.Sprintf("Multi-precision integers of unknown encrypted key (pub %d)", p.pubID)),
			result.Note(fmt.Sprintf("%d bytes", p.size)),
			result.DumpStr(values.Dump(p.reader, p.cxt.Debug()).String()),
		))
	}
	if _, err := p.reader.Seek(0, io.SeekEnd); err != nil { //skip to EOF
		return errs.Wrap(err)
	}
	return nil
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
