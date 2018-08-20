package pubkey

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

//ParseSes multi-precision integers of public key algorithm for Public-Key Encrypted Session Key Packet
func (p *Pubkey) ParseSes(parent *info.Item) error {
	switch true {
	case p.pubID.IsRSA():
		return p.rsaSes(parent)
	case p.pubID.IsDSA():
		parent.Add(info.NewItem(
			info.Name("Multi-precision integers of DSA"),
			info.Note(fmt.Sprintf("%d bytes", p.size)),
			info.DumpStr(values.Dump(p.reader, p.cxt.Debug()).String()),
		))
	case p.pubID.IsElgamal():
		return p.elgSes(parent)
	case p.pubID.IsECDH():
		return p.ecdhSes(parent)
	case p.pubID.IsECDSA():
		parent.Add(info.NewItem(
			info.Name("Multi-precision integers of ECDSA"),
			info.Note(fmt.Sprintf("%d bytes", p.size)),
			info.DumpStr(values.Dump(p.reader, p.cxt.Debug()).String()),
		))
	case p.pubID.IsEdDSA():
		parent.Add(info.NewItem(
			info.Name("Multi-precision integers of EdDSA"),
			info.Note(fmt.Sprintf("%d bytes", p.size)),
			info.DumpStr(values.Dump(p.reader, p.cxt.Debug()).String()),
		))
	default:
		parent.Add(info.NewItem(
			info.Name(fmt.Sprintf("Multi-precision integers of Unknown (pub %d)", p.pubID)),
			info.Note(fmt.Sprintf("%d bytes", p.size)),
			info.DumpStr(values.Dump(p.reader, p.cxt.Debug()).String()),
		))
	}
	return nil
}

func (p *Pubkey) rsaSes(item *info.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("RSA m^e mod n", p.cxt.Integer()))
	return nil
}

func (p *Pubkey) elgSes(item *info.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("ElGamal g^k mod p", p.cxt.Integer()))
	mpi, err = values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("ElGamal m * y^k mod p", p.cxt.Integer()))
	return nil
}

func (p *Pubkey) ecdhSes(item *info.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	switch (mpi.Rawdata())[0] {
	case 0x04:
		item.Add(mpi.ToItem("ECDH EC point (04 || X || Y)", p.cxt.Integer()))
	case 0x40:
		item.Add(mpi.ToItem("ECDH EC point (40 || X)", p.cxt.Integer()))
	default:
		item.Add(mpi.ToItem("ECDH EC point", p.cxt.Integer()))
	}
	ep, err := values.NewECParm(p.reader)
	if err != nil || ep == nil {
		return err
	}
	item.Add(ep.ToItem("symmetric key (encoded)", p.cxt.Integer()))
	return nil
}

/* Copyright 2016-2018 Spiegel
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
