package pubkey

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

//ParseSig multi-precision integers of public key algorithm for Signiture packet
func (p *Pubkey) ParseSig(parent *info.Item) error {
	switch true {
	case p.pubID.IsRSA():
		return p.rsaSig(parent)
	case p.pubID.IsDSA():
		return p.dsaSig(parent)
	case p.pubID.IsElgamal():
		return p.elgSig(parent)
	case p.pubID.IsECDH():
		parent.Add(info.NewItem(
			info.Name("Multi-precision integers of ECDH"),
			info.Note(fmt.Sprintf("%d bytes", p.size)),
		))
	case p.pubID.IsECDSA():
		return p.ecdsaSig(parent)
	default:
		parent.Add(info.NewItem(
			info.Name(fmt.Sprintf("Multi-precision integers of Unknown (pub %d)", p.pubID)),
			info.Note(fmt.Sprintf("%d bytes", p.size)),
		))
	}
	return nil
}

func (p *Pubkey) rsaSig(item *info.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("RSA m^d mod n -> PKCS-1", p.cxt.Integer()))
	return nil
}

func (p *Pubkey) dsaSig(item *info.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("DSA r", p.cxt.Integer()))
	mpi, err = values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("DSA s", p.cxt.Integer()))
	return nil
}

func (p *Pubkey) elgSig(item *info.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("ElGamal a = g^k mod p", p.cxt.Integer()))
	mpi, err = values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("ElGamal b = (h - a*x)/k mod p - 1", p.cxt.Integer()))
	return nil
}

func (p *Pubkey) ecdsaSig(item *info.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("ECDSA r", p.cxt.Integer()))
	mpi, err = values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("ECDSA s", p.cxt.Integer()))
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