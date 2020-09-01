package pubkey

import (
	"fmt"

	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/result"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/values"
)

//ParseSig multi-precision integers of public key algorithm for Signiture packet
func (p *Pubkey) ParseSig(parent *result.Item) error {
	switch true {
	case p.pubID.IsRSA():
		return errs.Wrap(p.rsaSig(parent))
	case p.pubID.IsDSA():
		return errs.Wrap(p.dsaSig(parent))
	case p.pubID.IsElgamal():
		return errs.Wrap(p.elgSig(parent))
	case p.pubID.IsECDH():
		parent.Add(result.NewItem(
			result.Name("Multi-precision integers of ECDH"),
			result.Note(fmt.Sprintf("%d bytes", p.size)),
			result.DumpStr(values.Dump(p.reader, p.cxt.Debug()).String()),
		))
	case p.pubID.IsECDSA():
		return errs.Wrap(p.ecdsaSig(parent))
	case p.pubID.IsEdDSA():
		return errs.Wrap(p.eddsaSig(parent))
	default:
		parent.Add(result.NewItem(
			result.Name(fmt.Sprintf("Multi-precision integers of Unknown (pub %d)", p.pubID)),
			result.Note(fmt.Sprintf("%d bytes", p.size)),
			result.DumpStr(values.Dump(p.reader, p.cxt.Debug()).String()),
		))
	}
	return nil
}

func (p *Pubkey) rsaSig(item *result.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("RSA signature value m^d mod n", p.cxt.Integer()))
	return nil
}

func (p *Pubkey) dsaSig(item *result.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("DSA value r", p.cxt.Integer()))
	mpi, err = values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("DSA value s", p.cxt.Integer()))
	return nil
}

func (p *Pubkey) elgSig(item *result.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("ElGamal a = g^k mod p", p.cxt.Integer()))
	mpi, err = values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("ElGamal b = (h - a*x)/k mod p - 1", p.cxt.Integer()))
	return nil
}

func (p *Pubkey) ecdsaSig(item *result.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("ECDSA value r", p.cxt.Integer()))
	mpi, err = values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("ECDSA value s", p.cxt.Integer()))
	return nil
}

func (p *Pubkey) eddsaSig(item *result.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("EC point r", p.cxt.Integer()))
	mpi, err = values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("EdDSA value s in the little endian representation", p.cxt.Integer()))
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
