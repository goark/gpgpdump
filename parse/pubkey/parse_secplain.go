package pubkey

import (
	"fmt"

	"github.com/goark/errs"

	"github.com/goark/gpgpdump/parse/result"
	"github.com/goark/gpgpdump/parse/values"
)

//ParseSecPlain multi-precision integers of public key algorithm for Secret-Key Packet (plain)
func (p *Pubkey) ParseSecPlain(parent *result.Item) error {
	switch true {
	case p.pubID.IsRSA():
		if err := p.rsaSec(parent); err != nil {
			return errs.Wrap(err)
		}
	case p.pubID.IsDSA():
		if err := p.dsaSec(parent); err != nil {
			return errs.Wrap(err)
		}
	case p.pubID.IsElgamal():
		if err := p.elgSec(parent); err != nil {
			return errs.Wrap(err)
		}
	case p.pubID.IsECDH():
		if err := p.ecdhSec(parent); err != nil {
			return errs.Wrap(err)
		}
	case p.pubID.IsECDSA():
		if err := p.ecdsaSec(parent); err != nil {
			return errs.Wrap(err)
		}
	case p.pubID.IsEdDSA():
		if err := p.eddsaSec(parent); err != nil {
			return errs.Wrap(err)
		}
	default:
		length := p.size - 2 //last 2-octet is checksum value
		b, err := p.reader.ReadBytes(length)
		if err != nil {
			return errs.Wrap(err)
		}
		parent.Add(result.NewItem(
			result.Name(fmt.Sprintf("Multi-precision integers of unknown secret key (pub %d)", p.pubID)),
			result.Note(fmt.Sprintf("%d bytes", length)),
			result.DumpStr(values.DumpBytes(b, p.cxt.Debug()).String()),
		))
	}
	return nil
}

func (p *Pubkey) rsaSec(item *result.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("RSA secret exponent d", p.cxt.Integer()))
	mpi, err = values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("RSA secret prime value p", p.cxt.Integer()))
	mpi, err = values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("RSA secret prime value q (p < q)", p.cxt.Integer()))
	mpi, err = values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("RSA u, the multiplicative inverse of p, mod q", p.cxt.Integer()))
	return nil
}

func (p *Pubkey) dsaSec(item *result.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("DSA secret exponent x", p.cxt.Integer()))
	return nil
}

func (p *Pubkey) elgSec(item *result.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("ElGamal secret exponent x", p.cxt.Integer()))
	return nil
}

func (p *Pubkey) ecdhSec(item *result.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("ECDH secret key", p.cxt.Integer()))
	return nil
}

func (p *Pubkey) ecdsaSec(item *result.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("ECDSA secret key", p.cxt.Integer()))
	return nil
}

func (p *Pubkey) eddsaSec(item *result.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("EdDSA secret key", p.cxt.Integer()))
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
