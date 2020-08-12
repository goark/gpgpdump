package pubkey

import (
	"fmt"

	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

//ParsePub multi-precision integers of Public-key packet
func (p *Pubkey) ParsePub(parent *info.Item) error {
	switch true {
	case p.pubID.IsRSA():
		return errs.Wrap(p.rsaPub(parent))
	case p.pubID.IsDSA():
		return errs.Wrap(p.dsaPub(parent))
	case p.pubID.IsElgamal():
		return errs.Wrap(p.elgPub(parent))
	case p.pubID.IsECDH():
		return errs.Wrap(p.ecdhPub(parent))
	case p.pubID.IsECDSA():
		return errs.Wrap(p.ecdsaPub(parent))
	case p.pubID.IsEdDSA():
		return errs.Wrap(p.eddsaPub(parent))
	default:
		parent.Add(info.NewItem(
			info.Name(fmt.Sprintf("Multi-precision integers of Unknown (pub %d)", p.pubID)),
			info.Note(fmt.Sprintf("%d bytes", p.size)),
			info.DumpStr(values.Dump(p.reader, p.cxt.Debug()).String()),
		))
	}
	return nil
}

func (p *Pubkey) rsaPub(item *info.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("RSA public modulus n", p.cxt.Integer()))
	mpi, err = values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("RSA public encryption exponent e", p.cxt.Integer()))
	return nil
}

func (p *Pubkey) dsaPub(item *info.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("DSA p", p.cxt.Integer()))
	mpi, err = values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("DSA q (q is a prime divisor of p-1)", p.cxt.Integer()))
	mpi, err = values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("DSA g", p.cxt.Integer()))
	mpi, err = values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("DSA y (= g^x mod p where x is secret)", p.cxt.Integer()))
	return nil
}

func (p *Pubkey) elgPub(item *info.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("ElGamal prime p", p.cxt.Integer()))

	mpi, err = values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("ElGamal group generator g", p.cxt.Integer()))

	mpi, err = values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("ElGamal public key value y (= g^x mod p where x is secret)", p.cxt.Integer()))
	return nil
}

func (p *Pubkey) ecdhPub(item *info.Item) error {
	oid, err := values.NewOID(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(oid.ToItem(true)) //enable dump data

	mpi, err := values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	flag := values.ECCPointCompFlag(0xff)
	if body := mpi.Rawdata(); len(body) > 0 {
		flag = values.ECCPointCompFlag(body[0])
	}
	item.Add(mpi.ToItem(flag.Name("ECDH"), p.cxt.Integer()))

	ep, err := values.NewECParm(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	i := ep.ToItem("KDF parameters", p.cxt.Integer())
	ln := len(ep)
	if ln > 0 {
		switch ep[0] {
		case 0x01:
			if ln > 2 {
				i.Add(values.HashID(ep[1]).ToItem(p.cxt.Debug()))
				i.Add(values.SymID(ep[2]).ToItem(p.cxt.Debug()))
			} else {
				i.Value = values.Unknown
			}
		default:
			i.Value = values.Unknown
		}
	} else {
		i.Value = values.Unknown
	}
	item.Add(i)

	return nil
}

func (p *Pubkey) ecdsaPub(item *info.Item) error {
	oid, err := values.NewOID(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(oid.ToItem(true)) //enable dump data

	mpi, err := values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	flag := values.ECCPointCompFlag(0xff)
	if body := mpi.Rawdata(); len(body) > 0 {
		flag = values.ECCPointCompFlag(body[0])
	}
	item.Add(mpi.ToItem(flag.Name("ECDSA"), p.cxt.Integer()))
	return nil
}

func (p *Pubkey) eddsaPub(item *info.Item) error {
	oid, err := values.NewOID(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(oid.ToItem(true)) //enable dump data

	mpi, err := values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	flag := values.ECCPointCompFlag(0xff)
	if body := mpi.Rawdata(); len(body) > 0 {
		flag = values.ECCPointCompFlag(body[0])
	}
	item.Add(mpi.ToItem(flag.Name("EdDSA"), p.cxt.Integer()))
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
