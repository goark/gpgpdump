package pubkey

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

//ParsePub multi-precision integers of Public-key packet
func (p *Pubkey) ParsePub(parent *info.Item) error {
	switch true {
	case p.pubID.IsRSA():
		return p.rsaPub(parent)
	case p.pubID.IsDSA():
		return p.dsaPub(parent)
	case p.pubID.IsElgamal():
		return p.elgPub(parent)
	case p.pubID.IsECDH():
		return p.ecdhPub(parent)
	case p.pubID.IsECDSA():
		return p.ecdsaPub(parent)
	default:
		parent.Add(info.NewItem(
			info.Name(fmt.Sprintf("Multi-precision integers of Unknown (pub %d)", p.pubID)),
			info.Note(fmt.Sprintf("%d bytes", p.size)),
		))
	}
	return nil
}

func (p *Pubkey) rsaPub(item *info.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("RSA n", p.cxt.Integer()))
	mpi, err = values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("RSA e", p.cxt.Integer()))
	return nil
}

func (p *Pubkey) dsaPub(item *info.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("DSA p", p.cxt.Integer()))
	mpi, err = values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("DSA q", p.cxt.Integer()))
	mpi, err = values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("DSA g", p.cxt.Integer()))
	mpi, err = values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("DSA y", p.cxt.Integer()))
	return nil
}

func (p *Pubkey) elgPub(item *info.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("ElGamal p", p.cxt.Integer()))
	mpi, err = values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("ElGamal g", p.cxt.Integer()))
	mpi, err = values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("ElGamal y", p.cxt.Integer()))
	return nil
}

func (p *Pubkey) ecdhPub(item *info.Item) error {
	oid, err := values.NewOID(p.reader)
	if err != nil {
		return err
	}
	item.Add(oid.ToItem(true)) //enable dump data
	mpi, err := values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("ECDH 04 || EC point (X,Y)", p.cxt.Integer()))
	ep, err := values.NewECParm(p.reader)
	if err != nil || ep == nil {
		return err
	}
	i := ep.ToItem("KDF parameters", p.cxt.Integer())
	ln := len(ep)
	if ln == 0 {
		i.Value = values.Unknown
	} else if ep[0] == 0x01 && ln > 2 {
		i.Add(values.HashID(ep[1]).ToItem(p.cxt.Debug()))
		i.Add(values.SymID(ep[2]).ToItem(p.cxt.Debug()))
	} else {
		i.Value = values.Unknown
	}

	item.Add(i)
	return nil
}

func (p *Pubkey) ecdsaPub(item *info.Item) error {
	oid, err := values.NewOID(p.reader)
	if err != nil {
		return err
	}
	item.Add(oid.ToItem(true)) //enable dump data
	mpi, err := values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("ECDSA 04 || EC point (X,Y)", p.cxt.Integer()))
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
