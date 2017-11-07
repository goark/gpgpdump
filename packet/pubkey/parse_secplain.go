package pubkey

import (
	"fmt"
	"io"

	"github.com/pkg/errors"
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
)

//ParseSecPlain multi-precision integers of public key algorithm for Secret-Key Packet (plain)
func (p *Pubkey) ParseSecPlain(parent *info.Item) error {
	switch true {
	case p.pubID.IsRSA():
		if err := p.rsaSec(parent); err != nil {
			return err
		}
	case p.pubID.IsDSA():
		if err := p.dsaSec(parent); err != nil {
			return err
		}
	case p.pubID.IsElgamal():
		if err := p.elgSec(parent); err != nil {
			return err
		}
	case p.pubID.IsECDH():
		if err := p.ecdhSec(parent); err != nil {
			return err
		}
	case p.pubID.IsECDSA():
		if err := p.ecdsaSec(parent); err != nil {
			return err
		}
	default:
		parent.Add(info.NewItem(
			info.Name(fmt.Sprintf("Multi-precision integers of unknown secret key (pub %d)", p.pubID)),
			info.Note(fmt.Sprintf("%d bytes", p.size-2)),
		))
		if _, err := p.reader.Seek(-1, io.SeekEnd); err != nil { //skip
			return errors.Wrap(err, "error in pubkey.Pubkey.ParseSecPlain() function (skip)")
		}
	}
	chk, err := p.reader.ReadBytes(2)
	if err != nil {
		return errors.Wrap(err, "error in pubkey.Pubkey.ParseSecPlain() function (Checksum)")
	}
	parent.Add(info.NewItem(
		info.Name("Checksum"),
		info.DumpStr(values.DumpBytes(chk, true).String()),
	))
	return nil
}

func (p *Pubkey) rsaSec(item *info.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("RSA d", p.cxt.Integer()))
	mpi, err = values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("RSA p", p.cxt.Integer()))
	mpi, err = values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("RSA q", p.cxt.Integer()))
	mpi, err = values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("RSA u", p.cxt.Integer()))
	return nil
}

func (p *Pubkey) dsaSec(item *info.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("DSA x", p.cxt.Integer()))
	return nil
}

func (p *Pubkey) elgSec(item *info.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("ElGamal x", p.cxt.Integer()))
	return nil
}

func (p *Pubkey) ecdhSec(item *info.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("ECDH x", p.cxt.Integer()))
	return nil
}

func (p *Pubkey) ecdsaSec(item *info.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil || mpi == nil {
		return err
	}
	item.Add(mpi.ToItem("ECDSA x", p.cxt.Integer()))
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
