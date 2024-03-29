package pubkey

import (
	"fmt"

	"github.com/goark/errs"

	"github.com/goark/gpgpdump/parse/result"
	"github.com/goark/gpgpdump/parse/values"
)

//ParseSes multi-precision integers of public key algorithm for Public-Key Encrypted Session Key Packet
func (p *Pubkey) ParseSes(parent *result.Item) error {
	switch true {
	case p.pubID.IsRSA():
		return errs.Wrap(p.rsaSes(parent))
	case p.pubID.IsDSA():
		parent.Add(result.NewItem(
			result.Name("Multi-precision integers of DSA"),
			result.Note(fmt.Sprintf("%d bytes", p.size)),
			result.DumpStr(values.Dump(p.reader, p.cxt.Debug()).String()),
		))
	case p.pubID.IsElgamal():
		return errs.Wrap(p.elgSes(parent))
	case p.pubID.IsECDH():
		return errs.Wrap(p.ecdhSes(parent))
	case p.pubID.IsECDSA():
		parent.Add(result.NewItem(
			result.Name("Multi-precision integers of ECDSA"),
			result.Note(fmt.Sprintf("%d bytes", p.size)),
			result.DumpStr(values.Dump(p.reader, p.cxt.Debug()).String()),
		))
	case p.pubID.IsEdDSA():
		parent.Add(result.NewItem(
			result.Name("Multi-precision integers of EdDSA"),
			result.Note(fmt.Sprintf("%d bytes", p.size)),
			result.DumpStr(values.Dump(p.reader, p.cxt.Debug()).String()),
		))
	default:
		parent.Add(result.NewItem(
			result.Name(fmt.Sprintf("Multi-precision integers of Unknown (pub %d)", p.pubID)),
			result.Note(fmt.Sprintf("%d bytes", p.size)),
			result.DumpStr(values.Dump(p.reader, p.cxt.Debug()).String()),
		))
	}
	return nil
}

func (p *Pubkey) rsaSes(item *result.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("RSA m^e mod n; m = sym alg(1 byte) + checksum(2 bytes) + PKCS#1 block encoding EME-PKCS1-v1_5", p.cxt.Integer()))
	return nil
}

func (p *Pubkey) elgSes(item *result.Item) error {
	mpi, err := values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("ElGamal g^k mod p", p.cxt.Integer()))
	mpi, err = values.NewMPI(p.reader)
	if err != nil {
		return errs.Wrap(err)
	}
	item.Add(mpi.ToItem("ElGamal m * y^k mod p; m = sym alg(1 byte) + checksum(2 bytes) + PKCS#1 block encoding EME-PKCS1-v1_5", p.cxt.Integer()))
	return nil
}

func (p *Pubkey) ecdhSes(item *result.Item) error {
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
	item.Add(ep.ToItem("symmetric key (encoded)", p.cxt.Integer()))
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
