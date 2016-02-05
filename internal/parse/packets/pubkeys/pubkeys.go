package pubkeys

import (
	"bytes"
	"fmt"
	"io"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

// Pubkey - information of public key algorithm
type Pubkey struct {
	*options.Options
	pub values.PubAlg
	mpi []byte
}

//New returns new Pubkey
func New(opt *options.Options, pub values.PubAlg, mpi []byte) *Pubkey {
	return &Pubkey{Options: opt, pub: pub, mpi: mpi}
}

//ParsePub multi-precision integers of public key algorithm for Public-key packet
func (p *Pubkey) ParsePub(pckt *items.Item) error {
	switch true {
	case p.pub.IsRSA():
		return p.rsaPub(pckt)
	case p.pub.IsDSA():
		return p.dsaPub(pckt)
	case p.pub.IsElgamal():
		return p.elgPub(pckt)
	case p.pub.IsECDH():
		return p.ecdhPub(pckt)
	case p.pub.IsECDSA():
		return p.ecdsaPub(pckt)
	default:
		pckt.AddSub(items.NewItem(fmt.Sprintf("Multi-precision integers of Unknown (pub %d)", p.pub), "", fmt.Sprintf("%d bytes", len(p.mpi)), ""))
	}
	return nil
}

func (p *Pubkey) rsaPub(pckt *items.Item) error {
	reader := bytes.NewReader(p.mpi)

	mpi, err := values.GetMPI(reader, "RSA n", p.Iflag)
	if err != nil {
		return err
	}
	pckt.AddSub(mpi.Get())

	mpi, err = values.GetMPI(reader, "RSA e", p.Iflag)
	if err != nil {
		return err
	}
	pckt.AddSub(mpi.Get())

	return nil
}

func (p *Pubkey) dsaPub(pckt *items.Item) error {
	reader := bytes.NewReader(p.mpi)

	mpi, err := values.GetMPI(reader, "DSA p", p.Iflag)
	if err != nil {
		return err
	}
	pckt.AddSub(mpi.Get())

	mpi, err = values.GetMPI(reader, "DSA q", p.Iflag)
	if err != nil {
		return err
	}
	pckt.AddSub(mpi.Get())

	mpi, err = values.GetMPI(reader, "DSA g", p.Iflag)
	if err != nil {
		return err
	}
	pckt.AddSub(mpi.Get())

	mpi, err = values.GetMPI(reader, "DSA y", p.Iflag)
	if err != nil {
		return err
	}
	pckt.AddSub(mpi.Get())

	return nil
}

func (p *Pubkey) elgPub(pckt *items.Item) error {
	reader := bytes.NewReader(p.mpi)

	mpi, err := values.GetMPI(reader, "ElGamal p", p.Iflag)
	if err != nil {
		return err
	}
	pckt.AddSub(mpi.Get())

	mpi, err = values.GetMPI(reader, "ElGamal g", p.Iflag)
	if err != nil {
		return err
	}
	pckt.AddSub(mpi.Get())

	mpi, err = values.GetMPI(reader, "ElGamal y", p.Iflag)
	if err != nil {
		return err
	}
	pckt.AddSub(mpi.Get())

	return nil
}

func (p *Pubkey) ecdsaPub(pckt *items.Item) error {
	reader := bytes.NewReader(p.mpi)

	oid, err := values.OID(reader)
	if err != nil {
		return err
	}
	pckt.AddSub(oid.Get())

	mpi, err := values.GetMPI(reader, "ECDH 04 || X || Y", p.Iflag)
	if err != nil {
		return err
	}
	pckt.AddSub(mpi.Get())

	return nil
}

func (p *Pubkey) ecdhPub(pckt *items.Item) error {
	reader := bytes.NewReader(p.mpi)

	oid, err := values.OID(reader)
	if err != nil {
		return err
	}
	pckt.AddSub(oid.Get())

	mpi, err := values.GetMPI(reader, "ECDSA 04 || X || Y", p.Iflag)
	if err != nil {
		return err
	}
	pckt.AddSub(mpi.Get())

	dat, err := getECParm(reader)
	if err != nil {
		return err
	}
	if dat == nil {
		return nil
	}
	item := items.NewItem("KDF parameters", "", fmt.Sprintf("%d bytes", len(dat)), "")
	if dat[0] == 0x01 {
		item.AddSub(values.HashAlg(dat[1]).Get())
		item.AddSub(values.SymAlg(dat[2]).Get())
	} else {
		item.Value = "Unknown"
	}
	pckt.AddSub(item)
	return nil
}

//ParseSig multi-precision integers of public key algorithm for Signiture packet
func (p *Pubkey) ParseSig(pckt *items.Item) error {
	switch true {
	case p.pub.IsRSA():
		return p.rsaSig(pckt)
	case p.pub.IsDSA():
		return p.dsaSig(pckt)
	case p.pub.IsElgamal():
		return p.elgSig(pckt)
	case p.pub.IsECDH():
		pckt.AddSub(items.NewItem("Multi-precision integers of ECDH", "", fmt.Sprintf("%d bytes", len(p.mpi)), ""))
	case p.pub.IsECDSA():
		return p.ecdsaSig(pckt)
	default:
		pckt.AddSub(items.NewItem(fmt.Sprintf("Multi-precision integers of Unknown (pub %d)", p.pub), "", fmt.Sprintf("%d bytes", len(p.mpi)), ""))
	}
	return nil
}

func (p *Pubkey) rsaSig(pckt *items.Item) error {
	reader := bytes.NewReader(p.mpi)

	mpi, err := values.GetMPI(reader, "RSA m^d mod n -> PKCS-1", p.Iflag)
	if err != nil {
		return err
	}
	pckt.AddSub(mpi.Get())

	return nil
}

func (p *Pubkey) dsaSig(pckt *items.Item) error {
	reader := bytes.NewReader(p.mpi)

	mpi, err := values.GetMPI(reader, "DSA r", p.Iflag)
	if err != nil {
		return err
	}
	pckt.AddSub(mpi.Get())

	mpi, err = values.GetMPI(reader, "DSA s", p.Iflag)
	if err != nil {
		return err
	}
	pckt.AddSub(mpi.Get())

	return nil
}

func (p *Pubkey) ecdsaSig(pckt *items.Item) error {
	reader := bytes.NewReader(p.mpi)

	mpi, err := values.GetMPI(reader, "ECDSA r", p.Iflag)
	if err != nil {
		return err
	}
	pckt.AddSub(mpi.Get())

	mpi, err = values.GetMPI(reader, "ECDSA s", p.Iflag)
	if err != nil {
		return err
	}
	pckt.AddSub(mpi.Get())

	return nil
}

func (p *Pubkey) elgSig(pckt *items.Item) error {
	reader := bytes.NewReader(p.mpi)

	mpi, err := values.GetMPI(reader, "ElGamal a = g^k mod p", p.Iflag)
	if err != nil {
		return err
	}
	pckt.AddSub(mpi.Get())

	mpi, err = values.GetMPI(reader, "ElGamal b = (h - a*x)/k mod p - 1", p.Iflag)
	if err != nil {
		return err
	}
	pckt.AddSub(mpi.Get())

	return nil
}

//ParseSes multi-precision integers of public key algorithm for Public-Key Encrypted Session Key Packet
func (p *Pubkey) ParseSes(pckt *items.Item) error {
	switch true {
	case p.pub.IsRSA():
		return p.rsaSes(pckt)
	case p.pub.IsDSA():
		pckt.AddSub(items.NewItem("Multi-precision integers of DSA", "", fmt.Sprintf("%d bytes", len(p.mpi)), ""))
	case p.pub.IsElgamal():
		return p.elgSes(pckt)
	case p.pub.IsECDH():
		return p.ecdhSes(pckt)
	case p.pub.IsECDSA():
		pckt.AddSub(items.NewItem("Multi-precision integers of ECDSA", "", fmt.Sprintf("%d bytes", len(p.mpi)), ""))
	default:
		pckt.AddSub(items.NewItem(fmt.Sprintf("Multi-precision integers of Unknown (pub %d)", p.pub), "", fmt.Sprintf("%d bytes", len(p.mpi)), ""))
	}
	return nil
}

func (p *Pubkey) rsaSes(pckt *items.Item) error {
	reader := bytes.NewReader(p.mpi)

	mpi, err := values.GetMPI(reader, "RSA m^e mod n -> m = Ses alg(1 byte) + checksum(2 bytes) + PKCS-1 block type 02", p.Iflag)
	if err != nil {
		return err
	}
	pckt.AddSub(mpi.Get())

	return nil
}

func (p *Pubkey) elgSes(pckt *items.Item) error {
	reader := bytes.NewReader(p.mpi)

	mpi, err := values.GetMPI(reader, "ElGamal g^k mod p", p.Iflag)
	if err != nil {
		return err
	}
	pckt.AddSub(mpi.Get())

	mpi, err = values.GetMPI(reader, "ElGamal m * y^k mod p -> m = sym alg(1 byte) + checksum(2 bytes) + PKCS-1 block type 02", p.Iflag)
	if err != nil {
		return err
	}
	pckt.AddSub(mpi.Get())

	return nil
}

func (p *Pubkey) ecdhSes(pckt *items.Item) error {
	reader := bytes.NewReader(p.mpi)

	mpi, err := values.GetMPI(reader, "ECDSA 04 || X || Y", p.Iflag)
	if err != nil {
		return err
	}
	pckt.AddSub(mpi.Get())

	dat, err := getECParm(reader)
	if err != nil {
		return err
	}
	if dat == nil {
		return nil
	}
	pckt.AddSub(items.NewItem("symmetric key (encoded)", "", fmt.Sprintf("%d bytes", len(dat)), ""))

	return nil
}

func getECParm(reader io.Reader) ([]byte, error) {
	var length [1]byte
	if _, err := io.ReadFull(reader, length[0:]); err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, err
	}
	buf := make([]byte, length[0])
	if _, err := io.ReadFull(reader, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
