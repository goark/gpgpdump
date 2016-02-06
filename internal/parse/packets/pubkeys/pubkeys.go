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
	pub    values.PubAlg
	reader *bytes.Reader
}

//New returns new Pubkey
func New(opt *options.Options, pub values.PubAlg, reader *bytes.Reader) *Pubkey {
	return &Pubkey{Options: opt, pub: pub, reader: reader}
}

//ParsePub multi-precision integers of public key algorithm for Public-key packet
func (p *Pubkey) ParsePub(item *items.Item) error {
	switch true {
	case p.pub.IsRSA():
		return p.rsaPub(item)
	case p.pub.IsDSA():
		return p.dsaPub(item)
	case p.pub.IsElgamal():
		return p.elgPub(item)
	case p.pub.IsECDH():
		return p.ecdhPub(item)
	case p.pub.IsECDSA():
		return p.ecdsaPub(item)
	default:
		item.AddSub(items.NewItem(fmt.Sprintf("Multi-precision integers of Unknown (pub %d)", p.pub), "", fmt.Sprintf("%d bytes", p.reader.Len()), ""))
	}
	return nil
}

func (p *Pubkey) rsaPub(item *items.Item) error {
	mpi, err := values.GetMPI(p.reader, "RSA n", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	mpi, err = values.GetMPI(p.reader, "RSA e", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	return nil
}

func (p *Pubkey) dsaPub(item *items.Item) error {
	mpi, err := values.GetMPI(p.reader, "DSA p", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	mpi, err = values.GetMPI(p.reader, "DSA q", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	mpi, err = values.GetMPI(p.reader, "DSA g", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	mpi, err = values.GetMPI(p.reader, "DSA y", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	return nil
}

func (p *Pubkey) elgPub(item *items.Item) error {
	mpi, err := values.GetMPI(p.reader, "ElGamal p", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	mpi, err = values.GetMPI(p.reader, "ElGamal g", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	mpi, err = values.GetMPI(p.reader, "ElGamal y", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	return nil
}

func (p *Pubkey) ecdsaPub(item *items.Item) error {
	oid, err := values.OID(p.reader)
	if err != nil {
		return err
	}
	item.AddSub(oid.Get())

	mpi, err := values.GetMPI(p.reader, "ECDH 04 || EC point (X,Y)", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	return nil
}

func (p *Pubkey) ecdhPub(item *items.Item) error {
	oid, err := values.OID(p.reader)
	if err != nil {
		return err
	}
	item.AddSub(oid.Get())

	mpi, err := values.GetMPI(p.reader, "ECDH 04 || EC point (X,Y)", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	dat, err := getECParm(p.reader)
	if err != nil {
		return err
	}
	if dat == nil {
		return nil
	}
	i := items.NewItem("KDF parameters", "", fmt.Sprintf("%d bytes", len(dat)), "")
	if dat[0] == 0x01 {
		i.AddSub(values.HashAlg(dat[1]).Get())
		i.AddSub(values.SymAlg(dat[2]).Get())
	} else {
		i.Value = "Unknown"
	}
	item.AddSub(i)
	return nil
}

//ParseSecPlain multi-precision integers of public key algorithm for Secret-Key Packet (plain)
func (p *Pubkey) ParseSecPlain(item *items.Item) error {
	switch true {
	case p.pub.IsRSA():
		if err := p.rsaSec(item, ""); err != nil {
			return err
		}
	case p.pub.IsDSA():
		if err := p.dsaSec(item, ""); err != nil {
			return err
		}
	case p.pub.IsElgamal():
		if err := p.elgSec(item, ""); err != nil {
			return err
		}
	case p.pub.IsECDH():
		if err := p.ecdhSec(item, ""); err != nil {
			return err
		}
	case p.pub.IsECDSA():
		if err := p.ecdsaSec(item, ""); err != nil {
			return err
		}
	default:
		item.AddSub(items.NewItem(fmt.Sprintf("Multi-precision integers of unknown secret key (pub %d)", p.pub), "", fmt.Sprintf("%d bytes", p.reader.Len()-2), ""))
		_ = skipBytes(p.reader, p.reader.Len()-2)
	}
	var chk [2]byte
	if _, err := p.reader.Read(chk[0:]); err != nil {
		return err
	}
	item.AddSub(values.NewRawData("Checksum", "", chk[:], true).Get())

	return nil
}

//ParseSecEnc multi-precision integers of public key algorithm for Secret-Key Packet (encrypted)
func (p *Pubkey) ParseSecEnc(item *items.Item) error {
	switch true {
	case p.pub.IsRSA():
		item.AddSub(items.NewItem("RSA encrypted key (d, p, q, u)", "", fmt.Sprintf("%d bytes", p.reader.Len()), ""))
	case p.pub.IsDSA():
		item.AddSub(items.NewItem("DSA encrypted key", "", fmt.Sprintf("%d bytes", p.reader.Len()), ""))
	case p.pub.IsElgamal():
		item.AddSub(items.NewItem("Elgamal encrypted key", "", fmt.Sprintf("%d bytes", p.reader.Len()), ""))
	case p.pub.IsECDH():
		item.AddSub(items.NewItem("ECDH encrypted key", "", fmt.Sprintf("%d bytes", p.reader.Len()), ""))
	case p.pub.IsECDSA():
		item.AddSub(items.NewItem("ECDSA encrypted key", "", fmt.Sprintf("%d bytes", p.reader.Len()), ""))
	default:
		item.AddSub(items.NewItem(fmt.Sprintf("Multi-precision integers of unknown encrypted key (pub %d)", p.pub), "", fmt.Sprintf("%d bytes", p.reader.Len()), ""))
	}
	_ = skipBytes(p.reader, p.reader.Len())
	return nil
}

func (p *Pubkey) rsaSec(item *items.Item, prefix string) error {
	mpi, err := values.GetMPI(p.reader, prefix+"RSA d", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	mpi, err = values.GetMPI(p.reader, prefix+"RSA p", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	mpi, err = values.GetMPI(p.reader, prefix+"RSA q", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	mpi, err = values.GetMPI(p.reader, prefix+"RSA u", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	return nil
}

func (p *Pubkey) dsaSec(item *items.Item, prefix string) error {
	mpi, err := values.GetMPI(p.reader, prefix+"DSA x", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	return nil
}

func (p *Pubkey) elgSec(item *items.Item, prefix string) error {
	mpi, err := values.GetMPI(p.reader, prefix+"ElGamal x", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	return nil
}

func (p *Pubkey) ecdsaSec(item *items.Item, prefix string) error {
	mpi, err := values.GetMPI(p.reader, prefix+"ECDSA x", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	return nil
}

func (p *Pubkey) ecdhSec(item *items.Item, prefix string) error {
	mpi, err := values.GetMPI(p.reader, prefix+"ECDH x", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	return nil
}

//ParseSig multi-precision integers of public key algorithm for Signiture packet
func (p *Pubkey) ParseSig(item *items.Item) error {
	switch true {
	case p.pub.IsRSA():
		return p.rsaSig(item)
	case p.pub.IsDSA():
		return p.dsaSig(item)
	case p.pub.IsElgamal():
		return p.elgSig(item)
	case p.pub.IsECDH():
		item.AddSub(items.NewItem("Multi-precision integers of ECDH", "", fmt.Sprintf("%d bytes", p.reader.Len()), ""))
	case p.pub.IsECDSA():
		return p.ecdsaSig(item)
	default:
		item.AddSub(items.NewItem(fmt.Sprintf("Multi-precision integers of Unknown (pub %d)", p.pub), "", fmt.Sprintf("%d bytes", p.reader.Len()), ""))
	}
	return nil
}

func (p *Pubkey) rsaSig(item *items.Item) error {
	mpi, err := values.GetMPI(p.reader, "RSA m^d mod n -> PKCS-1", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	return nil
}

func (p *Pubkey) dsaSig(item *items.Item) error {
	mpi, err := values.GetMPI(p.reader, "DSA r", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	mpi, err = values.GetMPI(p.reader, "DSA s", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	return nil
}

func (p *Pubkey) ecdsaSig(item *items.Item) error {
	mpi, err := values.GetMPI(p.reader, "ECDSA r", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	mpi, err = values.GetMPI(p.reader, "ECDSA s", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	return nil
}

func (p *Pubkey) elgSig(item *items.Item) error {
	mpi, err := values.GetMPI(p.reader, "ElGamal a = g^k mod p", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	mpi, err = values.GetMPI(p.reader, "ElGamal b = (h - a*x)/k mod p - 1", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	return nil
}

//ParseSes multi-precision integers of public key algorithm for Public-Key Encrypted Session Key Packet
func (p *Pubkey) ParseSes(item *items.Item) error {
	switch true {
	case p.pub.IsRSA():
		return p.rsaSes(item)
	case p.pub.IsDSA():
		item.AddSub(items.NewItem("Multi-precision integers of DSA", "", fmt.Sprintf("%d bytes", p.reader.Len()), ""))
	case p.pub.IsElgamal():
		return p.elgSes(item)
	case p.pub.IsECDH():
		return p.ecdhSes(item)
	case p.pub.IsECDSA():
		item.AddSub(items.NewItem("Multi-precision integers of ECDSA", "", fmt.Sprintf("%d bytes", p.reader.Len()), ""))
	default:
		item.AddSub(items.NewItem(fmt.Sprintf("Multi-precision integers of Unknown (pub %d)", p.pub), "", fmt.Sprintf("%d bytes", p.reader.Len()), ""))
	}
	return nil
}

func (p *Pubkey) rsaSes(item *items.Item) error {
	mpi, err := values.GetMPI(p.reader, "RSA m^e mod n -> m = Ses alg(1 byte) + checksum(2 bytes) + PKCS-1 block type 02", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	return nil
}

func (p *Pubkey) elgSes(item *items.Item) error {
	mpi, err := values.GetMPI(p.reader, "ElGamal g^k mod p", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	mpi, err = values.GetMPI(p.reader, "ElGamal m * y^k mod p -> m = sym alg(1 byte) + checksum(2 bytes) + PKCS-1 block type 02", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	return nil
}

func (p *Pubkey) ecdhSes(item *items.Item) error {
	mpi, err := values.GetMPI(p.reader, "ECDSA 04 || EC point (X,Y)", p.Iflag)
	if err != nil {
		return err
	}
	item.AddSub(mpi.Get())

	dat, err := getECParm(p.reader)
	if err != nil {
		return err
	}
	if dat != nil {
		item.AddSub(items.NewItem("symmetric key (encoded)", "", fmt.Sprintf("%d bytes", len(dat)), ""))
	}
	return nil
}

func getECParm(reader *bytes.Reader) ([]byte, error) {
	length, err := reader.ReadByte()
	if err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, err
	}
	if length == 0 {
		return nil, nil
	}
	buf := make([]byte, length)
	if _, err := reader.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func skipBytes(reader *bytes.Reader, length int) []byte {
	buf := make([]byte, length)
	if _, err := reader.Read(buf); err != nil {
		return nil
	}
	return buf
}
