package pubkeys

import (
	"bytes"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
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
func (p *Pubkey) ParsePub(indent values.Indent) values.Content {
	content := values.NewContent()
	switch true {
	case p.pub.IsRSA():
		content = append(content, indent.Fill("Multi-precision integers of RSA:"))
		content = content.AddIndent(p.rsaPub(), indent+1)
	case p.pub.IsDSA():
		content = append(content, indent.Fill("Multi-precision integers of DSA:"))
		content = content.AddIndent(p.dsaPub(), indent+1)
	case p.pub.IsElgamal():
		content = append(content, indent.Fill("Multi-precision integers of Elgamal:"))
		content = content.AddIndent(p.elgPub(), indent+1)
	default:
	}
	return content
}

func (p *Pubkey) rsaPub() values.Content {
	content := values.NewContent()
	reader := bytes.NewReader(p.mpi)
	mpi, err := GetMPI(reader)
	if err != nil {
		content = append(content, err.Error())
		return content
	}
	content = append(content, mpi.Dump("RSA n", p.Iflag))
	mpi, err = GetMPI(reader)
	if err != nil {
		content = append(content, err.Error())
		return content
	}
	content = append(content, mpi.Dump("RSA e", p.Iflag))
	return content
}

func (p *Pubkey) dsaPub() values.Content {
	content := values.NewContent()
	reader := bytes.NewReader(p.mpi)
	mpi, err := GetMPI(reader)
	if err != nil {
		content = append(content, err.Error())
		return content
	}
	content = append(content, mpi.Dump("DSA p", p.Iflag))
	mpi, err = GetMPI(reader)
	if err != nil {
		content = append(content, err.Error())
		return content
	}
	content = append(content, mpi.Dump("DSA q", p.Iflag))
	mpi, err = GetMPI(reader)
	if err != nil {
		content = append(content, err.Error())
		return content
	}
	content = append(content, mpi.Dump("DSA g", p.Iflag))
	mpi, err = GetMPI(reader)
	if err != nil {
		content = append(content, err.Error())
		return content
	}
	content = append(content, mpi.Dump("DSA y", p.Iflag))
	return content
}

func (p *Pubkey) elgPub() values.Content {
	content := values.NewContent()
	reader := bytes.NewReader(p.mpi)
	mpi, err := GetMPI(reader)
	if err != nil {
		content = append(content, err.Error())
		return content
	}
	content = append(content, mpi.Dump("ElGamal p", p.Iflag))
	mpi, err = GetMPI(reader)
	if err != nil {
		content = append(content, err.Error())
		return content
	}
	content = append(content, mpi.Dump("ElGamal g", p.Iflag))
	mpi, err = GetMPI(reader)
	if err != nil {
		content = append(content, err.Error())
		return content
	}
	content = append(content, mpi.Dump("ElGamal y", p.Iflag))
	return content
}

//ParseSig multi-precision integers of public key algorithm for Signiture packet
func (p *Pubkey) ParseSig(indent values.Indent) values.Content {
	content := values.NewContent()
	switch true {
	case p.pub.IsRSA():
		content = append(content, indent.Fill("Multi-precision integers of RSA:"))
		content = content.AddIndent(p.rsaSig(), indent+1)
		content = append(content, (indent + 2).Fill("-> PKCS-1"))
	case p.pub.IsDSA():
		content = append(content, indent.Fill("Multi-precision integers of DSA:"))
		content = content.AddIndent(p.dsaSig(), indent+1)
		content = append(content, (indent + 2).Fill("-> hash(DSA q bits)"))
	case p.pub.IsElgamal():
		content = append(content, indent.Fill("Multi-precision integers of Elgamal:"))
		content = content.AddIndent(p.elgSig(), indent+1)
	default:
		content = append(content, indent.Fill("Multi-precision integers of Unknown signature(pub %d)"))
	}
	return content
}

func (p *Pubkey) rsaSig() values.Content {
	content := values.NewContent()
	reader := bytes.NewReader(p.mpi)
	mpi, err := GetMPI(reader)
	if err != nil {
		content = append(content, err.Error())
		return content
	}
	content = append(content, mpi.Dump("RSA m^d mod n", p.Iflag))
	return content
}

func (p *Pubkey) dsaSig() values.Content {
	content := values.NewContent()
	reader := bytes.NewReader(p.mpi)
	mpi, err := GetMPI(reader)
	if err != nil {
		content = append(content, err.Error())
		return content
	}
	content = append(content, mpi.Dump("DSA r", p.Iflag))
	mpi, err = GetMPI(reader)
	if err != nil {
		content = append(content, err.Error())
		return content
	}
	content = append(content, mpi.Dump("DSA s", p.Iflag))
	return content
}

func (p *Pubkey) elgSig() values.Content {
	content := values.NewContent()
	reader := bytes.NewReader(p.mpi)
	mpi, err := GetMPI(reader)
	if err != nil {
		content = append(content, err.Error())
		return content
	}
	content = append(content, mpi.Dump("ElGamal a = g^k mod p", p.Iflag))
	mpi, err = GetMPI(reader)
	if err != nil {
		content = append(content, err.Error())
		return content
	}
	content = append(content, mpi.Dump("ElGamal b = (h - a*x)/k mod p - 1", p.Iflag))
	return content
}
