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

//Parse multi-precision integers of public key algorithm
func (p *Pubkey) Parse(indent values.Indent) values.Content {
	content := values.NewContent()
	switch true {
	case p.pub.IsRSA():
		content = append(content, indent.Fill("Multi-precision integers of RSA:"))
		content = content.AddIndent(p.rsa(), indent+1)
		content = append(content, (indent + 2).Fill("-> PKCS-1"))
	case p.pub.IsDSA():
		content = append(content, indent.Fill("Multi-precision integers of DSA:"))
		content = content.AddIndent(p.dsa(), indent+1)
		content = append(content, (indent + 2).Fill("-> hash(DSA q bits)"))
	default:
	}
	return content
}

func (p *Pubkey) rsa() values.Content {
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

func (p *Pubkey) dsa() values.Content {
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
