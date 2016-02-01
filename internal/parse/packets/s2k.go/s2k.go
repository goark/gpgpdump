package s2k

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
)

//const
const EXPBIAS = uint32(6)

// S2K - information of public key algorithm
type S2K struct {
	*options.Options
	buf  []byte
	left int
}

//New returns new Pubkey
func New(opt *options.Options, buf []byte) *S2K {
	return &S2K{Options: opt, buf: buf}
}

//Left returns left bytes
func (s S2K) Left() int {
	return s.left
}

//Parse parsing S2K information
func (s *S2K) Parse(indent values.Indent) values.Content {
	content := values.NewContent()
	s2kAlg := values.S2KAlg(s.buf[0])
	s.left = len(s.buf) - 1

	content = append(content, indent.Fill(s2kAlg.String()))
	switch s2kAlg {
	case 0:
		content = append(content, (indent + 1).Fill(values.HashAlg(s.buf[1]).String()))
		s.left--
	case 1:
		content = append(content, (indent + 1).Fill(values.HashAlg(s.buf[1]).String()))
		content = append(content, (indent + 1).Fill(fmt.Sprintf("Salt - %s", values.DumpByte(s.buf[2:10]))))
		s.left -= 9
	case 3:
		content = append(content, (indent + 1).Fill(values.HashAlg(s.buf[1]).String()))
		content = append(content, (indent + 1).Fill(fmt.Sprintf("Salt - %s", values.DumpByte(s.buf[2:10]))))
		c := uint32(s.buf[10])
		count := (uint32(16) + (c & 15)) << ((c >> 4) + EXPBIAS)
		content = append(content, (indent + 1).Fill(fmt.Sprintf("Salt - %d", count)))
		s.left -= 10
	}
	return content
}
