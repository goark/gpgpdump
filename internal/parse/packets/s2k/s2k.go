package s2k

import (
	"strconv"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

//EXPBIAS - S2K parameter
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

//Get parsing S2K information
func (s *S2K) Get() *items.Item {
	s2kAlg := values.S2KAlg(s.buf[0])
	s2k := s2kAlg.Get()
	s.left = len(s.buf) - 1

	switch s2kAlg {
	case 0:
		s2k.AddSub(values.HashAlg(s.buf[1]).Get())
		s.left--
	case 1:
		s2k.AddSub(values.HashAlg(s.buf[1]).Get())
		s2k.AddSub(values.NewRawData("Salt", "", s.buf[2:10], true).Get())
		s.left -= 9
	case 3:
		s2k.AddSub(values.HashAlg(s.buf[1]).Get())
		s2k.AddSub(values.NewRawData("Salt", "", s.buf[2:10], true).Get())
		c := uint32(s.buf[10])
		count := (uint32(16) + (c & 15)) << ((c >> 4) + EXPBIAS)
		s2k.AddSub(items.NewItem("Count", strconv.Itoa(int(count)), "", values.DumpByte(s.buf[10:11])))
		s.left -= 10
	case 101:
		mrk := string(s.buf[1:5])
		gpg := items.NewItem("GnuPG Unknown", mrk, "", values.DumpByte(s.buf[1:5]))
		s.left -= 4
		switch mrk {
		case "GNU1":
			gpg.Name = "GnuPG gnu-dummy"
			gpg.Note = "s2k 1001"
		case "GNU2":
			gpg.Name = "GnuPG gnu-divert-to-card"
			gpg.Note = "s2k 1001"
			l := s.buf[5]
			gpg.AddSub(values.NewRawData("Serial Number", "", s.buf[6:6+1], true).Get())
			s.left -= 1 + int(l)
		}
		s2k.AddSub(gpg)
	}
	return s2k
}
