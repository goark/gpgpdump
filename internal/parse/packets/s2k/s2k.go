package s2k

import (
	"bytes"
	"fmt"
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
	reader *bytes.Reader
	hasIV  bool
}

//New returns new Pubkey
func New(opt *options.Options, reader *bytes.Reader) *S2K {
	return &S2K{Options: opt, reader: reader, hasIV: true}
}

//Left returns left bytes
func (s S2K) Left() int {
	return s.reader.Len()
}

//HasIV returns true if it has IV
func (s S2K) HasIV() bool {
	return s.hasIV
}

//Get parsing S2K information
func (s *S2K) Get() *items.Item {
	ss, err := s.reader.ReadByte()
	if err != nil {
		return nil
	}
	s2kAlg := values.S2KAlg(ss)
	s2k := s2kAlg.Get()

	switch s2kAlg {
	case 0:
		h, err := s.reader.ReadByte()
		if err != nil {
			return s2k
		}
		s2k.AddSub(values.HashAlg(h).Get())
	case 1:
		h, err := s.reader.ReadByte()
		if err != nil {
			return s2k
		}
		s2k.AddSub(values.HashAlg(h).Get())
		var salt [8]byte
		if _, err := s.reader.Read(salt[0:]); err != nil {
			return s2k
		}
		s2k.AddSub(values.NewRawData("Salt", "", salt[:], true).Get())
	case 3:
		h, err := s.reader.ReadByte()
		if err != nil {
			return s2k
		}
		s2k.AddSub(values.HashAlg(h).Get())
		var salt [8]byte
		if _, err := s.reader.Read(salt[0:]); err != nil {
			return s2k
		}
		s2k.AddSub(values.NewRawData("Salt", "", salt[:], true).Get())
		c, err := s.reader.ReadByte()
		if err != nil {
			return s2k
		}
		count := (uint32(16) + (uint32(c) & 15)) << ((uint32(c) >> 4) + EXPBIAS)
		s2k.AddSub(items.NewItem("Count", strconv.Itoa(int(count)), fmt.Sprintf("coded: 0x%02x", c), ""))
	case 101:
		s.hasIV = false
		var mrk [4]byte
		if _, err := s.reader.Read(mrk[0:]); err != nil {
			return s2k
		}
		gpg := items.NewItem("GnuPG Unknown", string(mrk[:]), "", values.DumpByte(mrk[0:]))
		switch string(mrk[:]) {
		case "GNU1":
			gpg.Name = "GnuPG gnu-dummy"
			gpg.Note = "s2k 1001"
		case "GNU2":
			gpg.Name = "GnuPG gnu-divert-to-card"
			gpg.Note = "s2k 1001"
			l, err := s.reader.ReadByte()
			if err != nil {
				return s2k
			}
			ser := make([]byte, l)
			if _, err := s.reader.Read(ser); err != nil {
				return s2k
			}
			gpg.AddSub(values.NewRawData("Serial Number", "", ser, true).Get())
		}
		s2k.AddSub(gpg)
	}
	return s2k
}
