package s2k

import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/spiegel-im-spiegel/gpgpdump/errs"
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
func (s *S2K) Get() (*items.Item, error) {
	ss, err := s.reader.ReadByte()
	if err != nil {
		return nil, errs.ErrPacketInvalidData(fmt.Sprintf("S2K(size, %v)", err))
	}
	s2kAlg := values.S2KAlg(ss)
	s2k := s2kAlg.Get()
	h, err := s.reader.ReadByte()
	if err != nil {
		return s2k, errs.ErrPacketInvalidData(fmt.Sprintf("S2K(alg, %v)", err))
	}
	s2k.AddSub(values.HashAlg(h).Get())
	switch s2kAlg {
	case 0: //Simple S2K
	case 1: //Salted S2K
		salt, err := s.getSalt()
		if err != nil {
			return s2k, err
		}
		s2k.AddSub(salt)
	case 3: //Iterated and Salted S2K
		salt, err := s.getSalt()
		if err != nil {
			return s2k, err
		}
		s2k.AddSub(salt)
		ct, err := s.getCount()
		if err != nil {
			return s2k, err
		}
		s2k.AddSub(ct)
	case 101: //Private/Experimental algorithm (s2k 101)
		s.hasIV = false
		mrk, err := values.GetBytes(s.reader, 4)
		if err != nil {
			return s2k, errs.ErrPacketInvalidData(fmt.Sprintf("S2K(mark, %v)", err))
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
				return s2k, errs.ErrPacketInvalidData(fmt.Sprintf("S2K(s/n size, %v)", err))
			}
			ser, err := values.GetBytes(s.reader, int(l))
			if err != nil {
				return s2k, errs.ErrPacketInvalidData(fmt.Sprintf("S2K(s/n, %v)", err))
			}
			gpg.AddSub(values.NewRawData("Serial Number", "", ser, true).Get())
		}
		s2k.AddSub(gpg)
	}
	return s2k, nil
}

func (s *S2K) getSalt() (*items.Item, error) {
	salt, err := values.GetBytes(s.reader, 8)
	if err != nil {
		return nil, errs.ErrPacketInvalidData(fmt.Sprintf("S2K(salt, %v)", err))
	}
	return values.NewRawData("Salt", "", salt, true).Get(), nil
}

func (s *S2K) getCount() (*items.Item, error) {
	c, err := s.reader.ReadByte()
	if err != nil {
		return nil, errs.ErrPacketInvalidData(fmt.Sprintf("S2K(count, %v)", err))
	}
	count := (uint32(16) + (uint32(c) & 15)) << ((uint32(c) >> 4) + EXPBIAS)
	return items.NewItem("Count", strconv.Itoa(int(count)), fmt.Sprintf("coded: 0x%02x", c), ""), nil
}
