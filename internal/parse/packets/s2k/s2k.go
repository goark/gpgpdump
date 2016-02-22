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
func (s *S2K) Left() int {
	return s.reader.Len()
}

//HasIV returns true if it has IV
func (s *S2K) HasIV() bool {
	return s.hasIV
}

//Get parsing S2K information
func (s *S2K) Get() (*items.Item, error) {
	ss, err := s.reader.ReadByte()
	if err != nil {
		return nil, errs.ErrPacketInvalidData(fmt.Sprintf("S2K(alg, %v)", err))
	}
	s2kAlg := values.S2KAlg(ss)
	s2k := s2kAlg.Get()
	switch s2kAlg {
	case 0: //Simple S2K
		h, err := s.reader.ReadByte()
		if err != nil {
			return s2k, errs.ErrPacketInvalidData(fmt.Sprintf("S2K(hash-alg0, %v)", err))
		}
		s2k.AddSub(values.HashAlg(h).Get())
	case 1: //Salted S2K
		h, err := s.reader.ReadByte()
		if err != nil {
			return s2k, errs.ErrPacketInvalidData(fmt.Sprintf("S2K(hash-alg1, %v)", err))
		}
		s2k.AddSub(values.HashAlg(h).Get())
		salt, err := s.getSalt()
		if err != nil {
			return s2k, err
		}
		s2k.AddSub(salt)
	case 3: //Iterated and Salted S2K
		h, err := s.reader.ReadByte()
		if err != nil {
			return s2k, errs.ErrPacketInvalidData(fmt.Sprintf("S2K(hash-alg3, %v)", err))
		}
		s2k.AddSub(values.HashAlg(h).Get())
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
		//GNU-divert-to-card S2K format
		//refs https://lists.gnupg.org/pipermail/gnupg-users/2015-February/052769.html
		if s.Left() < 4 {
			return s2k, nil
		}
		mrk, err := values.GetBytes(s.reader, 3)
		if err != nil {
			return s2k, errs.ErrPacketInvalidData(fmt.Sprintf("S2K(gnu-div, %v)", err))
		}
		if bytes.Compare(mrk, []byte("GNU")) == 0 {
			s.hasIV = false
			n, err := s.reader.ReadByte()
			if err != nil {
				return s2k, errs.ErrPacketInvalidData(fmt.Sprintf("S2K(gnu-div num, %v)", err))
			}
			enum := 1000 + int(n)
			gnu := items.NewItem("GNU-divert-to-card", fmt.Sprintf("Extension Number %d", enum), "", "")
			switch enum {
			case 1002:
				l, err := s.reader.ReadByte()
				if err != nil {
					return s2k, errs.ErrPacketInvalidData(fmt.Sprintf("S2K(gnu-div s/n size, %v)", err))
				}
				ser, err := values.GetBytes(s.reader, int(l))
				if err != nil {
					return s2k, errs.ErrPacketInvalidData(fmt.Sprintf("S2K(gnu-div s/n, %v)", err))
				}
				gnu.AddSub(values.NewRawData("Serial Number", "", ser, true).Get())
			}
			s2k.AddSub(gnu)
		} else if _, err := s.reader.Seek(-3, 1); err != nil {
			return s2k, err
		}
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
	count := (uint32(16) + (uint32(c) & 0x0f)) << ((uint32(c) >> 4) + EXPBIAS)
	return items.NewItem("Count", strconv.Itoa(int(count)), fmt.Sprintf("coded: 0x%02x", c), ""), nil
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
