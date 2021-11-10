package s2k

import (
	"bytes"
	"fmt"
	"io"

	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/result"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/values"
)

//S2K - information of S2K packet
type S2K struct {
	reader *reader.Reader
	hasIV  bool
}

//New returns new Pubkey instance
func New(r *reader.Reader) *S2K {
	return &S2K{reader: r, hasIV: true}
}

//Parse is parsing S2K packet
func (s *S2K) Parse(parent *result.Item, dumpFlag bool) error {
	if s == nil {
		return nil
	}
	ss, err := s.reader.ReadByte()
	if err != nil {
		return errs.New("invalid s2k ID", errs.WithCause(err))
	}
	s2kID := values.S2KID(ss)
	itm := s2kID.ToItem(dumpFlag)
	parent.Add(itm)
	switch s2kID {
	case 0x00, 0x01, 0x03:
		//0x00: Simple S2K
		//0x01: Salted S2K
		//0x03: Iterated and Salted S2K
		//0x04: Argon2
		hashid, err := s.reader.ReadByte()
		if err != nil {
			return errs.New("invalid hash ID", errs.WithCause(err))
		}
		itm.Add(values.HashID(hashid).ToItem(dumpFlag))
		if s2kID != 0x00 {
			//0x01: Salted S2K
			//0x03: Iterated and Salted S2K
			salt, err := s.reader.ReadBytes(8)
			if err != nil {
				return errs.New("invalid salt ID", errs.WithCause(err))
			}
			itm.Add(values.Salt(salt).ToItem(true))
		}
		if s2kID == 0x03 {
			//0x03: Iterated and Salted S2K
			ct, err := s.reader.ReadByte()
			if err != nil {
				return errs.New("invalid stretch count ID", errs.WithCause(err))
			}
			itm.Add(values.Stretch(ct).ToItem())
		}
	case 0x04:
		//0x04: Argon2
		salt, err := s.reader.ReadBytes(16)
		if err != nil {
			return errs.New("salt value", errs.WithCause(err))
		}
		itm.Add(values.Salt(salt).ToItem(true))
		t, err := s.reader.ReadByte()
		if err != nil {
			return errs.New("invalid stretch count ID", errs.WithCause(err))
		}
		itm.Add(values.Argon2Params(t).ToItem("number of passes t"))
		p, err := s.reader.ReadByte()
		if err != nil {
			return errs.New("invalid stretch count ID", errs.WithCause(err))
		}
		itm.Add(values.Argon2Params(p).ToItem("degree of parallelism p"))
		m, err := s.reader.ReadByte()
		if err != nil {
			return errs.New("invalid stretch count ID", errs.WithCause(err))
		}
		itm.Add(values.Argon2Params(m).ToItem("exponent indicating the memory size m"))
	case 101:
		//Private/Experimental algorithm (s2k 101)
		//GNU-divert-to-card S2K format
		//refs https://lists.gnupg.org/pipermail/gnupg-users/2015-February/052769.html
		if s.reader.Rest() < 4 {
			return nil //unknown
		}
		mrk, err := s.reader.ReadBytes(3)
		if err != nil {
			return errs.New("invalid gnu-div", errs.WithCause(err))
		}
		if bytes.Equal(mrk, []byte("GNU")) {
			s.hasIV = false
			n, err := s.reader.ReadByte()
			if err != nil {
				return errs.New("invalid gnu-div num", errs.WithCause(err))
			}
			enum := 1000 + int(n)
			gnu := result.NewItem(
				result.Name("GNU-divert-to-card"),
				result.Value(fmt.Sprintf("Extension Number %d", enum)),
			)
			if enum == 1002 {
				l, err := s.reader.ReadByte()
				if err != nil {
					return errs.New("invalid gnu-div s/n size", errs.WithCause(err))
				}
				ser, err := s.reader.ReadBytes(int64(l))
				if err != nil {
					return errs.New("invalid gnu-div s/n", errs.WithCause(err))
				}
				gnu.Add(result.NewItem(
					result.Name("Serial Number"),
					result.DumpStr(values.DumpBytes(ser, true).String()),
				))
			}
			itm.Add(gnu)
		} else if _, err := s.reader.Seek(-3, io.SeekCurrent); err != nil { //roll back
			return errs.New("roll back error", errs.WithCause(err))
		}
	}
	return nil
}

//HasIV returns true if it has IV
func (s *S2K) HasIV() bool {
	return s.hasIV
}

/* Copyright 2016-2021 Spiegel
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
