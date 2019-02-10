package s2k

import (
	"bytes"
	"fmt"
	"io"

	"github.com/pkg/errors"
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/values"
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
func (s *S2K) Parse(parent *info.Item, dumpFlag bool) error {
	if s == nil {
		return nil
	}
	ss, err := s.reader.ReadByte()
	if err != nil {
		return errors.Wrap(err, "error in s2k.S2K.Parse() function (s2k ID)")
	}
	s2kID := values.S2KID(ss)
	itm := s2kID.ToItem(dumpFlag)
	parent.Add(itm)
	if s2kID == 0x00 || s2kID == 0x01 || s2kID == 0x03 {
		//0x00: Simple S2K
		//0x01: Salted S2K
		//0x03: Iterated and Salted S2K
		hashid, err := s.reader.ReadByte()
		if err != nil {
			return errors.Wrap(err, "error in s2k.S2K.Parse() function (hash ID)")
		}
		itm.Add(values.HashID(hashid).ToItem(dumpFlag))
		if s2kID != 0x00 {
			//0x01: Salted S2K
			//0x03: Iterated and Salted S2K
			salt, err := s.reader.ReadBytes(8)
			if err != nil {
				return errors.Wrap(err, "error in s2k.S2K.Parse() function (salt)")
			}
			itm.Add(values.Salt(salt).ToItem(true))
		}
		if s2kID == 0x03 {
			//0x03: Iterated and Salted S2K
			ct, err := s.reader.ReadByte()
			if err != nil {
				return errors.Wrap(err, "error in s2k.S2K.Parse() function (stretch count)")
			}
			itm.Add(values.Stretch(ct).ToItem())
		}
	} else if s2kID == 101 {
		//Private/Experimental algorithm (s2k 101)
		//GNU-divert-to-card S2K format
		//refs https://lists.gnupg.org/pipermail/gnupg-users/2015-February/052769.html
		if s.reader.Rest() < 4 {
			return nil //unknown
		}
		mrk, err := s.reader.ReadBytes(3)
		if err != nil {
			return errors.Wrap(err, "error in s2k.S2K.Parse() function (gnu-div)")
		}
		if bytes.Equal(mrk, []byte("GNU")) {
			s.hasIV = false
			n, err := s.reader.ReadByte()
			if err != nil {
				return errors.Wrap(err, "error in s2k.S2K.Parse() function (gnu-div num)")
			}
			enum := 1000 + int(n)
			gnu := info.NewItem(
				info.Name("GNU-divert-to-card"),
				info.Value(fmt.Sprintf("Extension Number %d", enum)),
			)
			if enum == 1002 {
				l, err := s.reader.ReadByte()
				if err != nil {
					return errors.Wrap(err, "error in s2k.S2K.Parse() function (gnu-div s/n size)")
				}
				ser, err := s.reader.ReadBytes(int64(l))
				if err != nil {
					return errors.Wrap(err, "error in s2k.S2K.Parse() function (gnu-div s/n)")
				}
				gnu.Add(info.NewItem(
					info.Name("Serial Number"),
					info.DumpStr(values.DumpBytes(ser, true).String()),
				))
			}
			itm.Add(gnu)
		} else if _, err := s.reader.Seek(-3, io.SeekCurrent); err != nil { //roll back
			return err
		}
	}
	return nil
}

//HasIV returns true if it has IV
func (s *S2K) HasIV() bool {
	return s.hasIV
}

/* Copyright 2016-2019 Spiegel
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
