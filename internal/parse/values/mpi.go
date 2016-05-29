package values

import (
	"fmt"
	"io"

	"github.com/spiegel-im-spiegel/gpgpdump/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

// MPI - multi-precision integer
type MPI struct {
	Raw       *RawData
	BitLength uint16
}

// Get returns Item instance
func (mpi *MPI) Get() *items.Item {
	item := mpi.Raw.Get()
	if len(item.Note) == 0 {
		item.Note = fmt.Sprintf("%d bits", mpi.BitLength)
	} else {
		item.Note = fmt.Sprintf("%s (%d bits)", item.Note, mpi.BitLength)
	}
	return item
}

//GetMPI returns parsing MPI
func GetMPI(reader io.Reader, note string, dump bool) (*MPI, error) {
	bitlength, err := GetBytes(reader, 2)
	if err != nil {
		return nil, errs.ErrPacketInvalidData(fmt.Sprintf("MPI(bitlength, %v)", err))
	}
	bl := uint16(Octets2Int(bitlength))
	bytelength := (int(bl) + 7) / 8
	buf, err := GetBytes(reader, bytelength)
	if err != nil {
		return &MPI{Raw: nil, BitLength: bl}, errs.ErrPacketInvalidData(fmt.Sprintf("MPI(body %v)", err))
	}
	raw := NewRawData("Multi-precision integer", note, buf, dump)
	return &MPI{Raw: raw, BitLength: bl}, nil
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
