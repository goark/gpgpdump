package values

import (
	"encoding/binary"
	"fmt"

	"github.com/pkg/errors"
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
)

// MPI class as multi-precision integer
type MPI struct {
	bitLength uint16
	data      []byte
}

//NewMPI returns MPI instance
func NewMPI(r *reader.Reader) (*MPI, error) {
	length, err := r.ReadBytes(2)
	if err != nil {
		return nil, errors.Wrap(err, "error in values.NewMPI() function (length)")
	}
	bitLength := binary.BigEndian.Uint16(length)
	byteLength := (int64(bitLength) + 7) / 8
	data, err := r.ReadBytes(byteLength)
	if err != nil {
		return nil, errors.Wrapf(err, "error in values.NewMPI() function (body:%d)", byteLength)
	}
	return &MPI{bitLength: bitLength, data: data}, nil
}

//ToItem returns Item instance
func (mpi *MPI) ToItem(note string, dumpFlag bool) *info.Item {
	if mpi == nil {
		return nil
	}
	if len(note) == 0 {
		note = fmt.Sprintf("%d bits", mpi.bitLength)
	} else {
		note = fmt.Sprintf("%s (%d bits)", note, mpi.bitLength)
	}
	return info.NewItem(
		info.Name("Multi-precision integer"),
		info.Note(note),
		info.DumpStr(DumpBytes(mpi.data, dumpFlag).String()),
	)
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
