package values

import (
	"encoding/binary"
	"fmt"

	"github.com/spiegel-im-spiegel/errs"
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
		return nil, errs.Wrap(err, "illegal length of MPI value")
	}
	bitLength := binary.BigEndian.Uint16(length)
	byteLength := (int64(bitLength) + 7) / 8
	data, err := r.ReadBytes(byteLength)
	if err != nil {
		return nil, errs.Wrap(
			err,
			fmt.Sprintf("illegal body of MPI value (length: %d bits, %d bytes)", bitLength, byteLength),
		)
	}
	return &MPI{bitLength: bitLength, data: data}, nil
}

//Rawdata returns MPI raw data
func (mpi *MPI) Rawdata() []byte {
	if mpi == nil {
		return nil
	}
	return mpi.data
}

//ToItem returns Item instance
func (mpi *MPI) ToItem(name string, dumpFlag bool) *info.Item {
	if mpi == nil {
		return nil
	}
	if len(name) == 0 {
		name = "Multi-precision integer"
	}
	return info.NewItem(
		info.Name(name),
		info.Note(fmt.Sprintf("%d bits", mpi.bitLength)),
		info.DumpStr(DumpBytes(mpi.data, dumpFlag).String()),
	)
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
