package pubkeys

import (
	"fmt"
	"io"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
)

// MPI is multi-precision integer
type MPI struct {
	Bytes     []byte
	BitLength uint16
}

//GetMPI returns parsing MPI
func GetMPI(reader io.Reader) (*MPI, error) {
	var bitlength [2]byte
	if _, err := io.ReadFull(reader, bitlength[:]); err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, err
	}
	mpi := &MPI{}
	mpi.BitLength = uint16(values.Octets2Int(bitlength[:]))
	bytelength := (int(mpi.BitLength) + 7) / 8
	mpi.Bytes = make([]byte, bytelength)
	if _, err := io.ReadFull(reader, mpi.Bytes); err != nil {
		return nil, err
	}
	return mpi, nil
}

// Dump returns dump-out MPI
func (mpi *MPI) Dump(header string, iflag bool) string {
	dump := "..."
	if iflag && mpi.BitLength > 0 && mpi.Bytes != nil {
		dump = values.DumpByte(mpi.Bytes)
	}
	return fmt.Sprintf("%s (%d bits) - %s", header, mpi.BitLength, dump)
}
