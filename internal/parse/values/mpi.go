package values

import (
	"fmt"
	"io"

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
	var bitlength [2]byte
	if _, err := io.ReadFull(reader, bitlength[0:]); err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, err
	}
	bl := uint16(Octets2Int(bitlength[:]))
	bytelength := (int(bl) + 7) / 8
	buf := make([]byte, bytelength)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return nil, err
	}
	raw := NewRawData("Multi-precision integer", note, buf, dump)
	return &MPI{Raw: raw, BitLength: bl}, nil
}
