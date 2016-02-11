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
