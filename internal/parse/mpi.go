package parse

import (
	"fmt"
	"io"
)

// MPI is multi-precision integer
type MPI struct {
	Bytes     []byte
	BitLength uint16
}

//GetMPI returns parsing MPI
func GetMPI(reader io.Reader) (*MPI, error) {
	var bitlength [2]byte
	if _, err := io.ReadFull(reader, bitlength[0:]); err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, err
	}
	mpi := &MPI{}
	mpi.BitLength = (uint16(bitlength[0]) << 8) | uint16(bitlength[1])
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
		dump = DumpByte(mpi.Bytes)
	}
	return fmt.Sprintf("%s(%d bits) - %s", header, mpi.BitLength, dump)
}

// RSASigMPI is MPIs for RSA Signiture
type RSASigMPI struct {
	RSASignature *MPI
}

// Get parsing MPI blocks for RSA
func (r *RSASigMPI) Get(reader io.Reader) error {
	mpi, err := GetMPI(reader)
	if err != nil {
		return err
	}
	r.RSASignature = mpi
	return nil
}

// DSASigMPI is MPIs for DSA Signiture
type DSASigMPI struct {
	DSASigR, DSASigS *MPI
}

// Get parsing MPI blocks for RSA
func (r *DSASigMPI) Get(reader io.Reader) error {
	mpi, err := GetMPI(reader)
	if err != nil {
		return err
	}
	r.DSASigR = mpi
	mpi, err = GetMPI(reader)
	if err != nil {
		return err
	}
	r.DSASigS = mpi
	return nil
}
