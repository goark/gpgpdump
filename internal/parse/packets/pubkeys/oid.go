package pubkeys

import (
	"bytes"
	"fmt"
	"io"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
)

// OID is for ECC
type OID struct {
	Bytes  []byte
	Length byte
}

//GetOID returns parsing OID
func GetOID(reader io.Reader) (*OID, error) {
	var length [1]byte
	if _, err := io.ReadFull(reader, length[0:]); err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, err
	}
	oid := &OID{}
	oid.Length = length[0]
	oid.Bytes = make([]byte, oid.Length)
	if _, err := io.ReadFull(reader, oid.Bytes); err != nil {
		return nil, err
	}
	return oid, nil
}

var oidList = map[string][]byte{
	"NIST curve P-256": {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07},
	"NIST curve P-384": {0x2b, 0x81, 0x04, 0x00, 0x22},
	"NIST curve P-521": {0x2b, 0x81, 0x04, 0x00, 0x23},
}

func (oid *OID) String() string {
	for k, v := range oidList {
		if bytes.Compare(oid.Bytes, v) == 0 {
			return k
		}
	}
	return "Unknown"
}

// ECParm is for Sym. Key for ECC
type ECParm struct {
	Bytes  []byte
	Length byte
}

//GetECParm returns parsing Sym. Key for ECC
func GetECParm(reader io.Reader) (*ECParm, error) {
	var length [1]byte
	if _, err := io.ReadFull(reader, length[0:]); err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, err
	}
	key := &ECParm{}
	key.Length = length[0]
	key.Bytes = make([]byte, key.Length)
	if _, err := io.ReadFull(reader, key.Bytes); err != nil {
		return nil, err
	}
	return key, nil
}

// Dump returns dump-out OID
func (key *ECParm) Dump(header string, iflag bool) string {
	dump := "..."
	if iflag && key.Length > 0 && key.Bytes != nil {
		dump = values.DumpByte(key.Bytes)
	}
	return fmt.Sprintf("%s (%d byte) - %s", header, key.Length, dump)
}
