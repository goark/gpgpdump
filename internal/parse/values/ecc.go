package values

import (
	"bytes"
	"io"
)

//OID returns RawData instance with parsing OID
func OID(reader io.Reader) (*RawData, error) {
	var length [1]byte
	if _, err := io.ReadFull(reader, length[0:]); err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, err
	}
	l := length[0]
	buf := make([]byte, l)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return nil, err
	}
	return NewRawData("ECC OID", oidString(buf), buf, true), nil
}

var oidList = map[string][]byte{
	"NIST curve P-256": {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07},
	"NIST curve P-384": {0x2b, 0x81, 0x04, 0x00, 0x22},
	"NIST curve P-521": {0x2b, 0x81, 0x04, 0x00, 0x23},
}

func oidString(oid []byte) string {
	for k, v := range oidList {
		if bytes.Compare(oid, v) == 0 {
			return k
		}
	}
	return "Unknown"
}
