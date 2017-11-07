package values

import (
	"bytes"
	"fmt"
	"io"

	"github.com/spiegel-im-spiegel/gpgpdump/errs"
)

//OID returns RawData instance with parsing OID
func OID(reader io.Reader) (*RawData, error) {
	length, err := GetBytes(reader, 1)
	if err != nil {
		return nil, errs.ErrPacketInvalidData(fmt.Sprintf("ECC OID(size %v)", err))
	}
	buf, err := GetBytes(reader, int(length[0]))
	if err != nil {
		return nil, errs.ErrPacketInvalidData(fmt.Sprintf("ECC OID(body %v)", err))
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
