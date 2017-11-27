package values

import (
	"bytes"
	"fmt"

	"github.com/pkg/errors"
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
)

//OID class as ECC OID
type OID []byte

var oidList = map[string][]byte{
	"NIST P-256":      {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07},
	"NIST P-384":      {0x2b, 0x81, 0x04, 0x00, 0x22},
	"NIST P-521":      {0x2b, 0x81, 0x04, 0x00, 0x23},
	"brainpoolP256r1": {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07},
	"brainpoolP512r1": {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D},
	"Ed25519":         {0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01},
	"Curve25519":      {0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01},
}

//NewOID returns OID instance
func NewOID(r *reader.Reader) (OID, error) {
	length, err := r.ReadByte()
	if err != nil {
		return nil, errors.Wrap(err, "error in values.NewOID() function (length)")
	}
	if length == 0 {
		return nil, nil
	}
	oid, err := r.ReadBytes(int64(length))
	if err != nil {
		err = errors.Wrap(err, "error in values.NewOID() function (body)")
	}
	return oid, err
}

//ToItem returns Item instance
func (oid OID) ToItem(dumpFlag bool) *info.Item {
	return info.NewItem(
		info.Name("ECC OID"),
		info.Note(oid.String()),
		info.DumpStr(DumpBytes([]byte(oid), dumpFlag).String()),
	)
}

//Stringer of OID
func (oid OID) String() string {
	for k, v := range oidList {
		if bytes.Compare(oid, v) == 0 {
			return k
		}
	}
	return Unknown
}

//ECParm class as ECC parameters
type ECParm []byte

//NewECParm returns ECParm instance
func NewECParm(r *reader.Reader) (ECParm, error) {
	length, err := r.ReadByte()
	if err != nil {
		return nil, nil // not error
	}
	if length == 0 {
		return nil, nil
	}
	buf, err := r.ReadBytes(int64(length))
	if err != nil {
		return nil, errors.Wrap(err, "error in values.NewECParm() function (body)")
	}
	return buf, nil
}

//ToItem returns Item instance
func (ep ECParm) ToItem(name string, dumpFlag bool) *info.Item {
	return info.NewItem(
		info.Name(name),
		info.Note(fmt.Sprintf("%d bytes", len(ep))),
		info.DumpStr(DumpBytes([]byte(ep), dumpFlag).String()),
	)
}

/* Copyright 2016,2017 Spiegel
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
