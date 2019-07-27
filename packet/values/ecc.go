package values

import (
	"bytes"
	"fmt"

	"github.com/spiegel-im-spiegel/errs"
	"github.com/spiegel-im-spiegel/gpgpdump/info"
	"github.com/spiegel-im-spiegel/gpgpdump/packet/reader"
)

//OID class as ECC OID
type OID []byte

var oidList = map[string][]byte{
	"nistp256 (256bits key size)":        {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07},
	"secp256k1 (256bits key size)":       {0x2b, 0x81, 0x04, 0x00, 0x0a},
	"nistp384 (384bits key size)":        {0x2b, 0x81, 0x04, 0x00, 0x22},
	"nistp521 (521bits key size)":        {0x2b, 0x81, 0x04, 0x00, 0x23},
	"brainpoolP256r1 (256bits key size)": {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07},
	"brainpoolP384r1 (384bits key size)": {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B},
	"brainpoolP512r1 (512bits key size)": {0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D},
	"ed25519 (256bits key size)":         {0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01},
	"cv25519 (256bits key size)":         {0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01},
}

//NewOID returns OID instance
func NewOID(r *reader.Reader) (OID, error) {
	length, err := r.ReadByte()
	if err != nil {
		return nil, errs.Wrap(err, "illegal length of OID value")
	}
	if length == 0 {
		return nil, nil
	}
	oid, err := r.ReadBytes(int64(length))
	if err != nil {
		return nil, errs.Wrapf(err, "illegal body of MPI value (length: %d bytes)", length)
	}
	return oid, err
}

//ToItem returns Item instance
func (oid OID) ToItem(dumpFlag bool) *info.Item {
	return info.NewItem(
		info.Name("ECC Curve OID"),
		info.Value(oid.String()),
		info.DumpStr(DumpBytes([]byte(oid), dumpFlag).String()),
	)
}

//Stringer of OID
func (oid OID) String() string {
	for k, v := range oidList {
		if bytes.Equal(oid, v) {
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
		return nil, errs.Wrapf(err, "illegal ECParm body (length: %d bytes)", length)
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

var eccPointCompFlagNames = Msgs{
	0x04: "uncompressed format",
	0x40: "Native point format of the curve follows",
	0x41: "Only X coordinate follows",
	0x42: "Only Y coordinate follows",
}

//PubID is Public-Key Algorithm ID
type ECCPointCompFlag byte

func (f ECCPointCompFlag) Name(algName string) string {
	return fmt.Sprintf("%v EC point (%v)", algName, f)
}

func (f ECCPointCompFlag) String() string {
	return eccPointCompFlagNames.Get(int(f), Unknown)
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
