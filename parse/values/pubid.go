package values

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/parse/result"
)

var pubIDNames = Msgs{
	1:  "RSA (Encrypt or Sign)",
	2:  "RSA Encrypt-Only",
	3:  "RSA Sign-Only",
	16: "Elgamal (Encrypt-Only)",
	17: "DSA (Digital Signature Algorithm)",
	18: "ECDH public key algorithm",
	19: "ECDSA public key algorithm",
	20: "Reserved (formerly Elgamal Encrypt or Sign)",
	21: "Reserved for Diffie-Hellman",
	22: "EdDSA",
	23: "Reserved (AEDH)",
	24: "Reserved (AEDSA)",
}

//PubID is Public-Key Algorithm ID
type PubID byte

//ToItem returns Item instance
func (pi PubID) ToItem(dumpFlag bool) *result.Item {
	return result.NewItem(
		result.Name("Public-key Algorithm"),
		result.Value(pi.String()),
		result.DumpStr(DumpByteString(byte(pi), dumpFlag)),
	)
}

//Stringer for PubID
func (pi PubID) String() string {
	var name string
	if 100 <= pi && pi <= 110 {
		name = PrivateAlgName
	} else {
		name = pubIDNames.Get(int(pi), Unknown)
	}
	return fmt.Sprintf("%s (pub %d)", name, int(pi))
}

//IsRSA returns if RSA algorithm.
func (pi PubID) IsRSA() bool {
	return (1 <= pi && pi <= 3)
}

//IsDSA returns if DSA algorithm.
func (pi PubID) IsDSA() bool {
	return (pi == 17)
}

//IsElgamal returns if Elgamal algorithm.
func (pi PubID) IsElgamal() bool {
	return (pi == 16 || pi == 20)
}

//IsECDH returns if ECDH algorithm.
func (pi PubID) IsECDH() bool {
	return (pi == 18)
}

//IsECDSA returns if ECDSA algorithm.
func (pi PubID) IsECDSA() bool {
	return (pi == 19)
}

//IsEdDSA returns if EdDSA algorithm.
func (pi PubID) IsEdDSA() bool {
	return (pi == 22)
}

/* Copyright 2016 Spiegel
 *
 * Licensed under the Apiche License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apiche.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
