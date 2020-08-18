package values

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/parse/result"
	"github.com/spiegel-im-spiegel/gpgpdump/parse/reader"
)

var subpacketNames = Msgs{
	0:  "Reserved",                               //00
	1:  "Image Attribute",                        //01
	2:  "Signature Creation Time",                //02
	3:  "Signature Expiration Time",              //03
	4:  "Exportable Certification",               //04
	5:  "Trust Signature",                        //05
	6:  "Regular Expression",                     //06
	7:  "Revocable",                              //07
	8:  "Reserved",                               //08
	9:  "Key Expiration Time",                    //09
	10: "Placeholder for backward compatibility", //10
	11: "Preferred Symmetric Algorithms",         //11
	12: "Revocation Key",                         //12
	13: "Reserved",                               //13
	14: "Reserved",                               //14
	15: "Reserved",                               //15
	16: "Issuer",                                 //16
	17: "Reserved",                               //17
	18: "Reserved",                               //18
	19: "Reserved",                               //19
	20: "Notation Data",                          //20
	21: "Preferred Hash Algorithms",              //21
	22: "Preferred Compression Algorithms",       //22
	23: "Key Server Preferences",                 //23
	24: "Preferred Key Server",                   //24
	25: "Primary User ID",                        //25
	26: "Policy URI",                             //26
	27: "Key Flags",                              //27
	28: "Signer's User ID",                       //28
	29: "Reason for Revocation",                  //29
	30: "Features",                               //30
	31: "Signature Target",                       //31
	32: "Embedded Signature",                     //32
	33: "Issuer Fingerprint",                     //33
	34: "Preferred AEAD Algorithms",              //34
	35: "Intended Recipient Fingerprint",         //35
	36: "Reserved",                               //36
	37: "Attested Certifications",                //37
}

//SuboacketID is sub-packet type ID
type SuboacketID byte

//ToItem returns Item instance
func (s SuboacketID) ToItem(r *reader.Reader, dumpFlag bool) *result.Item {
	return result.NewItem(
		result.Name(s.String()),
		result.Note(fmt.Sprintf("%d bytes", r.Len())),
		result.DumpStr(Dump(r, dumpFlag).String()),
	)
}

func (s SuboacketID) String() string {
	c := ""
	if s&0x80 != 0 { //critical bit
		c = " <critical>"
	}
	s &= 0x7f
	var name string
	if 100 <= s && s <= 110 {
		name = "Private or experimental"
	} else {
		name = subpacketNames.Get(int(s), Unknown)
	}
	return fmt.Sprintf("%s (sub %d)", name+c, s)
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
