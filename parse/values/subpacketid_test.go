package values

import (
	"fmt"
	"testing"

	"github.com/goark/gpgpdump/parse/reader"
)

var testSubpacketNames = []string{
	"Reserved (sub 0)",                                //00
	"Image Attribute (sub 1)",                         //01
	"Signature Creation Time (sub 2)",                 //02
	"Signature Expiration Time (sub 3)",               //03
	"Exportable Certification (sub 4)",                //04
	"Trust Signature (sub 5)",                         //05
	"Regular Expression (sub 6)",                      //06
	"Revocable (sub 7)",                               //07
	"Reserved (sub 8)",                                //08
	"Key Expiration Time (sub 9)",                     //09
	"Placeholder for backward compatibility (sub 10)", //10
	"Preferred Symmetric Algorithms (sub 11)",         //11
	"Revocation Key (sub 12)",                         //12
	"Reserved (sub 13)",                               //13
	"Reserved (sub 14)",                               //14
	"Reserved (sub 15)",                               //15
	"Issuer (sub 16)",                                 //16
	"Reserved (sub 17)",                               //17
	"Reserved (sub 18)",                               //18
	"Reserved (sub 19)",                               //19
	"Notation Data (sub 20)",                          //20
	"Preferred Hash Algorithms (sub 21)",              //21
	"Preferred Compression Algorithms (sub 22)",       //22
	"Key Server Preferences (sub 23)",                 //23
	"Preferred Key Server (sub 24)",                   //24
	"Primary User ID (sub 25)",                        //25
	"Policy URI (sub 26)",                             //26
	"Key Flags (sub 27)",                              //27
	"Signer's User ID (sub 28)",                       //28
	"Reason for Revocation (sub 29)",                  //29
	"Features (sub 30)",                               //30
	"Signature Target (sub 31)",                       //31
	"Embedded Signature (sub 32)",                     //32
	"Issuer Fingerprint (sub 33)",                     //33
	"Reserved (Preferred AEAD Algorithms) (sub 34)",   //34
	"Intended Recipient Fingerprint (sub 35)",         //35
	"Reserved (sub 36)",                               //36
	"Reserved (Attested Certifications) (sub 37)",     //37
	"Reserved (Key Block) (sub 38)",                   //38
	"Unknown (sub 39)",                                //39
}

func TestSubpacketID(t *testing.T) {
	var body = []byte{0x01, 0x02, 0x03, 0x04}
	for tp := 0; tp < len(testSubpacketNames); tp++ {
		i := SuboacketID(tp).ToItem(reader.New(body), true)
		if i.Name != testSubpacketNames[tp] {
			t.Errorf("Tag.Value = \"%s\", want \"%s\".", i.Name, testSubpacketNames[tp])
		}
		if i.Note != "4 bytes" {
			t.Errorf("Tag.Note = \"%s\", want \"4 bytes\"", i.Note)
		}
		if i.Dump != "01 02 03 04" {
			t.Errorf("Tag.Dump = \"%s\", want \"01 02 03 04\".", i.Dump)
		}
	}
	for tp := 100; tp <= 110; tp++ {
		i := SuboacketID(tp).ToItem(reader.New(body), true)
		name := fmt.Sprintf("Private or experimental (sub %d)", tp)
		if i.Name != name {
			t.Errorf("PubAlg.Value = \"%s\", want \"%s\".", i.Name, name)
		}
	}
}

var testSubpacketNamesCritical = []string{
	"Reserved <critical> (sub 0)",                                //00
	"Image Attribute <critical> (sub 1)",                         //01
	"Signature Creation Time <critical> (sub 2)",                 //02
	"Signature Expiration Time <critical> (sub 3)",               //03
	"Exportable Certification <critical> (sub 4)",                //04
	"Trust Signature <critical> (sub 5)",                         //05
	"Regular Expression <critical> (sub 6)",                      //06
	"Revocable <critical> (sub 7)",                               //07
	"Reserved <critical> (sub 8)",                                //08
	"Key Expiration Time <critical> (sub 9)",                     //09
	"Placeholder for backward compatibility <critical> (sub 10)", //10
	"Preferred Symmetric Algorithms <critical> (sub 11)",         //11
	"Revocation Key <critical> (sub 12)",                         //12
	"Reserved <critical> (sub 13)",                               //13
	"Reserved <critical> (sub 14)",                               //14
	"Reserved <critical> (sub 15)",                               //15
	"Issuer <critical> (sub 16)",                                 //16
	"Reserved <critical> (sub 17)",                               //17
	"Reserved <critical> (sub 18)",                               //18
	"Reserved <critical> (sub 19)",                               //19
	"Notation Data <critical> (sub 20)",                          //20
	"Preferred Hash Algorithms <critical> (sub 21)",              //21
	"Preferred Compression Algorithms <critical> (sub 22)",       //22
	"Key Server Preferences <critical> (sub 23)",                 //23
	"Preferred Key Server <critical> (sub 24)",                   //24
	"Primary User ID <critical> (sub 25)",                        //25
	"Policy URI <critical> (sub 26)",                             //26
	"Key Flags <critical> (sub 27)",                              //27
	"Signer's User ID <critical> (sub 28)",                       //28
	"Reason for Revocation <critical> (sub 29)",                  //29
	"Features <critical> (sub 30)",                               //30
	"Signature Target <critical> (sub 31)",                       //31
	"Embedded Signature <critical> (sub 32)",                     //32
	"Issuer Fingerprint <critical> (sub 33)",                     //33
	"Reserved (Preferred AEAD Algorithms) <critical> (sub 34)",   //34
	"Intended Recipient Fingerprint <critical> (sub 35)",         //35
	"Reserved <critical> (sub 36)",                               //36
	"Reserved (Attested Certifications) <critical> (sub 37)",     //37
	"Reserved (Key Block) <critical> (sub 38)",                   //38
	"Unknown <critical> (sub 39)",                                //39
}

func TestSubpacketIDCritical(t *testing.T) {
	var body = []byte{0x01, 0x02, 0x03, 0x04}
	for tp := 0; tp < len(testSubpacketNamesCritical); tp++ {
		i := SuboacketID(tp+0x80).ToItem(reader.New(body), true)
		if i.Name != testSubpacketNamesCritical[tp] {
			t.Errorf("Tag.Value = \"%s\", want \"%s\".", i.Name, testSubpacketNamesCritical[tp])
		}
		if i.Note != "4 bytes" {
			t.Errorf("Tag.Note = \"%s\", want \"4 bytes\"", i.Note)
		}
		if i.Dump != "01 02 03 04" {
			t.Errorf("Tag.Dump = \"%s\", want \"01 02 03 04\".", i.Dump)
		}
	}
	for tp := 100; tp <= 110; tp++ {
		i := SuboacketID(tp+0x80).ToItem(reader.New(body), true)
		name := fmt.Sprintf("Private or experimental <critical> (sub %d)", tp)
		if i.Name != name {
			t.Errorf("PubAlg.Value = \"%s\", want \"%s\".", i.Name, name)
		}
	}
}

/* Copyright 2016-2021 Spiegel
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
