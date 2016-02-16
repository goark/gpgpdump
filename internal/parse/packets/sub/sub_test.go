package sub

import (
	"fmt"
	"testing"
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
	"Unknown (sub 33)",                                //33
}

var testSubpacketFunctions = Functions{}

func TestPacketType(t *testing.T) {
	for tp := 0; tp <= 33; tp++ {
		i := PacketType(tp).Get()
		if i.Name != testSubpacketNames[tp] {
			t.Errorf("Tag.Name = \"%s\", want \"%s\".", i.Name, testSubpacketNames[tp])
		}
		if i.Value != "" {
			t.Errorf("Tag.Value = \"%s\", want \"\".", i.Value)
		}
		if i.Note != "" {
			t.Errorf("Tag.Note = \"%s\", want \"\"", i.Note)
		}
		if i.Dump != "" {
			t.Errorf("Tag.Dump = \"%s\", want \"\".", i.Dump)
		}
	}
	for tp := 100; tp <= 110; tp++ {
		i := PacketType(tp).Get()
		name := fmt.Sprintf("Private or experimental (sub %d)", tp)
		if i.Name != name {
			t.Errorf("PubAlg.Value = \"%s\", want \"%s\".", i.Name, name)
		}
	}
}

func TestParseSub(t *testing.T) {
	for tp := 0; tp <= 33; tp++ {
	}
}