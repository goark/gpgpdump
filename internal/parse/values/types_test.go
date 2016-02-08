package values

import (
	"fmt"
	"testing"
)

var testTagNames = []string{
	"Reserved (tag 0)",
	"Public-Key Encrypted Session Key Packet (tag 1)",
	"Signature Packet (tag 2)",
	"Symmetric-Key Encrypted Session Key Packet (tag 3)",
	"One-Pass Signature Packet (tag 4)",
	"Secret-Key Packet (tag 5)",
	"Public-Key Packet (tag 6)",
	"Secret-Subkey Packet (tag 7)",
	"Compressed Data Packet (tag 8)",
	"Symmetrically Encrypted Data Packet (tag 9)",
	"Marker Packet (Obsolete Literal Packet) (tag 10)",
	"Literal Data Packet (tag 11)",
	"Trust Packet (tag 12)",
	"User ID Packet (tag 13)",
	"Public-Subkey Packet (tag 14)",
	"Unknown (tag 15)",
	"Unknown (tag 16)",
	"User Attribute Packet (tag 17)",
	"Sym. Encrypted Integrity Protected Data Packet (tag 18)",
	"Modification Detection Code Packet (tag 19)",
	"Unknown (tag 20)",
	"Unknown (tag 21)",
	"Unknown (tag 22)",
	"Unknown (tag 23)",
	"Unknown (tag 24)",
	"Unknown (tag 25)",
	"Unknown (tag 26)",
	"Unknown (tag 27)",
	"Unknown (tag 28)",
	"Unknown (tag 29)",
	"Unknown (tag 30)",
	"Unknown (tag 31)",
	"Unknown (tag 32)",
	"Unknown (tag 33)",
	"Unknown (tag 34)",
	"Unknown (tag 35)",
	"Unknown (tag 36)",
	"Unknown (tag 37)",
	"Unknown (tag 38)",
	"Unknown (tag 39)",
	"Unknown (tag 40)",
	"Unknown (tag 41)",
	"Unknown (tag 42)",
	"Unknown (tag 43)",
	"Unknown (tag 44)",
	"Unknown (tag 45)",
	"Unknown (tag 46)",
	"Unknown (tag 47)",
	"Unknown (tag 48)",
	"Unknown (tag 49)",
	"Unknown (tag 50)",
	"Unknown (tag 51)",
	"Unknown (tag 52)",
	"Unknown (tag 53)",
	"Unknown (tag 54)",
	"Unknown (tag 55)",
	"Unknown (tag 56)",
	"Unknown (tag 57)",
	"Unknown (tag 58)",
	"Unknown (tag 59)",
	"Private or Experimental Values (tag 60)",
	"Private or Experimental Values (tag 61)",
	"Private or Experimental Values (tag 62)",
	"Private or Experimental Values (tag 63)",
	"Unknown (tag 64)",
}

func TestTag(t *testing.T) {
	for tag := 0; tag <= 64; tag++ {
		i := Tag(tag).Get(0)
		if i.Name != "Packet" {
			t.Errorf("Tag.Name = \"%s\", want \"Packet\".", i.Name)
		}
		if i.Value != testTagNames[tag] {
			t.Errorf("Tag.Value = \"%s\", want \"%s\".", i.Value, testTagNames[tag])
		}
		if i.Note != "0 bytes" {
			t.Errorf("Tag.Note = \"%s\", want \"0 bytes\"", i.Note)
		}
		if i.Dump != "" {
			t.Errorf("Tag.Dump = \"%s\", want \"\".", i.Dump)
		}
	}
}

func TestSigType(t *testing.T) {
	for tag := 0; tag <= 0x51; tag++ {
		i := SigType(tag).Get()
		var value string
		switch tag {
		case 0x00:
			value = "Signature of a binary document (0x00)"
		case 0x01:
			value = "Signature of a canonical text document (0x01)"
		case 0x02:
			value = "Standalone signature (0x02)"
		case 0x10:
			value = "Generic certification of a User ID and Public-Key packet (0x10)"
		case 0x11:
			value = "Persona certification of a User ID and Public-Key packet (0x11)"
		case 0x12:
			value = "Casual certification of a User ID and Public-Key packet (0x12)"
		case 0x13:
			value = "Positive certification of a User ID and Public-Key packet (0x13)"
		case 0x18:
			value = "Subkey Binding Signature (0x18)"
		case 0x19:
			value = "Primary Key Binding Signature (0x19)"
		case 0x1f:
			value = "Signature directly on a key (0x1f)"
		case 0x20:
			value = "Key revocation signature (0x20)"
		case 0x28:
			value = "Subkey revocation signature (0x28)"
		case 0x30:
			value = "Certification revocation signature (0x30)"
		case 0x40:
			value = "Timestamp signature (0x40)"
		case 0x50:
			value = "Third-Party Confirmation signature (0x50)"
		default:
			value = fmt.Sprintf("Unknown (0x%02x)", tag)
		}
		if i.Name != "Signiture Type" {
			t.Errorf("SigType.Name = \"%s\", want \"Signiture Type\".", i.Name)
		}
		if i.Value != value {
			t.Errorf("SigType.Value = \"%s\", want \"%s\".", i.Value, value)
		}
		if i.Note != "" {
			t.Errorf("SigType.Note = \"%s\", want \"\"", i.Note)
		}
		if i.Dump != "" {
			t.Errorf("SigType.Dump = \"%s\", want \"\".", i.Dump)
		}
	}
}

var testPubAlgNames = []string{
	"Unknown (pub 0)",
	"RSA (Encrypt or Sign) (pub 1)",
	"RSA Encrypt-Only (pub 2)",
	"RSA Sign-Only (pub 3)",
	"Unknown (pub 4)",
	"Unknown (pub 5)",
	"Unknown (pub 6)",
	"Unknown (pub 7)",
	"Unknown (pub 8)",
	"Unknown (pub 9)",
	"Unknown (pub 10)",
	"Unknown (pub 11)",
	"Unknown (pub 12)",
	"Unknown (pub 13)",
	"Unknown (pub 14)",
	"Unknown (pub 15)",
	"Elgamal (Encrypt-Only) (pub 16)",
	"DSA (Digital Signature Algorithm) (pub 17)",
	"ECDH public key algorithm (pub 18)",
	"ECDSA public key algorithm (pub 19)",
	"Reserved (formerly Elgamal Encrypt or Sign) (pub 20)",
	"Reserved for Diffie-Hellman (pub 21)",
	"EdDSA (pub 22)",
	"Unknown (pub 23)",
}

func TestPubAlg(t *testing.T) {
	for tag := 0; tag <= 23; tag++ {
		i := PubAlg(tag).Get()
		if i.Name != "Public-key Algorithm" {
			t.Errorf("PubAlg.Name = \"%s\", want \"Public-key Algorithm\".", i.Name)
		}
		if i.Value != testPubAlgNames[tag] {
			t.Errorf("PubAlg.Value = \"%s\", want \"%s\".", i.Value, testPubAlgNames[tag])
		}
		if i.Note != "" {
			t.Errorf("PubAlg.Note = \"%s\", want \"\"", i.Note)
		}
		if i.Dump != "" {
			t.Errorf("PubAlg.Dump = \"%s\", want \"\".", i.Dump)
		}
	}
	for tag := 100; tag <= 110; tag++ {
		i := PubAlg(tag).Get()
		value := fmt.Sprintf("Private/Experimental algorithm (pub %d)", tag)
		if i.Value != value {
			t.Errorf("PubAlg.Value = \"%s\", want \"%s\".", i.Value, value)
		}
	}
}

func TestPubAlgRSA(t *testing.T) {
	for tag := 0; tag <= 23; tag++ {
		pub := PubAlg(tag)
		switch tag {
		case 1, 2, 3:
			if !pub.IsRSA() {
				t.Errorf("PubAlg.IsRSA(%d) = %v, want true.", tag, pub.IsRSA())
			}
		default:
			if pub.IsRSA() {
				t.Errorf("PubAlg.IsRSA(%d) = %v, want false.", tag, pub.IsRSA())
			}
		}
	}
}

func TestPubAlgDSA(t *testing.T) {
	for tag := 0; tag <= 23; tag++ {
		pub := PubAlg(tag)
		switch tag {
		case 17:
			if !pub.IsDSA() {
				t.Errorf("PubAlg.IsDSA(%d) = %v, want true.", tag, pub.IsDSA())
			}
		default:
			if pub.IsDSA() {
				t.Errorf("PubAlg.IsDSA(%d) = %v, want false.", tag, pub.IsDSA())
			}
		}
	}
}

func TestPubAlgElgamal(t *testing.T) {
	for tag := 0; tag <= 23; tag++ {
		pub := PubAlg(tag)
		switch tag {
		case 16, 20:
			if !pub.IsElgamal() {
				t.Errorf("PubAlg.IsElgamal(%d) = %v, want true.", tag, pub.IsElgamal())
			}
		default:
			if pub.IsElgamal() {
				t.Errorf("PubAlg.IsElgamal(%d) = %v, want false.", tag, pub.IsElgamal())
			}
		}
	}
}

func TestPubAlgECDH(t *testing.T) {
	for tag := 0; tag <= 23; tag++ {
		pub := PubAlg(tag)
		switch tag {
		case 18:
			if !pub.IsECDH() {
				t.Errorf("PubAlg.IsECDH(%d) = %v, want true.", tag, pub.IsECDH())
			}
		default:
			if pub.IsECDH() {
				t.Errorf("PubAlg.IsECDH(%d) = %v, want false.", tag, pub.IsECDH())
			}
		}
	}
}

func TestPubAlgECDSA(t *testing.T) {
	for tag := 0; tag <= 23; tag++ {
		pub := PubAlg(tag)
		switch tag {
		case 19:
			if !pub.IsECDSA() {
				t.Errorf("PubAlg.IsECDSA(%d) = %v, want true.", tag, pub.IsECDSA())
			}
		default:
			if pub.IsECDSA() {
				t.Errorf("PubAlg.IsECDSA(%d) = %v, want false.", tag, pub.IsECDSA())
			}
		}
	}
}

var testSymAlgNames = []string{
	"Plaintext or unencrypted data (sym 0)",
	"IDEA (sym 1)",
	"TripleDES (168 bit key derived from 192) (sym 2)",
	"CAST5 (sym 3)",
	"Blowfish (sym 4)",
	"Reserved (sym 5)",
	"Reserved (sym 6)",
	"AES with 128-bit key (sym 7)",
	"AES with 192-bit key (sym 8)",
	"AES with 256-bit key (sym 9)",
	"Twofish with 256-bit key (sym 10)",
	"Camellia with 128-bit key (sym 11)",
	"Camellia with 192-bit key (sym 12)",
	"Camellia with 256-bit key (sym 13)",
	"Unknown (sym 14)",
}

func TestSymAlg(t *testing.T) {
	for tag := 0; tag <= 14; tag++ {
		i := SymAlg(tag).Get()
		if i.Name != "Symmetric Algorithm" {
			t.Errorf("SymAlg.Name = \"%s\", want \"Symmetric Algorithm\".", i.Name)
		}
		if i.Value != testSymAlgNames[tag] {
			t.Errorf("SymAlg.Value = \"%s\", want \"%s\".", i.Value, testSymAlgNames[tag])
		}
		if i.Note != "" {
			t.Errorf("SymAlg.Note = \"%s\", want \"\"", i.Note)
		}
		if i.Dump != "" {
			t.Errorf("SymAlg.Dump = \"%s\", want \"\".", i.Dump)
		}
	}
	for tag := 100; tag <= 110; tag++ {
		i := SymAlg(tag).Get()
		value := fmt.Sprintf("Private/Experimental algorithm (sym %d)", tag)
		if i.Value != value {
			t.Errorf("SymAlg.Value = \"%s\", want \"%s\".", i.Value, value)
		}
	}
}

var testSymAlgIVLen = []int{
	8,  //Plaintext or unencrypted data
	8,  //IDEA
	8,  //TripleDES (168 bit key derived from 192)
	8,  //CAST5
	8,  //Blowfish
	8,  //Reserved
	8,  //Reserved
	16, //AES with 128-bit key
	16, //AES with 192-bit key
	16, //AES with 256-bit key
	16, //Twofish with 256-bit key
	16, //Camellia with 128-bit key
	16, //Camellia with 192-bit key
	16, //Camellia with 256-bit key
	0,  //Unknown
}

func TestSymAlgIVLen(t *testing.T) {
	for tag := 0; tag <= 14; tag++ {
		v := SymAlg(tag)
		if v.IVLen() != testSymAlgIVLen[tag] {
			t.Errorf("SymAlg.IVLen(%d) = %d, want %d.", tag, v.IVLen(), testSymAlgIVLen[tag])
		}
	}
}

var testHashAlgNames = []string{
	"Unknown (hash 0)",
	"MD5 (hash 1)",
	"SHA-1 (hash 2)",
	"RIPE-MD/160 (hash 3)",
	"Reserved (hash 4)",
	"Reserved (hash 5)",
	"Reserved (hash 6)",
	"Reserved (hash 7)",
	"SHA256 (hash 8)",
	"SHA384 (hash 9)",
	"SHA512 (hash 10)",
	"SHA224 (hash 11)",
	"Unknown (hash 12)",
}

func TestHashAlg(t *testing.T) {
	for tag := 0; tag <= 12; tag++ {
		i := HashAlg(tag).Get()
		if i.Name != "Hash Algorithm" {
			t.Errorf("HashAlg.Name = \"%s\", want \"Hash Algorithm\".", i.Name)
		}
		if i.Value != testHashAlgNames[tag] {
			t.Errorf("HashAlg.Value = \"%s\", want \"%s\".", i.Value, testHashAlgNames[tag])
		}
		if i.Note != "" {
			t.Errorf("HashAlg.Note = \"%s\", want \"\"", i.Note)
		}
		if i.Dump != "" {
			t.Errorf("HashAlg.Dump = \"%s\", want \"\".", i.Dump)
		}
	}
	for tag := 100; tag <= 110; tag++ {
		i := HashAlg(tag).Get()
		value := fmt.Sprintf("Private/Experimental algorithm (hash %d)", tag)
		if i.Value != value {
			t.Errorf("HashAlg.Value = \"%s\", want \"%s\".", i.Value, value)
		}
	}
}

var testS2kAlgNames = []string{
	"Simple S2K (s2k 0)",
	"Salted S2K (s2k 1)",
	"Reserved (s2k 2)",
	"Iterated and Salted S2K (s2k 3)",
	"Unknown (s2k 4)",
}

func TestS2KAlg(t *testing.T) {
	for tag := 0; tag <= 4; tag++ {
		i := S2KAlg(tag).Get()
		if i.Name != "String-to-Key (S2K) Algorithm" {
			t.Errorf("S2KAlg.Name = \"%s\", want \"String-to-Key (S2K) Algorithm\".", i.Name)
		}
		if i.Value != testS2kAlgNames[tag] {
			t.Errorf("S2KAlg.Value = \"%s\", want \"%s\".", i.Value, testS2kAlgNames[tag])
		}
		if i.Note != "" {
			t.Errorf("S2KAlg.Note = \"%s\", want \"\"", i.Note)
		}
		if i.Dump != "" {
			t.Errorf("S2KAlg.Dump = \"%s\", want \"\".", i.Dump)
		}
	}
	for tag := 100; tag <= 110; tag++ {
		i := S2KAlg(tag).Get()
		value := fmt.Sprintf("Private/Experimental algorithm (s2k %d)", tag)
		if i.Value != value {
			t.Errorf("S2KAlg.Value = \"%s\", want \"%s\".", i.Value, value)
		}
	}
}

var testCompAlgNames = []string{
	"Uncompressed (comp 0)",
	"ZIP (comp 1)",
	"ZLIB (comp 2)",
	"BZip2 (comp 3)",
	"Unknown (comp 4)",
}

func TestCompAlg(t *testing.T) {
	for tag := 0; tag <= 4; tag++ {
		i := CompAlg(tag).Get()
		if i.Name != "Compression Algorithm" {
			t.Errorf("CompAlg.Name = \"%s\", want \"Compression Algorithm\".", i.Name)
		}
		if i.Value != testCompAlgNames[tag] {
			t.Errorf("CompAlg.Value = \"%s\", want \"%s\".", i.Value, testCompAlgNames[tag])
		}
		if i.Note != "" {
			t.Errorf("CompAlg.Note = \"%s\", want \"\"", i.Note)
		}
		if i.Dump != "" {
			t.Errorf("CompAlg.Dump = \"%s\", want \"\".", i.Dump)
		}
	}
}
