package values

import (
	"fmt"

	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

var tagNames = Msgs{
	0:  "Reserved",
	1:  "Public-Key Encrypted Session Key Packet",
	2:  "Signature Packet",
	3:  "Symmetric-Key Encrypted Session Key Packet",
	4:  "One-Pass Signature Packet",
	5:  "Secret-Key Packet",
	6:  "Public-Key Packet",
	7:  "Secret-Subkey Packet",
	8:  "Compressed Data Packet",
	9:  "Symmetrically Encrypted Data Packet",
	10: "Marker Packet (Obsolete Literal Packet)",
	11: "Literal Data Packet",
	12: "Trust Packet",
	13: "User ID Packet",
	14: "Public-Subkey Packet",
	17: "User Attribute Packet",
	18: "Sym. Encrypted Integrity Protected Data Packet",
	19: "Modification Detection Code Packet",
	60: "Private or Experimental Values",
	61: "Private or Experimental Values",
	62: "Private or Experimental Values",
	63: "Private or Experimental Values",
}

// Tag is tag ID of packet
type Tag int

// Get returns Item instance
func (t Tag) Get(size int) *items.Item {
	return items.NewItem("Packet", fmt.Sprintf("%s (tag %d)", tagNames.Get(int(t), "Unknown"), t), fmt.Sprintf("%d bytes", size), "")
}

var sigTypeNames = Msgs{
	0x00: "Signature of a binary document",
	0x01: "Signature of a canonical text document",
	0x02: "Standalone signature",
	0x10: "Generic certification of a User ID and Public-Key packet",
	0x11: "Persona certification of a User ID and Public-Key packet",
	0x12: "Casual certification of a User ID and Public-Key packet",
	0x13: "Positive certification of a User ID and Public-Key packet",
	0x18: "Subkey Binding Signature",
	0x19: "Primary Key Binding Signature",
	0x1f: "Signature directly on a key",
	0x20: "Key revocation signature",
	0x28: "Subkey revocation signature",
	0x30: "Certification revocation signature",
	0x40: "Timestamp signature",
	0x50: "Third-Party Confirmation signature",
}

// SigType is Signiture Type
type SigType byte

// Get returns Item instance
func (s SigType) Get() *items.Item {
	return items.NewItem("Signiture Type", fmt.Sprintf("%s (0x%02x)", sigTypeNames.Get(int(s), "Unknown"), s), "", fmt.Sprintf("%02x", byte(s)))
}

var pubAlgNames = Msgs{
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
}

// PubAlg is Public-Key Algorithm ID
type PubAlg byte

// Get returns Item instance
func (pa PubAlg) Get() *items.Item {
	var name string
	if 100 <= pa && pa <= 110 {
		name = "Private/Experimental algorithm"
	} else {
		name = pubAlgNames.Get(int(pa), "Unknown")
	}
	return items.NewItem("Public-key algorithm", fmt.Sprintf("%s (pub %d)", name, pa), "", fmt.Sprintf("%02x", byte(pa)))
}

// IsRSA returns if RSA algorithm.
func (pa PubAlg) IsRSA() bool {
	return (1 <= pa && pa <= 3)
}

// IsDSA returns if DSA algorithm.
func (pa PubAlg) IsDSA() bool {
	return (pa == 17)
}

// IsElgamal returns if Elgamal algorithm.
func (pa PubAlg) IsElgamal() bool {
	return (pa == 16 || pa == 20)
}

// IsECDH returns if ECDH algorithm.
func (pa PubAlg) IsECDH() bool {
	return (pa == 18)
}

// IsECDSA returns if ECDSA algorithm.
func (pa PubAlg) IsECDSA() bool {
	return (pa == 19)
}

var symAlgNames = Msgs{
	0:  "Plaintext or unencrypted data",
	1:  "IDEA",
	2:  "TripleDES (168 bit key derived from 192)",
	3:  "CAST5",
	4:  "Blowfish",
	5:  "Reserved",
	6:  "Reserved",
	7:  "AES with 128-bit key",
	8:  "AES with 192-bit key",
	9:  "AES with 256-bit key",
	10: "Twofish with 256-bit key",
	11: "Camellia with 128-bit key",
	12: "Camellia with 192-bit key",
	13: "Camellia with 256-bit key",
}

//SymAlg is Symmetric-Key Algorithm ID
type SymAlg byte

// Get returns Item instance
func (s SymAlg) Get() *items.Item {
	var name string
	if 100 <= s && s <= 110 {
		name = "Private/Experimental algorithm"
	} else {
		name = symAlgNames.Get(int(s), "Unknown")
	}
	return items.NewItem("Symmetric algorithm", fmt.Sprintf("%s (sym %d)", name, s), "", fmt.Sprintf("%02x", byte(s)))
}

var hashAlgNames = Msgs{
	0:  "Unknown",
	1:  "MD5",
	2:  "SHA-1",
	3:  "RIPE-MD/160",
	4:  "Reserved",
	5:  "Reserved",
	6:  "Reserved",
	7:  "Reserved",
	8:  "SHA256",
	9:  "SHA384",
	10: "SHA512",
	11: "SHA224",
}

// HashAlg is Hash Algorithm ID
type HashAlg byte

// Get returns Item instance
func (ha HashAlg) Get() *items.Item {
	var name string
	if 100 <= ha && ha <= 110 {
		name = "Private/Experimental algorithm"
	} else {
		name = hashAlgNames.Get(int(ha), "Unknown")
	}
	return items.NewItem("Hash algorithm", fmt.Sprintf("%s (hash %d)", name, ha), "", fmt.Sprintf("%02x", byte(ha)))
}

var s2kAlgNames = Msgs{
	0: "Simple S2K",
	1: "Salted S2K",
	2: "Reserved valu",
	3: "Iterated and Salted S2K",
}

// S2KAlg is S2K Algorithm ID
type S2KAlg byte

// Get returns Item instance
func (sa S2KAlg) Get() *items.Item {
	var name string
	if 100 <= sa && sa <= 110 {
		name = "Private/Experimental S2K"
	} else {
		name = s2kAlgNames.Get(int(sa), "Unknown")
	}
	return items.NewItem("String-to-Key (S2K) algorithm", fmt.Sprintf("%s (s2k %d)", name, sa), "", fmt.Sprintf("%02x", byte(sa)))
}

var compAlgNames = Msgs{
	0: "Uncompressed",
	1: "ZIP",
	2: "ZLIB",
	3: "BZip2",
}

// CompAlg is Compression Algorithm ID
type CompAlg byte

// Get returns Item instance
func (ca CompAlg) Get() *items.Item {
	return items.NewItem("Compression algorithms", fmt.Sprintf("%s (comp %d)", compAlgNames.Get(int(ca), "Unknown"), ca), "", fmt.Sprintf("%02x", byte(ca)))
}
