package parse

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp/packet"
)

// Indent is indent size
type Indent int

// Fill space for Indent
func (ind Indent) Fill(str string) string {
	return ind.String() + str
}

func (ind Indent) String() string {
	if ind <= 0 {
		return ""
	}
	return strings.Repeat("\t", int(ind))
}

// Tag is tag ID of packet
type Tag int

func (t Tag) String() string {
	switch t {
	case 0:
		return "Reserved(tag 0)"
	case 1:
		return "Public-Key Encrypted Session Key Packet(tag 1)"
	case 2:
		return "Signature Packet(tag 2)"
	case 3:
		return "Symmetric-Key Encrypted Session Key Packet(tag 3)"
	case 4:
		return "One-Pass Signature Packet(tag 4)"
	case 5:
		return "Secret-Key Packet(tag 5)"
	case 6:
		return "Public-Key Packet(tag 6)"
	case 7:
		return "Secret-Subkey Packet(tag 7)"
	case 8:
		return "Compressed Data Packet(tag 8)"
	case 9:
		return "Symmetrically Encrypted Data Packet(tag 9)"
	case 10:
		return "Marker Packet(tag 10)"
	case 11:
		return "Literal Data Packet(tag 11)"
	case 12:
		return "Trust Packet(tag 12)"
	case 13:
		return "User ID Packet(tag 13)"
	case 14:
		return "Public-Subkey Packet(tag 14)"
	case 17:
		return "User Attribute Packet(tag 17)"
	case 18:
		return "Sym. Encrypted and Integrity Protected Data Packet(tag 18)"
	case 19:
		return "Modification Detection Code Packet(tag 19)"
	case 60, 61, 62, 63:
		return fmt.Sprintf("Private or Experimental Values(tag %d)", t)
	default:
		return fmt.Sprintf("Unknown(tag %d)", t)
	}
}

// StringPacketInfo returns string of packet information
func StringPacketInfo(oPacket *packet.OpaquePacket) string {
	tag := Tag(oPacket.Tag)
	size := len(oPacket.Contents)
	return fmt.Sprintf("%v(%d bytes)", tag, size)
}

// SigVer is Signiture Version
type SigVer byte

// IsOld return true if old version
func (v SigVer) IsOld() bool {
	return (v == 2 || v == 3)
}

// IsNew return true if new version
func (v SigVer) IsNew() bool {
	return (v == 4)
}

func (v SigVer) String() string {
	switch true {
	case v.IsOld():
		return fmt.Sprintf("%d - old", byte(v))
	case v.IsNew():
		return fmt.Sprintf("%d - new", byte(v))
	default:
		return fmt.Sprintf("%d - unknown", byte(v))
	}
}

// SigType is Signiture Type
type SigType byte

func (s SigType) String() string {
	switch s {
	case 0x00:
		return "Signature of a binary document(0x00)"
	case 0x01:
		return "Signature of a canonical text document(0x01)."
	case 0x02:
		return "Standalone signature(0x02)."
	case 0x10:
		return "Generic certification of a User ID and Public-Key packet(0x10)."
	case 0x11:
		return "Persona certification of a User ID and Public-Key packet(0x11)."
	case 0x12:
		return "Casual certification of a User ID and Public-Key packet(0x12)."
	case 0x13:
		return "Positive certification of a User ID and Public-Key packet(0x13)."
	case 0x18:
		return "Subkey Binding Signature(0x18)."
	case 0x19:
		return "Primary Key Binding Signature(0x19)."
	case 0x1f:
		return "Signature directly on a key(0x1f)."
	case 0x20:
		return "Key revocation signature(0x20)."
	case 0x28:
		return "Subkey revocation signature(0x28)."
	case 0x30:
		return "Certification revocation signature(0x30)."
	case 0x40:
		return "Timestamp signature(0x40)."
	case 0x50:
		return "Third-Party Confirmation signature(0x50)."
	default:
		return fmt.Sprintf("Unknown(0x%02x)", byte(s))
	}
}

// KeyID is Key ID
type KeyID uint64

func (kid KeyID) String() string {
	return fmt.Sprintf("0x%X", uint64(kid))
}

// PubAlg is Public-Key Algorithm ID
type PubAlg uint8

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

func (pa PubAlg) String() string {
	if 100 <= pa && pa <= 110 {
		return fmt.Sprintf("Private/Experimental algorithm(pub %d)", pa)
	}
	switch pa {
	case 1:
		return "RSA (Encrypt or Sign)(pub 1)"
	case 2:
		return "RSA Encrypt-Only(pub 2)"
	case 3:
		return "RSA Sign-Only(pub 3)"
	case 16:
		return "Elgamal (Encrypt-Only)(pub 16)"
	case 17:
		return "DSA (Digital Signature Algorithm)(pub 17)"
	case 18:
		return "ECDH public key algorithm(pub 18)"
	case 19:
		return "ECDSA public key algorithm(pub 19)"
	case 20:
		return "Reserved (formerly Elgamal Encrypt or Sign)(pub 20)"
	case 21:
		return "Reserved for Diffie-Hellman(pub 21)"
	case 22:
		return "EdDSA(pub 22)"
	default:
		return fmt.Sprintf("Unknown(pub %d)", pa)
	}
}

// HashAlg is Hash Algorithm ID
type HashAlg uint8

func (ha HashAlg) String() string {
	if 100 <= ha && ha <= 110 {
		return fmt.Sprintf("Private/Experimental algorithm(hash %d)", ha)
	}
	switch ha {
	case 1:
		return "MD5(hash 1)"
	case 2:
		return "SHA-1(hash 2)"
	case 3:
		return "RIPE-MD/160(hash 3)"
	case 4:
		return "Reserved(hash 4)"
	case 5:
		return "Reserved(hash 5)"
	case 6:
		return "Reserved(hash 6)"
	case 7:
		return "Reserved(hash 7)"
	case 8:
		return "SHA256(hash 8)"
	case 9:
		return "SHA384(hash 9)"
	case 10:
		return "SHA512(hash 10)"
	case 11:
		return "SHA224(hash 11)"
	default:
		return fmt.Sprintf("Unknown(hash %d)", ha)
	}
}

// LiteralFormat is format of literal data
type LiteralFormat byte

func (l LiteralFormat) String() string {
	switch l {
	case 0x62: //'b'
		return "binary"
	case 0x74: //'t'
		return "text"
	case 0x75: //'u'
		return "UTF-8 text"
	case 0x31, 0x6c: //'l' -- RFC 1991 incorrectly stated this local mode flag as '1' (ASCII numeral one). Both of these local modes are deprecated.
		return "local"
	default:
		return "unknown"
	}
}

// StringRFC3339UNIX returns time string from UNIX Time
func StringRFC3339UNIX(u uint32, utc bool) string {
	return StringRFC3339(time.Unix(int64(u), 0), utc)
}

// StringRFC3339 returns time string from UNIX Time
func StringRFC3339(t time.Time, utc bool) string {
	if utc {
		t = t.In(time.UTC)
	}
	return t.Format(time.RFC3339)
}

// Octets2Int returns integer from two-octets data
func Octets2Int(octets []byte) uint64 {
	rtn := uint64(0)
	if len(octets) <= 8 {
		for _, o := range octets {
			rtn = (rtn << 8) | uint64(o)
		}
	}
	return rtn
}

// DumpByte returns string byte-data
func DumpByte(data []byte) string {
	sep := ""
	var buf = make([]byte, 0, 16)
	for _, b := range data {
		buf = append(buf, fmt.Sprintf("%s%02x", sep, b)...)
		sep = " "
	}
	return string(buf)
}
