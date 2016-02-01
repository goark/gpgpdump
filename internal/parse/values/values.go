package values

import (
	"bytes"
	"fmt"
	"strings"
	"time"
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

//Content is output strings
type Content []string

//NewContent returns Content.
func NewContent() Content {
	return make(Content, 0, 8)
}

func (c Content) String() string {
	if c == nil {
		return ""
	}
	buf := bytes.NewBuffer(make([]byte, 0, 128))
	for _, l := range c {
		buf.WriteString(l)
		buf.WriteByte('\n')
	}
	return string(buf.Bytes())
}

//Add adding Content
func (c Content) Add(a Content) Content {
	if a != nil {
		return append(c, a...)
	}
	return c
}

//AddIndent adding Content with indent
func (c Content) AddIndent(a Content, i Indent) Content {
	if a != nil {
		for _, l := range a {
			c = append(c, i.Fill(l))
		}
	}
	return c
}

//Msgs is type of message list.
type Msgs map[int]string

//Get returns message.
func (m Msgs) Get(i int, def string) string {
	if msg, ok := m[i]; ok {
		return msg
	}
	return def
}

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

func (t Tag) String() string {
	return fmt.Sprintf("%s (tag %d)", tagNames.Get(int(t), "Unknown"), t)
}

// PubVer is Public-Key Packet Version
type PubVer byte

// IsOld return true if old version
func (v PubVer) IsOld() bool {
	return (v == 2 || v == 3)
}

// IsNew return true if new version
func (v PubVer) IsNew() bool {
	return (v == 4)
}

func (v PubVer) String() string {
	var t string
	switch true {
	case v.IsOld():
		t = "old"
	case v.IsNew():
		t = "new"
	default:
		t = "unknown"
	}
	return fmt.Sprintf("Ver %d - %s", v, t)
}

// SigVer is Signiture Packet Version
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
	var t string
	switch true {
	case v.IsOld():
		t = "old"
	case v.IsNew():
		t = "new"
	default:
		t = "unknown"
	}
	return fmt.Sprintf("Ver %d - %s", v, t)
}

// PubSymKeyVer is Public-Key Encrypted Session Key Packet Version
type PubSymKeyVer byte

func (v PubSymKeyVer) String() string {
	var t string
	switch v {
	case 2:
		t = "old"
	case 3:
		t = "new"
	default:
		t = "unknown"
	}
	return fmt.Sprintf("Ver %d - %s", v, t)
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

func (s SigType) String() string {
	return fmt.Sprintf("%s (%02x)", sigTypeNames.Get(int(s), "Unknown"), byte(s))
}

// KeyID is Key ID
type KeyID uint64

func (kid KeyID) String() string {
	return fmt.Sprintf("Key ID - 0x%X", uint64(kid))
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

func (pa PubAlg) String() string {
	var name string
	if 100 <= pa && pa <= 110 {
		name = "Private/Experimental algorithm"
	} else {
		name = pubAlgNames.Get(int(pa), "Unknown")
	}
	return fmt.Sprintf("Public-key algorithm - %s (pub %d)", name, pa)
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

func (s SymAlg) String() string {
	var name string
	if 100 <= s && s <= 110 {
		name = "Private/Experimental algorithm"
	} else {
		name = symAlgNames.Get(int(s), "Unknown")
	}
	return fmt.Sprintf("Symmetric algorithm - %s (sym %d)", name, s)
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

func (ha HashAlg) String() string {
	var name string
	if 100 <= ha && ha <= 110 {
		name = "Private/Experimental algorithm"
	} else {
		name = hashAlgNames.Get(int(ha), "Unknown")
	}
	return fmt.Sprintf("Hash algorithm - %s (hash %d)", name, ha)
}

var compAlgNames = Msgs{
	0: "Uncompressed",
	1: "ZIP",
	2: "ZLIB",
	3: "BZip2",
}

// CompAlg is Compression Algorithm ID
type CompAlg byte

func (ca CompAlg) String() string {
	return fmt.Sprintf("%s (comp %d)", compAlgNames.Get(int(ca), "Unknown"), ca)
}

var literalFormatNames = Msgs{
	0x62: "binary",     //'b'
	0x74: "text",       //'t'
	0x75: "UTF-8 text", //'u'
	0x31: "local",      //'l' -- RFC 1991 incorrectly stated this local mode flag as '1' (ASCII numeral one). Both of these local modes are deprecated.
	0x6c: "local",      //'l'
}

// LiteralFormat is format of literal data
type LiteralFormat byte

func (l LiteralFormat) String() string {
	return literalFormatNames.Get(int(l), "unknown")
}

// StringRFC3339UNIX returns time string from UNIX Time (uint32)
func StringRFC3339UNIX(u uint32, utc bool) string {
	return StringRFC3339UNIX64(int64(u), utc)
}

// StringRFC3339UNIX64 returns time string from UNIX Time (int64)
func StringRFC3339UNIX64(u int64, utc bool) string {
	return StringRFC3339(time.Unix(u, 0), utc)
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

// Octets2IntLE returns integer from two-octets data (by little endian)
func Octets2IntLE(octets []byte) uint16 {
	rtn := uint16(0)
	if len(octets) == 2 {
		rtn = (uint16(octets[1]) << 8) | uint16(octets[0])
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
