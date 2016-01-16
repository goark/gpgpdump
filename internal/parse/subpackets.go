package parse

import (
	"fmt"

	"golang.org/x/crypto/openpgp/packet"
)

var subpacketName = []string{
	"Reserved",                               //00
	"Reserved",                               //01
	"Signature Creation Time",                //02
	"Signature Expiration Time",              //03
	"Exportable Certification",               //04
	"Trust Signature",                        //05
	"Regular Expression",                     //06
	"Revocable",                              //07
	"Reserved",                               //08
	"Key Expiration Time",                    //09
	"Placeholder for backward compatibility", //10
	"Preferred Symmetric Algorithms",         //11
	"Revocation Key",                         //12
	"Reserved",                               //13
	"Reserved",                               //14
	"Reserved",                               //15
	"Issuer",                                 //16
	"Reserved",                               //17
	"Reserved",                               //18
	"Reserved",                               //19
	"Notation Data",                          //20
	"Preferred Hash Algorithms",              //21
	"Preferred Compression Algorithms",       //22
	"Key Server Preferences",                 //23
	"Preferred Key Server",                   //24
	"Primary User ID",                        //25
	"Policy URI",                             //26
	"Key Flags",                              //27
	"Signer's User ID",                       //28
	"Reason for Revocation",                  //29
	"Features",                               //30
	"Signature Target",                       //31
	"Embedded Signature",                     //32
}

// SubpacketType is sub-packet type
type SubpacketType byte

func (s SubpacketType) String() string {
	name := "Unknown"
	if 100 <= s && s <= 110 {
		name = "Private or experimental"
	} else if int(s) < len(subpacketName) {
		name = subpacketName[s]
	}
	return fmt.Sprintf("%s(sub %d)", name, s)
}

// ParseSubpacket is function value of parsing sub-packet
type parseSubpacket func(*Subpackets, *packet.OpaqueSubpacket) []string

var parseSubpacketFunctions = []parseSubpacket{
	parseSPReserved,
	parseSPReserved,
	parseSPType02,
	parseSPType03,
	parseSPType04,
	parseSPType05,
	parseSPType06,
	parseSPType07,
	parseSPReserved,
	parseSPType09,
	parseSPType10,
	parseSPType11,
	parseSPType12,
	parseSPReserved,
	parseSPReserved,
	parseSPReserved,
	parseSPType16,
	parseSPReserved,
	parseSPReserved,
	parseSPReserved,
	parseSPType20,
	parseSPType21,
	parseSPType22,
	parseSPType23,
	parseSPType24,
	parseSPType25,
	parseSPType26,
	parseSPType27,
	parseSPType28,
	parseSPType29,
	parseSPType30,
	parseSPType31,
	parseSPType32,
}

// Subpackets - Sub-Packets
type Subpackets struct {
	*Options
	Title            string
	OpaqueSubpackets []*packet.OpaqueSubpacket
	SigCreationTime  int64
	KeyCreationTime  int64
}

//Parse parsing sub-packets
func (sp *Subpackets) Parse(indent Indent) []string {
	var content = make([]string, 0)
	for _, pckt := range sp.OpaqueSubpackets {
		st := SubpacketType(pckt.SubType)
		content = append(content, indent.Fill(sp.info(pckt)))
		if int(st) < len(parseSubpacketFunctions) {
			strs := parseSubpacketFunctions[st](sp, pckt)
			if strs != nil {
				for _, str := range strs {
					content = append(content, (indent + 1).Fill(str))
				}
			}
		}
	}
	return content
}

func (sp *Subpackets) info(op *packet.OpaqueSubpacket) string {
	sptype := SubpacketType(op.SubType)
	size := len(op.Contents)
	return fmt.Sprintf("%s %v(%d bytes)", sp.Title, sptype, size)
}

func parseSPReserved(sp *Subpackets, op *packet.OpaqueSubpacket) []string {
	return nil
}

//Signature Creation Time
func parseSPType02(sp *Subpackets, op *packet.OpaqueSubpacket) []string {
	var content = make([]string, 0)
	sp.SigCreationTime = int64(Octets2Int(op.Contents))
	content = append(content, StringRFC3339UNIX64(sp.SigCreationTime, sp.Options.Uflag))
	return content
}

//Signature Expiration Time
func parseSPType03(sp *Subpackets, op *packet.OpaqueSubpacket) []string {
	var content = make([]string, 0)
	expire := sp.SigCreationTime + int64(Octets2Int(op.Contents))
	content = append(content, StringRFC3339UNIX64(expire, sp.Options.Uflag))
	return content
}

//Exportable Certification
func parseSPType04(sp *Subpackets, op *packet.OpaqueSubpacket) []string {
	var content = make([]string, 0)
	if op.Contents[0] == 0x00 {
		content = append(content, "Not exportable")
	} else {
		content = append(content, "Exportable")
	}
	return content
}

//Trust Signature
func parseSPType05(sp *Subpackets, op *packet.OpaqueSubpacket) []string {
	var content = make([]string, 0)
	content = append(content, fmt.Sprintf("Level - %d", op.Contents[0]))
	content = append(content, fmt.Sprintf("Trust amount - %d", op.Contents[2]))
	return content
}

//Regular Expression
func parseSPType06(sp *Subpackets, op *packet.OpaqueSubpacket) []string {
	var content = make([]string, 0)
	content = append(content, string(op.Contents))
	return content
}

//Revocable
func parseSPType07(sp *Subpackets, op *packet.OpaqueSubpacket) []string {
	var content = make([]string, 0)
	if op.Contents[0] == 0x00 {
		content = append(content, "Not revocable")
	} else {
		content = append(content, "Revocable")
	}
	return content
}

//Key Expiration Time
func parseSPType09(sp *Subpackets, op *packet.OpaqueSubpacket) []string {
	var content = make([]string, 0)
	expire := sp.KeyCreationTime + int64(Octets2Int(op.Contents))
	content = append(content, StringRFC3339UNIX64(expire, sp.Options.Uflag))
	return content
}

//Placeholder for backward compatibility
func parseSPType10(sp *Subpackets, op *packet.OpaqueSubpacket) []string {
	return nil
}

//Preferred Symmetric Algorithms
func parseSPType11(sp *Subpackets, op *packet.OpaqueSubpacket) []string {
	var content = make([]string, 0)
	for _, c := range op.Contents {
		content = append(content, SymAlg(c).String())
	}
	return content
}

//Revocation Key
func parseSPType12(sp *Subpackets, op *packet.OpaqueSubpacket) []string {
	var content = make([]string, 0)
	class := op.Contents[0]
	pub := PubAlg(op.Contents[1])
	fingerprint := op.Contents[2:]

	className := "Unknown"
	if (class & 0x80) != 0x00 {
		switch true {
		case (class & 0x40) != 0x00:
			className = "Sensitive"
		default:
			className = "Normal"
		}
	}
	content = append(content, fmt.Sprintf("Class - %s", className))
	content = append(content, fmt.Sprintf("Public-key algorithm - %v", pub))
	content = append(content, fmt.Sprintf("Fingerprint - %v", DumpByte(fingerprint)))
	return content
}

//Issuer
func parseSPType16(sp *Subpackets, op *packet.OpaqueSubpacket) []string {
	var content = make([]string, 0)
	keyID := KeyID(Octets2Int(op.Contents))
	content = append(content, fmt.Sprintf("Key ID - %v", keyID))
	return content
}

//Notation Data
func parseSPType20(sp *Subpackets, op *packet.OpaqueSubpacket) []string {
	var content = make([]string, 0)
	flags := op.Contents[0:4]
	nameLength := int(Octets2Int(op.Contents[4:6]))
	valueLength := int(Octets2Int(op.Contents[6:8]))
	name := op.Contents[8 : 8+nameLength]
	value := op.Contents[8+nameLength : 8+nameLength+valueLength]

	human := flags[0] & 0x80
	content = append(content, fmt.Sprintf("%s", stringFlagInfo(human, "Human-readable")))
	if (flags[0] & 0x7f) != 0x00 {
		content = append(content, fmt.Sprintf("%s", stringFlagInfo(flags[0]&0x7f, fmt.Sprintf("Unknown flag1(0x%02x)", flags[0]))))
	}
	if flags[1] != 0x00 {
		content = append(content, fmt.Sprintf("%s", stringFlagInfo(flags[1], fmt.Sprintf("Unknown flag2(0x%02x)", flags[1]))))
	}
	if flags[2] != 0x00 {
		content = append(content, fmt.Sprintf("%s", stringFlagInfo(flags[2], fmt.Sprintf("Unknown flag3(0x%02x)", flags[2]))))
	}
	if flags[3] != 0x00 {
		content = append(content, fmt.Sprintf("%s", stringFlagInfo(flags[4], fmt.Sprintf("Unknown flag4(0x%02x)", flags[3]))))
	}
	content = append(content, fmt.Sprintf("Name - %s", string(name)))
	if human != 0x00 {
		content = append(content, fmt.Sprintf("Value - %v", string(value)))
	} else {
		content = append(content, fmt.Sprintf("Value - %v", DumpByte(value)))
	}
	return content
}

//Preferred Hash Algorithms
func parseSPType21(sp *Subpackets, op *packet.OpaqueSubpacket) []string {
	var content = make([]string, 0)
	for _, c := range op.Contents {
		content = append(content, HashAlg(c).String())
	}
	return content
}

//Preferred Compression Algorithms
func parseSPType22(sp *Subpackets, op *packet.OpaqueSubpacket) []string {
	var content = make([]string, 0)
	for _, c := range op.Contents {
		content = append(content, CompAlg(c).String())
	}
	return content
}

//Key Server Preferences
func parseSPType23(sp *Subpackets, op *packet.OpaqueSubpacket) []string {
	var content = make([]string, 0)
	flag1 := op.Contents[0]

	content = append(content, fmt.Sprintf("%s", stringFlagInfo(flag1&0x80, "No-modify")))
	if (flag1 & 0x7f) != 0x00 {
		content = append(content, fmt.Sprintf("%s", stringFlagInfo(flag1&0x7f, fmt.Sprintf("Unknown flag1(0x%02x)", flag1))))
	}
	if len(op.Contents) > 1 {
		flags := op.Contents[1:]
		for i, flag := range flags {
			if flag != 0x00 {
				content = append(content, fmt.Sprintf("%s", stringFlagInfo(flag, fmt.Sprintf("Unknown flag%d(0x%02x)", i+2, flag))))
			}
		}
	}
	return content
}

//Preferred Key Server
func parseSPType24(sp *Subpackets, op *packet.OpaqueSubpacket) []string {
	var content = make([]string, 0)
	content = append(content, string(op.Contents))
	return content
}

//Primary User ID
func parseSPType25(sp *Subpackets, op *packet.OpaqueSubpacket) []string {
	var content = make([]string, 0)
	if op.Contents[0] == 0x00 {
		content = append(content, "Not primary")
	} else {
		content = append(content, "Primary")
	}
	return content
}

//Policy URI
func parseSPType26(sp *Subpackets, op *packet.OpaqueSubpacket) []string {
	var content = make([]string, 0)
	content = append(content, string(op.Contents))
	return content
}

//Key Flags
func parseSPType27(sp *Subpackets, op *packet.OpaqueSubpacket) []string {
	var content = make([]string, 0)
	flag1 := op.Contents[0]

	content = append(content, fmt.Sprintf("%s", stringFlagInfo(flag1&0x01, "This key may be used to certify other keys.")))
	content = append(content, fmt.Sprintf("%s", stringFlagInfo(flag1&0x02, "This key may be used to sign data.")))
	content = append(content, fmt.Sprintf("%s", stringFlagInfo(flag1&0x04, "This key may be used to encrypt communications.")))
	content = append(content, fmt.Sprintf("%s", stringFlagInfo(flag1&0x08, "This key may be used to encrypt storage.")))
	content = append(content, fmt.Sprintf("%s", stringFlagInfo(flag1&0x10, "The private component of this key may have been split by a secret-sharing mechanism.")))
	content = append(content, fmt.Sprintf("%s", stringFlagInfo(flag1&0x20, "This key may be used for authentication.")))
	content = append(content, fmt.Sprintf("%s", stringFlagInfo(flag1&0x80, "The private component of this key may be in the possession of more than one person.")))
	if (flag1 & 0x40) != 0x00 {
		content = append(content, fmt.Sprintf("%s", stringFlagInfo(flag1&0x40, fmt.Sprintf("Unknown flag1(0x%02x)", flag1))))
	}
	if len(op.Contents) > 1 {
		flags := op.Contents[1:]
		for i, flag := range flags {
			if flag != 0x00 {
				content = append(content, fmt.Sprintf("%s", stringFlagInfo(flag, fmt.Sprintf("Unknown flag%d(0x%02x)", i+2, flag))))
			}
		}
	}
	return content
}

//Signer's User ID
func parseSPType28(sp *Subpackets, op *packet.OpaqueSubpacket) []string {
	var content = make([]string, 0)
	content = append(content, string(op.Contents))
	return content
}

//Reason for Revocation
func parseSPType29(sp *Subpackets, op *packet.OpaqueSubpacket) []string {
	var content = make([]string, 0)
	code := op.Contents[0]
	if 100 <= code && code <= 110 {
		content = append(content, "Private Use")
	} else {
		switch code {
		case 0:
			content = append(content, "No reason specified (key revocations or cert revocations)")
		case 1:
			content = append(content, "Key is superseded (key revocations)")
		case 2:
			content = append(content, "Key material has been compromised (key revocations)")
		case 3:
			content = append(content, "Key is retired and no longer used (key revocations)")
		case 32:
			content = append(content, "User ID information is no longer valid (cert revocations)")
		default:
			content = append(content, fmt.Sprintf("Unknown reason(%d)", code))
		}
	}
	return content
}

//Features
func parseSPType30(sp *Subpackets, op *packet.OpaqueSubpacket) []string {
	var content = make([]string, 0)
	flag1 := op.Contents[0]

	content = append(content, fmt.Sprintf("%s", stringFlagInfo(flag1&0x01, "Modification Detection (packets 18 and 19)")))
	if (flag1 & 0xfe) != 0x00 {
		content = append(content, fmt.Sprintf("%s", stringFlagInfo(flag1&0xfe, fmt.Sprintf("Unknown flag1(0x%02x)", flag1))))
	}
	if len(op.Contents) > 1 {
		flags := op.Contents[1:]
		for i, flag := range flags {
			if flag != 0x00 {
				content = append(content, fmt.Sprintf("%s", stringFlagInfo(flag, fmt.Sprintf("Unknown flag%d(0x%02x)", i+2, flag))))
			}
		}
	}
	return content
}

//Signature Target
func parseSPType31(sp *Subpackets, op *packet.OpaqueSubpacket) []string {
	var content = make([]string, 0)
	pubAlg := PubAlg(op.Contents[0])
	hashAlg := HashAlg(op.Contents[1])
	hash := op.Contents[2:]

	content = append(content, fmt.Sprintf("Public-key algorithm - %v", pubAlg))
	content = append(content, fmt.Sprintf("Hash algorithm - %v", hashAlg))
	content = append(content, fmt.Sprintf("Hash(%d bytes) - %v", len(hash), DumpByte(hash)))
	return content
}

//Embedded Signature
func parseSPType32(sp *Subpackets, op *packet.OpaqueSubpacket) []string {
	//sig := &packet.OpaquePacket{Tag: uint8(0x02), Reason: error(nil), Contents: op.Contents}
	//cxt := Tag02{Options: sp.Options, OpaquePacket: sig}
	//content, err := cxt.Parse(0)
	//if err != nil {
	//	return nil
	//}
	//return content
	return nil
}

func stringFlagInfo(flag byte, name string) string {
	if flag != 0x00 {
		return fmt.Sprintf("Set flag - %s", name)
	}
	return fmt.Sprintf("Unset flag - %s", name)
}
