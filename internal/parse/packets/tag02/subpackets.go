package tag02

import (
	"fmt"

	"golang.org/x/crypto/openpgp/packet"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
)

var subpacketNames = values.Msgs{
	0:  "Reserved",                               //00
	1:  "Reserved",                               //01
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
}

// SubpacketType is sub-packet type
type SubpacketType byte

func (s SubpacketType) String() string {
	var name string
	if 100 <= s && s <= 110 {
		name = "Private or experimental"
	} else {
		name = subpacketNames.Get(int(s), "Unknown")
	}
	return fmt.Sprintf("%s (sub %d)", name, s)
}

// Subpackets - Sub-Packets
type Subpackets struct {
	*options.Options
	title            string
	opaqueSubpackets []*packet.OpaqueSubpacket
}

//NewSubpackets returns new Subpackets.
func NewSubpackets(opt *options.Options, title string, body []byte) (*Subpackets, error) {
	osp, err := packet.OpaqueSubpackets(body)
	if err != nil {
		return nil, err
	}
	return &Subpackets{Options: opt, title: title, opaqueSubpackets: osp}, nil
}

// ParseSubpacket is function value of parsing sub-packet
type ParseSubpacket func(*Subpackets, *packet.OpaqueSubpacket) (values.Content, error)

//Functions is type of function list.
type Functions map[int]ParseSubpacket

//Get returns message.
func (fs Functions) Get(i int, def ParseSubpacket) ParseSubpacket {
	if f, ok := fs[i]; ok {
		return f
	}
	return def
}

var parseSubpacketFunctions = Functions{
	2:  parseSPType02,
	3:  parseSPType03,
	4:  parseSPType04,
	5:  parseSPType05,
	6:  parseSPType06,
	7:  parseSPType07,
	9:  parseSPType09,
	10: parseSPType10,
	11: parseSPType11,
	12: parseSPType12,
	16: parseSPType16,
	20: parseSPType20,
	21: parseSPType21,
	22: parseSPType22,
	23: parseSPType23,
	24: parseSPType24,
	25: parseSPType25,
	26: parseSPType26,
	27: parseSPType27,
	28: parseSPType28,
	29: parseSPType29,
	30: parseSPType30,
	31: parseSPType31,
}

//Parse parsing sub-packets
func (sp *Subpackets) Parse(indent values.Indent) values.Content {
	content := values.NewContent()
	for _, pckt := range sp.opaqueSubpackets {
		st := SubpacketType(pckt.SubType)
		content = append(content, indent.Fill(SubpacketName(SubpacketType(pckt.SubType), len(pckt.Contents), sp.title)))
		var f ParseSubpacket
		if st == 32 {
			f = parseSPType32 // recursive call in parseSPType32()
		} else {
			f = parseSubpacketFunctions.Get(int(st), parseSPReserved)
		}
		c, err := f(sp, pckt)
		if err != nil {
			return content
		}
		content = content.AddIndent(c, indent+1)
	}
	return content
}

//SubpacketName returns sub-packet name
func SubpacketName(t SubpacketType, l int, title string) string {
	return fmt.Sprintf("%s %v (%d bytes)", title, t, l)
}

func parseSPReserved(sp *Subpackets, op *packet.OpaqueSubpacket) (values.Content, error) {
	return nil, nil
}

//Signature Creation Time
func parseSPType02(sp *Subpackets, op *packet.OpaqueSubpacket) (values.Content, error) {
	content := values.NewContent()
	sp.SigCreationTime = values.Octets2Int(op.Contents)
	content = append(content, values.SigTime(sp.SigCreationTime, sp.Uflag).String())
	return content, nil
}

//Signature Expiration Time
func parseSPType03(sp *Subpackets, op *packet.OpaqueSubpacket) (values.Content, error) {
	content := values.NewContent()
	days := values.Octets2Int(op.Contents)
	after := fmt.Sprintf("%v days after", float64(days)/86400)
	if sp.SigCreationTime == 0 {
		content = append(content, after)
	} else {
		content = append(content, fmt.Sprintf("%s (%s)", after, values.SigTime(sp.SigCreationTime+days, sp.Uflag).RFC3339()))
		sp.SigCreationTime = 0
	}
	return content, nil
}

//Exportable Certification
func parseSPType04(sp *Subpackets, op *packet.OpaqueSubpacket) (values.Content, error) {
	content := values.NewContent()
	if op.Contents[0] == 0x00 {
		content = append(content, "Not exportable")
	} else {
		content = append(content, "Exportable")
	}
	return content, nil
}

//Trust Signature
func parseSPType05(sp *Subpackets, op *packet.OpaqueSubpacket) (values.Content, error) {
	content := values.NewContent()
	content = append(content, fmt.Sprintf("Level - %d", op.Contents[0]))
	content = append(content, fmt.Sprintf("Trust amount - %d", op.Contents[2]))
	return content, nil
}

//Regular Expression
func parseSPType06(sp *Subpackets, op *packet.OpaqueSubpacket) (values.Content, error) {
	content := values.NewContent()
	content = append(content, string(op.Contents))
	return content, nil
}

//Revocable
func parseSPType07(sp *Subpackets, op *packet.OpaqueSubpacket) (values.Content, error) {
	content := values.NewContent()
	if op.Contents[0] == 0x00 {
		content = append(content, "Not revocable")
	} else {
		content = append(content, "Revocable")
	}
	return content, nil
}

//Key Expiration Time
func parseSPType09(sp *Subpackets, op *packet.OpaqueSubpacket) (values.Content, error) {
	content := values.NewContent()
	days := values.Octets2Int(op.Contents)
	after := fmt.Sprintf("%v days after", float64(days)/86400)
	if sp.KeyCreationTime == 0 {
		content = append(content, after)
	} else {
		content = append(content, fmt.Sprintf("%s (%s)", after, values.SigTime(sp.KeyCreationTime+days, sp.Uflag).RFC3339()))
		sp.KeyCreationTime = 0
	}
	return content, nil
}

//Placeholder for backward compatibility
func parseSPType10(sp *Subpackets, op *packet.OpaqueSubpacket) (values.Content, error) {
	return nil, nil
}

//Preferred Symmetric Algorithms
func parseSPType11(sp *Subpackets, op *packet.OpaqueSubpacket) (values.Content, error) {
	content := values.NewContent()
	for _, c := range op.Contents {
		content = append(content, values.SymAlg(c).String())
	}
	return content, nil
}

//Revocation Key
func parseSPType12(sp *Subpackets, op *packet.OpaqueSubpacket) (values.Content, error) {
	content := values.NewContent()
	class := op.Contents[0]
	pub := values.PubAlg(op.Contents[1])
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
	content = append(content, fmt.Sprintf("Fingerprint - %v", values.DumpByte(fingerprint)))
	return content, nil
}

//Issuer
func parseSPType16(sp *Subpackets, op *packet.OpaqueSubpacket) (values.Content, error) {
	content := values.NewContent()
	keyID := values.KeyID(values.Octets2Int(op.Contents))
	content = append(content, keyID.String())
	return content, nil
}

//Notation Data
func parseSPType20(sp *Subpackets, op *packet.OpaqueSubpacket) (values.Content, error) {
	content := values.NewContent()
	flags := op.Contents[0:4]
	nameLength := int(values.Octets2Int(op.Contents[4:6]))
	valueLength := int(values.Octets2Int(op.Contents[6:8]))
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
		content = append(content, fmt.Sprintf("Value - %v", values.DumpByte(value)))
	}
	return content, nil
}

//Preferred Hash Algorithms
func parseSPType21(sp *Subpackets, op *packet.OpaqueSubpacket) (values.Content, error) {
	content := values.NewContent()
	for _, c := range op.Contents {
		content = append(content, values.HashAlg(c).String())
	}
	return content, nil
}

//Preferred Compression Algorithms
func parseSPType22(sp *Subpackets, op *packet.OpaqueSubpacket) (values.Content, error) {
	content := values.NewContent()
	for _, c := range op.Contents {
		content = append(content, values.CompAlg(c).String())
	}
	return content, nil
}

//Key Server Preferences
func parseSPType23(sp *Subpackets, op *packet.OpaqueSubpacket) (values.Content, error) {
	content := values.NewContent()
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
	return content, nil
}

//Preferred Key Server
func parseSPType24(sp *Subpackets, op *packet.OpaqueSubpacket) (values.Content, error) {
	content := values.NewContent()
	content = append(content, string(op.Contents))
	return content, nil
}

//Primary User ID
func parseSPType25(sp *Subpackets, op *packet.OpaqueSubpacket) (values.Content, error) {
	content := values.NewContent()
	if op.Contents[0] == 0x00 {
		content = append(content, "Not primary")
	} else {
		content = append(content, "Primary")
	}
	return content, nil
}

//Policy URI
func parseSPType26(sp *Subpackets, op *packet.OpaqueSubpacket) (values.Content, error) {
	content := values.NewContent()
	content = append(content, string(op.Contents))
	return content, nil
}

//Key Flags
func parseSPType27(sp *Subpackets, op *packet.OpaqueSubpacket) (values.Content, error) {
	content := values.NewContent()
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
	return content, nil
}

//Signer's User ID
func parseSPType28(sp *Subpackets, op *packet.OpaqueSubpacket) (values.Content, error) {
	content := values.NewContent()
	content = append(content, string(op.Contents))
	return content, nil
}

var reasonNames = values.Msgs{
	0:  "No reason specified (key revocations or cert revocations)",
	1:  "Key is superseded (key revocations)",
	2:  "Key material has been compromised (key revocations)",
	3:  "Key is retired and no longer used (key revocations)",
	32: "User ID information is no longer valid (cert revocations)",
}

//Reason for Revocation
func parseSPType29(sp *Subpackets, op *packet.OpaqueSubpacket) (values.Content, error) {
	content := values.NewContent()
	code := int(op.Contents[0])

	var name string
	if 100 <= code && code <= 110 {
		name = "Private/Experimental algorithm"
	} else {
		name = reasonNames.Get(int(code), "Unknown reason")
	}
	content = append(content, fmt.Sprintf("%s (%d)", name, code))
	return content, nil
}

//Features
func parseSPType30(sp *Subpackets, op *packet.OpaqueSubpacket) (values.Content, error) {
	content := values.NewContent()
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
	return content, nil
}

//Signature Target
func parseSPType31(sp *Subpackets, op *packet.OpaqueSubpacket) (values.Content, error) {
	content := values.NewContent()
	pubAlg := values.PubAlg(op.Contents[0])
	hashAlg := values.HashAlg(op.Contents[1])
	hash := op.Contents[2:]

	content = append(content, pubAlg.String())
	content = append(content, hashAlg.String())
	content = append(content, fmt.Sprintf("Hash (%d bytes) - %v", len(hash), values.DumpByte(hash)))
	return content, nil
}

//Embedded Signature
func parseSPType32(sp *Subpackets, op *packet.OpaqueSubpacket) (values.Content, error) {
	return New(sp.Options, op.Contents).Parse(0) //recursive call
}

func stringFlagInfo(flag byte, name string) string {
	if flag != 0x00 {
		return fmt.Sprintf("Set flag - %s", name)
	}
	return fmt.Sprintf("Unset flag - %s", name)
}
