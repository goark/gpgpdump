package tag02

import (
	"fmt"
	"strconv"

	"golang.org/x/crypto/openpgp/packet"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/options"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

var subpacketNames = values.Msgs{
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
}

// SubpacketType is sub-packet type
type SubpacketType byte

// Get returns Item instance
func (s SubpacketType) Get() *items.Item {
	return items.NewItem(s.String(), "", "", fmt.Sprintf("%02x", byte(s)))
}

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
type ParseSubpacket func(*Subpackets, *packet.OpaqueSubpacket, *items.Item) error

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
func (sp *Subpackets) Parse(pckt *items.Item) error {
	sub := items.NewItem(sp.title, "", "", "")
	for _, p := range sp.opaqueSubpackets {
		var f ParseSubpacket
		if p.SubType == 32 {
			f = parseSPType32 // recursive call in parseSPType32()
		} else {
			f = parseSubpacketFunctions.Get(int(p.SubType), parseSPReserved)
		}
		if err := f(sp, p, sub); err != nil {
			return err
		}
	}
	pckt.AddSub(sub)
	return nil
}

func parseSPReserved(sp *Subpackets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := SubpacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))
	item.AddSub(st)
	return nil
}

//Signature Creation Time
func parseSPType02(sp *Subpackets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := SubpacketType(op.SubType).Get()
	unix := values.SigTime(op.Contents, sp.Uflag)
	st.Value = unix.Get().Value
	st.Note = unix.Get().Note
	sp.SigCreationTime = unix.Unix()
	item.AddSub(st)
	return nil
}

//Signature Expiration Time
func parseSPType03(sp *Subpackets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := SubpacketType(op.SubType).Get()
	exp := values.SigExpire(op.Contents, sp.SigCreationTime, sp.Uflag).Get()
	st.Value = exp.Value
	st.Note = exp.Note
	sp.SigCreationTime = 0
	item.AddSub(st)
	return nil
}

//Exportable Certification
func parseSPType04(sp *Subpackets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := SubpacketType(op.SubType).Get()
	st.Note = values.DumpByte(op.Contents)
	if op.Contents[0] == 0x00 {
		st.Value = "Not exportable"
	} else {
		st.Value = "Exportable"
	}
	item.AddSub(st)
	return nil
}

//Trust Signature
func parseSPType05(sp *Subpackets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := SubpacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))

	st.AddSub(items.NewItem("Level", strconv.Itoa(int(op.Contents[0])), "", values.DumpByte(op.Contents[0:1])))
	st.AddSub(items.NewItem("Trust amount", strconv.Itoa(int(op.Contents[0])), "", values.DumpByte(op.Contents[1:2])))

	item.AddSub(st)
	return nil
}

//Regular Expression
func parseSPType06(sp *Subpackets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := SubpacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))
	st.Value = string(op.Contents)
	item.AddSub(st)
	return nil
}

//Revocable
func parseSPType07(sp *Subpackets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := SubpacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))
	if op.Contents[0] == 0x00 {
		st.Value = "Not revocable"
	} else {
		st.Value = "Revocable"
	}
	item.AddSub(st)
	return nil
}

//Key Expiration Time
func parseSPType09(sp *Subpackets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := SubpacketType(op.SubType).Get()
	exp := values.SigExpire(op.Contents, sp.KeyCreationTime, sp.Uflag).Get()
	st.Value = exp.Value
	st.Note = exp.Note
	sp.KeyCreationTime = 0
	return nil
}

//Placeholder for backward compatibility
func parseSPType10(sp *Subpackets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := SubpacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))
	item.AddSub(st)
	return nil
}

//Preferred Symmetric Algorithms
func parseSPType11(sp *Subpackets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := SubpacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))
	for _, c := range op.Contents {
		st.AddSub(values.SymAlg(c).Get())
	}
	item.AddSub(st)
	return nil
}

//Revocation Key
func parseSPType12(sp *Subpackets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := SubpacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))

	class := op.Contents[0]
	pub := values.PubAlg(op.Contents[1])
	fingerprint := values.NewRawData("Fingerprint", "", op.Contents[2:], true)

	className := "Unknown"
	if (class & 0x80) != 0x00 {
		switch true {
		case (class & 0x40) != 0x00:
			className = "Sensitive"
		default:
			className = "Normal"
		}
	}
	st.AddSub(items.NewItem("Class", className, "", values.DumpByte(op.Contents[0:1])))
	st.AddSub(pub.Get())
	st.AddSub(fingerprint.Get())

	item.AddSub(st)
	return nil
}

//Issuer
func parseSPType16(sp *Subpackets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := SubpacketType(op.SubType).Get()
	kid := values.KeyID(values.Octets2Int(op.Contents)).Get()
	st.Value = kid.Value
	st.Note = kid.Note
	item.AddSub(st)
	return nil
}

//Notation Data
func parseSPType20(sp *Subpackets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := SubpacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))

	flags := op.Contents[0:4]
	nameLength := int(values.Octets2Int(op.Contents[4:6]))
	valueLength := int(values.Octets2Int(op.Contents[6:8]))
	name := op.Contents[8 : 8+nameLength]
	value := op.Contents[8+nameLength : 8+nameLength+valueLength]

	human := flags[0] & 0x80
	st.AddSub(stringFlagInfo(human, "Human-readable"))
	if (flags[0] & 0x7f) != 0x00 {
		st.AddSub(stringFlagInfo(flags[0]&0x7f, fmt.Sprintf("Unknown flag1(0x%02x)", flags[0])))
	}
	if flags[1] != 0x00 {
		st.AddSub(stringFlagInfo(flags[1], fmt.Sprintf("Unknown flag2(0x%02x)", flags[1])))
	}
	if flags[2] != 0x00 {
		st.AddSub(stringFlagInfo(flags[1], fmt.Sprintf("Unknown flag3(0x%02x)", flags[2])))
	}
	if flags[3] != 0x00 {
		st.AddSub(stringFlagInfo(flags[1], fmt.Sprintf("Unknown flag4(0x%02x)", flags[3])))
	}
	item.AddSub(items.NewItem("Name", string(name), "", ""))
	if human != 0x00 {
		st.AddSub(items.NewItem("Value", string(value), "", ""))
	} else {
		st.AddSub(values.NewRawData("Value", "", value, true).Get())
	}

	item.AddSub(st)
	return nil
}

//Preferred Hash Algorithms
func parseSPType21(sp *Subpackets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := SubpacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))
	for _, c := range op.Contents {
		st.AddSub(values.HashAlg(c).Get())
	}
	item.AddSub(st)
	return nil
}

//Preferred Compression Algorithms
func parseSPType22(sp *Subpackets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := SubpacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))
	for _, c := range op.Contents {
		st.AddSub(values.CompAlg(c).Get())
	}
	item.AddSub(st)
	return nil
}

//Key Server Preferences
func parseSPType23(sp *Subpackets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := SubpacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))

	flag1 := op.Contents[0]
	st.AddSub(stringFlagInfo(flag1&0x80, "No-modify"))
	if (flag1 & 0x7f) != 0x00 {
		st.AddSub(stringFlagInfo(flag1&0x7f, fmt.Sprintf("Unknown flag1(0x%02x)", flag1)))
	}
	if len(op.Contents) > 1 {
		flags := op.Contents[1:]
		for i, flag := range flags {
			if flag != 0x00 {
				st.AddSub(stringFlagInfo(flag, fmt.Sprintf("Unknown flag%d(0x%02x)", i+2, flag)))
			}
		}
	}
	item.AddSub(st)
	return nil
}

//Preferred Key Server
func parseSPType24(sp *Subpackets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := SubpacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))
	st.Value = string(op.Contents)
	item.AddSub(st)
	return nil
}

//Primary User ID
func parseSPType25(sp *Subpackets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := SubpacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))
	if op.Contents[0] == 0x00 {
		st.Value = "Not primary"
	} else {
		st.Value = "Primary"
	}
	item.AddSub(st)
	return nil
}

//Policy URI
func parseSPType26(sp *Subpackets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := SubpacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))
	st.Value = string(op.Contents)
	item.AddSub(st)
	return nil
}

//Key Flags
func parseSPType27(sp *Subpackets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := SubpacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))

	flag1 := op.Contents[0]
	st.AddSub(stringFlagInfo(flag1&0x01, "This key may be used to certify other keys."))
	st.AddSub(stringFlagInfo(flag1&0x02, "This key may be used to sign data."))
	st.AddSub(stringFlagInfo(flag1&0x04, "This key may be used to encrypt communications."))
	st.AddSub(stringFlagInfo(flag1&0x08, "This key may be used to encrypt storage."))
	st.AddSub(stringFlagInfo(flag1&0x10, "The private component of this key may have been split by a secret-sharing mechanism."))
	st.AddSub(stringFlagInfo(flag1&0x20, "This key may be used for authentication."))
	st.AddSub(stringFlagInfo(flag1&0x80, "The private component of this key may be in the possession of more than one person."))
	if (flag1 & 0x40) != 0x00 {
		st.AddSub(stringFlagInfo(flag1&0x40, fmt.Sprintf("Unknown flag1(0x%02x)", flag1)))
	}
	if len(op.Contents) > 1 {
		flags := op.Contents[1:]
		for i, flag := range flags {
			if flag != 0x00 {
				st.AddSub(stringFlagInfo(flag, fmt.Sprintf("Unknown flag%d(0x%02x)", i+2, flag)))
			}
		}
	}

	item.AddSub(st)
	return nil
}

//Signer's User ID
func parseSPType28(sp *Subpackets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := SubpacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))
	st.Value = string(op.Contents)
	item.AddSub(st)
	return nil
}

var reasonNames = values.Msgs{
	0:  "No reason specified (key revocations or cert revocations)",
	1:  "Key is superseded (key revocations)",
	2:  "Key material has been compromised (key revocations)",
	3:  "Key is retired and no longer used (key revocations)",
	32: "User ID information is no longer valid (cert revocations)",
}

//Reason for Revocation
func parseSPType29(sp *Subpackets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := SubpacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))

	code := int(op.Contents[0])
	var name string
	if 100 <= code && code <= 110 {
		name = "Private/Experimental algorithm"
	} else {
		name = reasonNames.Get(int(code), "Unknown reason")
	}
	st.Value = fmt.Sprintf("%s (%d)", name, code)
	item.AddSub(st)
	return nil
}

//Features
func parseSPType30(sp *Subpackets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := SubpacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))

	flag1 := op.Contents[0]
	st.AddSub(stringFlagInfo(flag1&0x01, "Modification Detection (packets 18 and 19)"))
	if (flag1 & 0xfe) != 0x00 {
		st.AddSub(stringFlagInfo(flag1&0xfe, fmt.Sprintf("Unknown flag1(0x%02x)", flag1)))
	}
	if len(op.Contents) > 1 {
		flags := op.Contents[1:]
		for i, flag := range flags {
			if flag != 0x00 {
				st.AddSub(stringFlagInfo(flag, fmt.Sprintf("Unknown flag%d(0x%02x)", i+2, flag)))
			}
		}
	}
	item.AddSub(st)
	return nil
}

//Signature Target
func parseSPType31(sp *Subpackets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := SubpacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))

	pubAlg := values.PubAlg(op.Contents[0])
	hashAlg := values.HashAlg(op.Contents[1])
	hash := op.Contents[2:]

	st.AddSub(pubAlg.Get())
	st.AddSub(hashAlg.Get())
	st.AddSub(values.NewRawData("Hash", "", hash, true).Get())

	item.AddSub(st)
	return nil
}

//Embedded Signature
func parseSPType32(sp *Subpackets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := SubpacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))

	p, err := New(sp.Options, values.Tag(2), op.Contents).Parse() //recursive call
	if err != nil {
		return err
	}
	st.AddSub(p)
	item.AddSub(st)
	return nil
}

func stringFlagInfo(flag byte, name string) *items.Item {
	f := items.NewItem("Flag", "Unset", name, "")
	if flag != 0x00 {
		f.Value = "Set"
	}
	return f
}
