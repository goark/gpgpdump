package tag02

import (
	"fmt"
	"strconv"

	"golang.org/x/crypto/openpgp/packet"

	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/packets/sub"
	"github.com/spiegel-im-spiegel/gpgpdump/internal/parse/values"
	"github.com/spiegel-im-spiegel/gpgpdump/items"
)

var parseSubpacketFunctions = sub.Functions{
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

//ParseSub parsing sub-packets
func ParseSub(sp *sub.Packets, pckt *items.Item) error {
	s := items.NewItem(sp.Title, "", "", "")
	for _, p := range sp.OpaqueSubpackets {
		if p.SubType == 32 {
			// recursive call in parseSPType32()
			if err := parseSPType32(sp, p, s); err != nil {
				return err
			}
		} else {
			if err := parseSubpacketFunctions.Get(int(p.SubType), sub.ParseSPReserved)(sp, p, s); err != nil {
				return err
			}
		}
	}
	pckt.AddSub(s)
	return nil
}

//Signature Creation Time
func parseSPType02(sp *sub.Packets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := sub.PacketType(op.SubType).Get()
	unix := values.SigTime(op.Contents, sp.Uflag)
	st.Value = unix.Get().Value
	st.Dump = unix.Get().Dump
	sp.SigCreationTime = unix.Unix()
	item.AddSub(st)
	return nil
}

//Signature Expiration Time
func parseSPType03(sp *sub.Packets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := sub.PacketType(op.SubType).Get()
	exp := values.SigExpire(op.Contents, sp.SigCreationTime, sp.Uflag).Get()
	st.Value = exp.Value
	st.Note = exp.Note
	sp.SigCreationTime = 0
	item.AddSub(st)
	return nil
}

//Exportable Certification
func parseSPType04(sp *sub.Packets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := sub.PacketType(op.SubType).Get()
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
func parseSPType05(sp *sub.Packets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := sub.PacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))

	st.AddSub(items.NewItem("Level", strconv.Itoa(int(op.Contents[0])), "", values.DumpByte(op.Contents[0:1])))
	st.AddSub(items.NewItem("Trust amount", strconv.Itoa(int(op.Contents[0])), "", values.DumpByte(op.Contents[1:2])))

	item.AddSub(st)
	return nil
}

//Regular Expression
func parseSPType06(sp *sub.Packets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := sub.PacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))
	st.Value = string(op.Contents)
	item.AddSub(st)
	return nil
}

//Revocable
func parseSPType07(sp *sub.Packets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := sub.PacketType(op.SubType).Get()
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
func parseSPType09(sp *sub.Packets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := sub.PacketType(op.SubType).Get()
	exp := values.SigExpire(op.Contents, sp.KeyCreationTime, sp.Uflag).Get()
	st.Value = exp.Value
	st.Note = exp.Note
	sp.KeyCreationTime = 0
	return nil
}

//Placeholder for backward compatibility
func parseSPType10(sp *sub.Packets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := sub.PacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))
	item.AddSub(st)
	return nil
}

//Preferred Symmetric Algorithms
func parseSPType11(sp *sub.Packets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := sub.PacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))
	for _, c := range op.Contents {
		st.AddSub(values.SymAlg(c).Get())
	}
	item.AddSub(st)
	return nil
}

//Revocation Key
func parseSPType12(sp *sub.Packets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := sub.PacketType(op.SubType).Get()
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
func parseSPType16(sp *sub.Packets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := sub.PacketType(op.SubType).Get()
	kid := values.KeyID(values.Octets2Int(op.Contents)).Get()
	st.Value = kid.Value
	st.Note = kid.Note
	item.AddSub(st)
	return nil
}

//Notation Data
func parseSPType20(sp *sub.Packets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := sub.PacketType(op.SubType).Get()
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
func parseSPType21(sp *sub.Packets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := sub.PacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))
	for _, c := range op.Contents {
		st.AddSub(values.HashAlg(c).Get())
	}
	item.AddSub(st)
	return nil
}

//Preferred Compression Algorithms
func parseSPType22(sp *sub.Packets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := sub.PacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))
	for _, c := range op.Contents {
		st.AddSub(values.CompAlg(c).Get())
	}
	item.AddSub(st)
	return nil
}

//Key Server Preferences
func parseSPType23(sp *sub.Packets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := sub.PacketType(op.SubType).Get()
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
func parseSPType24(sp *sub.Packets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := sub.PacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))
	st.Value = string(op.Contents)
	item.AddSub(st)
	return nil
}

//Primary User ID
func parseSPType25(sp *sub.Packets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := sub.PacketType(op.SubType).Get()
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
func parseSPType26(sp *sub.Packets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := sub.PacketType(op.SubType).Get()
	st.Note = fmt.Sprintf("%d bytes", len(op.Contents))
	st.Value = string(op.Contents)
	item.AddSub(st)
	return nil
}

//Key Flags
func parseSPType27(sp *sub.Packets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := sub.PacketType(op.SubType).Get()
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
func parseSPType28(sp *sub.Packets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := sub.PacketType(op.SubType).Get()
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
func parseSPType29(sp *sub.Packets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := sub.PacketType(op.SubType).Get()
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
func parseSPType30(sp *sub.Packets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := sub.PacketType(op.SubType).Get()
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
func parseSPType31(sp *sub.Packets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := sub.PacketType(op.SubType).Get()
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
func parseSPType32(sp *sub.Packets, op *packet.OpaqueSubpacket, item *items.Item) error {
	st := sub.PacketType(op.SubType).Get()
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
